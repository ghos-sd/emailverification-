# -*- coding: utf-8 -*-
import os, re, asyncio, random, string, logging, functools
from typing import List, Tuple, Optional

import aiosmtplib
import dns.resolver
from aiosmtplib import SMTPConnectError, SMTPHeloError, SMTPRecipientRefused, SMTPException

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ---------------- Configuration ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

# Hardcoded parameters
CONNECT_TIMEOUT = 8
SMTP_TIMEOUT = 12
PORTS = (587, 25, 465)      # Try multiple ports
MAX_MX = 3                  # Max 3 MX records to check
PARALLEL = 4                # Max parallel probes
PROBE_DOMAIN = "verifier.example.com" # Use a real domain you control for better trust

# ---------------- Logging Setup ----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("email-check-bot")

# ---------------- Helpers ----------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

def lines(text: str) -> List[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]

def rand_local() -> str:
    return "probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

def classify(code: int) -> str:
    if code in (250, 251): return "ok"
    if code in (550, 551, 552, 553, 554): return "dead"
    if code in (450, 451, 452, 421): return "temp"
    return "unknown"

def banner_hint(banner: str) -> Optional[str]:
    b = (banner or "").lower()
    if "outlook" in b or "protection.outlook.com" in b or "microsoft" in b:
        return "ms"
    if "google.com" in b or "gmail" in b or "google" in b:
        return "google"
    if "proofpoint" in b: return "proofpoint"
    if "mimecast" in b: return "mimecast"
    return None

def verdict_label(kind: str) -> str:
    return {
        "ok": "شغّال ✅",
        "dead": "غير شغّال ❌",
        "lock": "يرفض التحقق 🔒",
        "temp": "مؤقت ⏳",
        "catch": "Catch-all 🎯",
        "syntax": "صيغة غير صحيحة ❌",
        "domain": "دومين غير صالح ❌",
        "unknown": "غير مؤكد ⚠️",
    }.get(kind, "غير مؤكد ⚠️")

@functools.lru_cache(maxsize=1024)
def cached_mx_lookup(domain: str) -> List[Tuple[int, str]]:
    """Cached DNS MX lookup to avoid repeated queries."""
    try:
        ans = dns.resolver.resolve(domain, "MX")
        mx = []
        for r in ans:
            try:
                mx.append((int(r.preference), str(r.exchange).rstrip(".")))
            except Exception:
                pass
        mx.sort(key=lambda x: x[0])
        return mx
    except Exception:
        # Fallback to A record if no MX is found
        try:
            dns.resolver.resolve(domain, "A")
            return [(50, domain)]
        except Exception:
            return []

# ---------------- SMTP Probe ----------------
async def smtp_probe(host: str, port: int, email: str, helo_name: str) -> Tuple[str, str]:
    """
    Probes an SMTP server to verify an email address.
    Returns (kind, brief_reason).
    """
    use_tls = (port == 465)
    client = None
    try:
        # Establish a connection
        client = aiosmtplib.SMTP(
            hostname=host,
            port=port,
            timeout=SMTP_TIMEOUT,
            use_tls=use_tls,
        )

        banner = await asyncio.wait_for(client.connect(), timeout=CONNECT_TIMEOUT)
        hint = banner_hint(banner or "")

        # Initial EHLO/HELO
        try:
            await asyncio.wait_for(client.ehlo(helo_name), timeout=SMTP_TIMEOUT)
        except (SMTPHeloError, asyncio.TimeoutError):
            try:
                await asyncio.wait_for(client.helo(helo_name), timeout=SMTP_TIMEOUT)
            except Exception:
                return ("lock" if hint in ("ms", "mimecast", "proofpoint") else "unknown",
                        "HELO/EHLO Rejected")

        # Handle STARTTLS for port 587
        if port == 587:
            try:
                await asyncio.wait_for(client.starttls(), timeout=SMTP_TIMEOUT)
                await asyncio.wait_for(client.ehlo(helo_name), timeout=SMTP_TIMEOUT)
            except Exception:
                return ("lock" if hint else "unknown", "STARTTLS Rejected")

        # MAIL FROM command
        mail_from = f"{rand_local()}@{helo_name}"
        try:
            code_mail, _ = await asyncio.wait_for(client.mail(mail_from), timeout=SMTP_TIMEOUT)
            if code_mail >= 500:
                return ("lock" if hint else "unknown", f"MAIL FROM {code_mail}")
        except (SMTPRecipientRefused, asyncio.TimeoutError):
            return ("lock" if hint else "unknown", "MAIL FROM Rejected")

        # Real RCPT command
        code_real, _ = await asyncio.wait_for(client.rcpt(email), timeout=SMTP_TIMEOUT)
        res_real = classify(code_real)

        # Probe for catch-all
        domain = email.split("@", 1)[-1]
        fake_rcpt = f"{rand_local()}@{domain}"
        code_fake, _ = await asyncio.wait_for(client.rcpt(fake_rcpt), timeout=SMTP_TIMEOUT)
        res_fake = classify(code_fake)

        # Final decision logic
        if res_real == "ok" and res_fake == "ok":
            return "catch", "Server accepts any address"
        if res_real == "ok" and res_fake != "ok":
            return "ok", f"RCPT {code_real}"
        if res_real == "dead":
            return "dead", f"RCPT {code_real}"
        if res_real == "temp":
            return "temp", f"RCPT {code_real}"

        if hint in ("ms", "google", "mimecast", "proofpoint"):
            return "lock", f"Policy {hint}"

        return "unknown", f"RCPT {code_real}"

    except SMTPConnectError:
        return "temp", "Connection Refused/Timeout"
    except asyncio.TimeoutError:
        return "temp", "Connection Timeout"
    except Exception as e:
        return "unknown", f"Exception {e.__class__.__name__}"
    finally:
        # Ensure client disconnects gracefully
        if client and client.is_connected:
            try:
                await client.quit()
            except Exception:
                pass

def main():
    if not BOT_TOKEN:
        raise SystemExit("Error: BOT_TOKEN is not set.")
    
    app = Application.builder().token(BOT_TOKEN).build()
    
    # ---------------- Telegram Handlers ----------------
    WELCOME = (
        "أهلًا! أرسل قائمة إيميلات (كل إيميل في سطر) وسأرجّع:\n"
        "✅ شغّال | ❌ غير شغّال | 🔒 يرفض التحقق | ⏳ مؤقت | 🎯 Catch-all | ⚠️ غير مؤكد\n\n"
        "مثال:\n"
        "user@gmail.com\n"
        "not-exist@nope-domain-xyz.com\n"
        "info@yourdomain.com"
    )

    async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(WELCOME)

    async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(WELCOME)

    async def verify_one(email: str) -> Tuple[str, str]:
        if not EMAIL_RE.match(email):
            return verdict_label("syntax"), "Invalid format"
        domain = email.split("@", 1)[-1]
        
        mx = await asyncio.get_running_loop().run_in_executor(None, cached_mx_lookup, domain)
        if not mx:
            return verdict_label("domain"), "No MX/A record"

        targets = []
        for _, host in mx[:MAX_MX]:
            for p in PORTS:
                targets.append((host, p))
        
        sem = asyncio.Semaphore(PARALLEL)
        result_queue = asyncio.Queue()

        decisive = {"ok", "dead", "catch", "lock"}
        soft_map = []

        async def worker(host, port):
            async with sem:
                kind, why = await smtp_probe(host, port, email, PROBE_DOMAIN)
                await result_queue.put((host, port, kind, why))

        tasks = [asyncio.create_task(worker(h, p)) for h, p in targets]

        decided: Optional[Tuple[str, str]] = None
        for _ in range(len(tasks)):
            host, port, kind, why = await result_queue.get()
            if kind in decisive and decided is None:
                decided = (verdict_label(kind), f"{host}:{port} {why}")
                for t in tasks:
                    t.cancel()
                break
            elif kind in ("temp", "unknown"):
                soft_map.append(f"{host}:{port} {why}")

        for t in tasks:
            try: await t
            except asyncio.CancelledError: pass
            except Exception: pass

        if decided:
            return decided
        if soft_map:
            return verdict_label("unknown"), " / ".join(soft_map[:3])
        return verdict_label("unknown"), "Undetermined"

    async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
        text = (update.message.text or "").strip()
        targets = lines(text)[:25]
        if not targets:
            return
        
        msg = await update.message.reply_text("جاري التحقق… ⏳")
        
        out_lines = []
        for i, em in enumerate(targets):
            await msg.edit_text(f"جاري التحقق من {em} ({i+1}/{len(targets)})...")
            status, reason = await verify_one(em)
            out_lines.append(f"{em} — {status}")
        
        await msg.edit_text("\n".join(out_lines))

    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    
    log.info("Email checker bot is running.")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
