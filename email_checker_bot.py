# -*- coding: utf-8 -*-
import os, re, asyncio, random, string, logging, functools
from typing import List, Tuple, Optional, Any

import aiosmtplib
import dns.resolver
from aiosmtplib import SMTPConnectError, SMTPHeloError, SMTPException

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ----------------- Configuration & Logging -----------------
class Config:
    """Centralized configuration for the bot."""
    BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
    PROBE_DOMAIN = os.getenv("PROBE_DOMAIN", "verifier.example.com").strip()
    CONNECT_TIMEOUT = 8
    SMTP_TIMEOUT = 12
    PORTS = (587, 25, 465)
    MAX_MX = 3
    PARALLEL_PROBES = 4

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("email-check-bot")

# --------- Stable DNS Resolver ---------
_resolver = dns.resolver.Resolver(configure=False)
_resolver.nameservers = ["1.1.1.1", "1.0.0.1"]
dns_resolve = _resolver.resolve

# ----------------- Utilities -----------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

def lines(text: str) -> List[str]:
    """Splits a multi-line string into a list of cleaned, non-empty lines."""
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]

def rand_local() -> str:
    """Generates a random local part for a probe email address."""
    return "probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

def classify(code: int) -> str:
    """Classifies an SMTP response code into a human-readable category."""
    if code in (250, 251): return "ok"
    if code in (550, 551, 552, 553, 554): return "dead"
    if code in (450, 451, 452, 421): return "temp"
    return "unknown"

def banner_hint(banner: str) -> Optional[str]:
    """Analyzes the SMTP banner to guess the service provider."""
    b = (banner or "").lower()
    if "outlook" in b or "protection.outlook.com" in b or "microsoft" in b: return "ms"
    if "google.com" in b or "gmail" in b or "google" in b: return "google"
    if "proofpoint" in b: return "proofpoint"
    if "mimecast" in b: return "mimecast"
    return None

def verdict_label(kind: str) -> str:
    """Returns a user-friendly label for a verification result."""
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
        ans = dns_resolve(domain, "MX")
        mx = []
        for r in ans:
            try:
                mx.append((int(r.preference), str(r.exchange).rstrip(".")))
            except Exception:
                pass
        mx.sort(key=lambda x: x[0])
        return mx
    except Exception:
        try:
            dns_resolve(domain, "A")
            return [(50, domain)]
        except Exception:
            return []

# ----------------- Verifier Core -----------------
class EmailVerifier:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    async def _smtp_probe(self, host: str, port: int, email: str) -> Tuple[str, str]:
        """Performs a single SMTP probe to a mail server."""
        client = None
        try:
            client = aiosmtplib.SMTP(
                hostname=host,
                port=port,
                timeout=self.cfg.SMTP_TIMEOUT,
                use_tls=(port == 465),
            )
            await asyncio.wait_for(client.connect(), timeout=self.cfg.CONNECT_TIMEOUT)
            hint = banner_hint(client.server_greeting or "")
            
            # EHLO/HELO
            try:
                await asyncio.wait_for(client.ehlo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)
            except (SMTPHeloError, asyncio.TimeoutError):
                await asyncio.wait_for(client.helo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)

            # STARTTLS on port 587
            if port == 587:
                await client.starttls()
                await client.ehlo(self.cfg.PROBE_DOMAIN)

            # MAIL FROM
            await client.mail(f"{rand_local()}@{self.cfg.PROBE_DOMAIN}")

            # Real RCPT
            code_real, _ = await client.rcpt(email)
            res_real = classify(code_real)

            # Catch-all probe
            domain = email.split("@", 1)[-1]
            code_fake, _ = await client.rcpt(f"{rand_local()}@{domain}")
            res_fake = classify(code_fake)

            if res_real == "ok" and res_fake == "ok":
                return "catch", "Accepts any address"
            if res_real == "ok":
                return "ok", f"RCPT {code_real}"
            if res_real == "dead":
                return "dead", f"RCPT {code_real}"
            if res_real == "temp":
                return "temp", f"RCPT {code_real}"

            if hint in ("ms", "google", "mimecast", "proofpoint"):
                return "lock", f"Policy {hint}"

            return "unknown", f"RCPT {code_real}"

        except SMTPConnectError:
            return "temp", "Connect Refused/Timeout"
        except asyncio.TimeoutError:
            return "temp", "Timeout"
        except SMTPException as e:
            return "unknown", f"SMTP Error: {type(e).__name__}"
        except Exception as e:
            return "unknown", f"Unexpected Error: {type(e).__name__}"
        finally:
            if client and client.is_connected:
                await client.quit()

    async def verify(self, email: str) -> Tuple[str, str]:
        """Main verification method that orchestrates the probes."""
        if not EMAIL_RE.match(email):
            return verdict_label("syntax"), "Invalid format"

        domain = email.split("@", 1)[-1]
        mx_records = await asyncio.get_running_loop().run_in_executor(None, cached_mx_lookup, domain)
        if not mx_records:
            return verdict_label("domain"), "No MX/A record"

        tasks = []
        for _, host in mx_records[:self.cfg.MAX_MX]:
            for p in self.cfg.PORTS:
                tasks.append(asyncio.create_task(self._smtp_probe(host, p, email)))

        decisive_kinds = {"ok", "dead", "catch", "lock"}
        soft_results = []
        
        for task in asyncio.as_completed(tasks):
            try:
                kind, why = await task
                if kind in decisive_kinds:
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    return verdict_label(kind), why
                else:
                    soft_results.append(f"{kind}:{why}")
            except asyncio.CancelledError:
                pass

        if soft_results:
            return verdict_label("unknown"), " / ".join(soft_results[:3])
        
        return verdict_label("unknown"), "Undetermined"


# ----------------- Telegram Handlers -----------------
CFG = Config()
VERIFIER = EmailVerifier(CFG)

WELCOME_MESSAGE = (
    "أهلًا! أرسل قائمة إيميلات (كل إيميل في سطر) وسأرجّع:\n"
    "✅ شغّال | ❌ غير شغّال | 🔒 يرفض التحقق | ⏳ مؤقت | 🎯 Catch-all | ⚠️ غير مؤكد\n\n"
    "مثال:\nuser@gmail.com\nnot-exist@nope-domain-xyz.com\ninfo@yourdomain.com"
)

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME_MESSAGE)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME_MESSAGE)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    emails = lines(text)[:25]
    if not emails:
        return

    msg = await update.message.reply_text("جاري التحقق… ⏳")
    results = []
    total = len(emails)

    for i, email in enumerate(emails, 1):
        filled = i * 10 // total
        bar = "▇" * filled + " " * (10 - filled)
        try:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=msg.message_id,
                text=f"جاري التحقق… ⏳\n`[{bar}]` {i}/{total} - {email}",
                parse_mode="Markdown",
            )
        except Exception:
            pass

        status, reason = await VERIFIER.verify(email)
        
        if status == "غير مؤكد ⚠️":
            results.append(f"{email} — {status} ({reason})")
        else:
            results.append(f"{email} — {status}")

    try:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=msg.message_id,
            text="\n".join(results),
        )
    except Exception:
        await update.message.reply_text("\n".join(results))

# ----------------- Main Entry Point -----------------
def main():
    if not CFG.BOT_TOKEN:
        raise SystemExit("Error: BOT_TOKEN is not set in environment variables.")
    app = Application.builder().token(CFG.BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    
    log.info("Email checker bot is running.")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
