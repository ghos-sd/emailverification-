# -*- coding: utf-8 -*-
"""
Telegram Email Verifier Bot (Async)

- Core: Python (asyncio)
- Libraries: aiosmtplib (async SMTP), python-telegram-bot (Telegram API), dnspython/dns.resolver (DNS/MX)
- What it does:
  * Parses user messages (one email per line) and verifies each email via SMTP:
      EHLO/HELO → (STARTTLS on 587) → MAIL FROM → RCPT TO
  * Detects catch-all by probing a fake address on the same domain
  * Tries common SMTP ports (25, 587, 465) for each MX
  * Uses dns.resolver to get MX records (falls back to A if no MX)
  * Enforces timeouts for all network ops to avoid hanging
  * Classifies results into:
      ok (valid), dead (does not exist), temp (temporary issue),
      lock (verification rejected by policy), catch (catch-all domain),
      syntax (invalid format), domain (no MX/A), unknown (unconfirmed)
  * Sends real-time progress updates (single edited message + progress bar)
  * Outputs a clean summary per email with the verdict label

- Configuration:
  * BOT_TOKEN (env)      : Telegram Bot token
  * PROBE_DOMAIN (env)   : FQDN used in EHLO/MAIL FROM (use a REAL domain/subdomain you control)
"""

import os
import re
import asyncio
import random
import string
import logging
import functools
from typing import List, Tuple, Optional

import aiosmtplib
from aiosmtplib import SMTPConnectError, SMTPHeloError, SMTPException
import dns.resolver

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ----------------- Configuration & Logging -----------------
class Config:
    BOT_TOKEN: str = os.getenv("BOT_TOKEN", "").strip()
    PROBE_DOMAIN: str = os.getenv("PROBE_DOMAIN", "probe.example.com").strip()  # Set a REAL FQDN for better trust
    CONNECT_TIMEOUT: float = 8
    SMTP_TIMEOUT: float = 12
    PORTS: Tuple[int, ...] = (587, 25, 465)
    MAX_MX: int = 3                 # Max MX records to try (by priority)
    PARALLEL_PROBES: int = 4        # Limit concurrent probes per email

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("email-check-bot")

CFG = Config()

# --------- Stable DNS Resolver (Cloudflare) ---------
# Using a fixed, reliable resolver reduces flakiness in containers
_resolver = dns.resolver.Resolver(configure=False)
_resolver.nameservers = ["1.1.1.1", "1.0.0.1"]
_resolver.lifetime = 4.0
_resolver.timeout = 2.0
dns_resolve = _resolver.resolve

# ----------------- Utilities -----------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

def lines(text: str) -> List[str]:
    """Split into clean non-empty lines."""
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]

def rand_local() -> str:
    """Random local-part used in MAIL FROM and fake RCPT."""
    return "probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

def classify(code: int) -> str:
    """Map SMTP numeric reply to a coarse category."""
    if code in (250, 251):
        return "ok"
    if code in (550, 551, 552, 553, 554):
        return "dead"
    if code in (450, 451, 452, 421):
        return "temp"
    return "unknown"

def banner_hint(banner: str) -> Optional[str]:
    """Identify common hosted providers from the banner for policy hints."""
    b = (banner or "").lower()
    if "outlook" in b or "protection.outlook.com" in b or "microsoft" in b:
        return "ms"
    if "google.com" in b or "gmail" in b or "google" in b:
        return "google"
    if "proofpoint" in b:
        return "proofpoint"
    if "mimecast" in b:
        return "mimecast"
    return None

def verdict_label(kind: str) -> str:
    """User-facing label text with emoji."""
    return {
        "ok": "شغّال ✅",
        "dead": "غير شغّال ❌",
        "temp": "مؤقت ⏳",
        "lock": "يرفض التحقق 🔒",
        "catch": "Catch-all 🎯",
        "syntax": "صيغة غير صحيحة ❌",
        "domain": "دومين غير صالح ❌",
        "unknown": "غير مؤكد ⚠️",
    }.get(kind, "غير مؤكد ⚠️")

@functools.lru_cache(maxsize=1024)
def cached_mx_lookup(domain: str) -> List[Tuple[int, str]]:
    """Resolve MX records (cached). Fallback to A record if no MX."""
    try:
        ans = dns_resolve(domain, "MX")
        pairs: List[Tuple[int, str]] = []
        for r in ans:
            try:
                pairs.append((int(r.preference), str(r.exchange).rstrip(".")))
            except Exception:
                pass
        pairs.sort(key=lambda x: x[0])
        return pairs
    except Exception:
        # Fallback to A record
        try:
            dns_resolve(domain, "A")
            return [(50, domain)]
        except Exception:
            return []

# ----------------- Verifier Core -----------------
class EmailVerifier:
    """Core logic to verify a single email asynchronously."""
    def __init__(self, cfg: Config):
        self.cfg = cfg

    async def _smtp_probe(self, host: str, port: int, email: str) -> Tuple[str, str]:
        """
        One SMTP probe flow:
          connect → EHLO/HELO → (STARTTLS on 587) → MAIL FROM → RCPT TO (real) → RCPT TO (fake)
        Returns (kind, reason)
        """
        client: Optional[aiosmtplib.SMTP] = None
        try:
            client = aiosmtplib.SMTP(
                hostname=host,
                port=port,
                timeout=self.cfg.SMTP_TIMEOUT,
                use_tls=(port == 465),  # implicit TLS on 465
            )
            banner = await asyncio.wait_for(client.connect(), timeout=self.cfg.CONNECT_TIMEOUT)
            hint = banner_hint(banner or "")

            # EHLO/HELO
            try:
                await asyncio.wait_for(client.ehlo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)
            except (SMTPHeloError, asyncio.TimeoutError):
                try:
                    await asyncio.wait_for(client.helo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)
                except Exception:
                    # Some providers will block untrusted EHLO
                    return ("lock" if hint in ("ms", "mimecast", "proofpoint") else "unknown", "HELO/EHLO Rejected")

            # STARTTLS on 587 if available; if refused, continue without failing hard
            if port == 587:
                try:
                    await asyncio.wait_for(client.starttls(), timeout=self.cfg.SMTP_TIMEOUT)
                    await asyncio.wait_for(client.ehlo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)
                except Exception:
                    pass

            # MAIL FROM (use non-existent but well-formed probe address)
            code_mail, _ = await asyncio.wait_for(
                client.mail(f"{rand_local()}@{self.cfg.PROBE_DOMAIN}"),
                timeout=self.cfg.SMTP_TIMEOUT,
            )
            if code_mail >= 500:
                # Policy/Relay restriction is common → treat as lock/unknown (based on hint)
                return ("lock" if hint else "unknown", f"MAIL FROM {code_mail}")

            # RCPT (real)
            code_real, _ = await asyncio.wait_for(client.rcpt(email), timeout=self.cfg.SMTP_TIMEOUT)
            res_real = classify(code_real)

            # Catch-all detection: RCPT (fake) for same domain
            domain = email.split("@", 1)[-1]
            fake_rcpt = f"{rand_local()}@{domain}"
            code_fake, _ = await asyncio.wait_for(client.rcpt(fake_rcpt), timeout=self.cfg.SMTP_TIMEOUT)
            res_fake = classify(code_fake)

            # Decide
            if res_real == "ok" and res_fake == "ok":
                return "catch", "Accepts any address"
            if res_real == "ok":
                return "ok", f"RCPT {code_real}"
            if res_real == "dead":
                return "dead", f"RCPT {code_real}"
            if res_real == "temp":
                return "temp", f"RCPT {code_real}"

            # Big providers sometimes obscure verification without AUTH
            if hint in ("ms", "google", "mimecast", "proofpoint"):
                return "lock", f"Policy {hint}"

            return "unknown", f"RCPT {code_real}"

        except SMTPConnectError:
            return "temp", "Connect Refused/Timeout"
        except asyncio.TimeoutError:
            return "temp", "Timeout"
        except SMTPException as e:
            return "unknown", f"SMTP {e.__class__.__name__}"
        except Exception as e:
            return "unknown", f"Exception {e.__class__.__name__}"
        finally:
            if client and client.is_connected:
                try:
                    await client.quit()
                except Exception:
                    pass

    async def verify(self, email: str) -> Tuple[str, str]:
        """
        High-level verification (per email):
          - syntax check
          - MX lookup (fallback A)
          - parallel probes across MX × PORTS (limited by PARALLEL_PROBES)
          - return first decisive result; otherwise summarize soft reasons
        """
        if not EMAIL_RE.match(email):
            return verdict_label("syntax"), "Invalid format"

        domain = email.split("@", 1)[-1]
        mx_list = await asyncio.get_running_loop().run_in_executor(None, cached_mx_lookup, domain)
        if not mx_list:
            return verdict_label("domain"), "No MX/A record"

        # Prepare targets
        targets: List[Tuple[str, int]] = []
        for _, host in mx_list[: self.cfg.MAX_MX]:
            for p in self.cfg.PORTS:
                targets.append((host, p))

        # Limit concurrency per email for politeness and stability
        sem = asyncio.Semaphore(self.cfg.PARALLEL_PROBES)
        decisive = {"ok", "dead", "catch", "lock"}

        async def runner(h: str, p: int) -> Tuple[str, str]:
            async with sem:
                return await self._smtp_probe(h, p, email)

        tasks = [asyncio.create_task(runner(h, p)) for h, p in targets]

        try:
            for t in asyncio.as_completed(tasks):
                kind, why = await t
                if kind in decisive:
                    # Cancel the rest once we have a decisive answer
                    for other in tasks:
                        if not other.done():
                            other.cancel()
                    return verdict_label(kind), why
            # If no decisive answer, collect soft reasons
            soft = []
            for task in tasks:
                if task.done():
                    k, w = task.result()
                    if k not in decisive:
                        soft.append(f"{k}:{w}")
            return verdict_label("unknown"), " / ".join(soft[:3]) if soft else "Undetermined"
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

# ----------------- Telegram Handlers -----------------
VERIFIER = EmailVerifier(CFG)

WELCOME = (
    "أهلًا! أرسل قائمة إيميلات (كل إيميل في سطر) وسأرجّع:\n"
    "✅ شغّال | ❌ غير شغّال | 🔒 يرفض التحقق | ⏳ مؤقت | 🎯 Catch-all | ⚠️ غير مؤكد\n\n"
    "مثال:\nuser@gmail.com\nnot-exist@nope-domain-xyz.com\ninfo@yourdomain.com"
)

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Accept a list of emails (one per line), verify them concurrently,
    show live progress by editing one message, then print the final report.
    """
    raw = (update.message.text or "").strip()
    emails = lines(raw)[:25]  # keep reasonable batch size
    if not emails:
        return

    msg = await update.message.reply_text("جاري التحقق… ⏳")
    results: List[Tuple[int, str]] = [(-1, "")] * len(emails)

    # Run checks concurrently per email, but we’ll still emit progress
    async def verify_indexed(idx: int, em: str):
        status, reason = await VERIFIER.verify(em)
        return idx, f"{em} — {status}"

    tasks = [asyncio.create_task(verify_indexed(i, em)) for i, em in enumerate(emails)]
    completed = 0
    total = len(tasks)

    for t in asyncio.as_completed(tasks):
        idx, line = await t
        results[idx] = (idx, line)
        completed += 1
        filled = max(1, completed * 10 // total)
        bar = "▇" * filled + " " * (10 - filled)
        try:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=msg.message_id,
                text=f"جاري التحقق… ⏳\n`[{bar}]` {completed}/{total}\nآخر نتيجة: {line}",
                parse_mode="Markdown",
            )
        except Exception:
            pass

    # Final sorted output (original order)
    final_lines = [ln for _, ln in sorted(results, key=lambda x: x[0])]
    final_text = "\n".join(final_lines) if final_lines else "لا توجد نتائج."
    try:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=msg.message_id,
            text=final_text,
        )
    except Exception:
        await update.message.reply_text(final_text)

# ----------------- Main -----------------
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
