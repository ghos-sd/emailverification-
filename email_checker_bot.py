# -*- coding: utf-8 -*-
"""
Telegram bot: async email verifier (MX + SMTP RCPT probing)

- Python + asyncio
- aiosmtplib: اتصال SMTP غير متزامن وموثوق
- dns.resolver: جلب MX/‏A مع كاش لتقليل الاستعلامات
- python-telegram-bot: واجهة تيليجرام غير متزامنة

المنطق:
1) يتحقق من صيغة الإيميل.
2) يستعلم MX (ويFallback إلى A).
3) يجرب عدة بورتات 25/587/465 لكل MX.
4) ترتيب الأوامر: EHLO/HELO → STARTTLS (587) → MAIL FROM → RCPT TO.
5) يكشف catch-all عبر عنوان مزيف على نفس الدومين.
6) يصنّف النتيجة: ok/dead/temp/lock/catch/syntax/domain/unknown.
7) يحدّث رسالة واحدة بشريط تقدم، ويعرض النتائج النهائية بوضوح.
"""

import os, re, asyncio, random, string, logging, functools
from typing import List, Tuple, Optional

import aiosmtplib
from aiosmtplib import (
    SMTPConnectError,
    SMTPHeloError,
    SMTPRecipientRefused,
    SMTPRecipientsRefused,
    SMTPException,
)
import dns.resolver

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ===================== Config & Logging =====================
class Config:
    BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
    PROBE_DOMAIN = os.getenv("PROBE_DOMAIN", "verifier.example.com").strip()
    CONNECT_TIMEOUT = 8
    SMTP_TIMEOUT = 12
    PORTS = (587, 25, 465)
    MAX_MX = 3
    PARALLEL_PROBES = 4

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("email-check-bot")

# ثابت: ريزولفر DNS خارجي (أنسب داخل الحاويات)
_resolver = dns.resolver.Resolver(configure=False)
_resolver.nameservers = ["1.1.1.1", "1.0.0.1"]
dns_resolve = _resolver.resolve

# ===================== Utilities =====================
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
    if "outlook" in b or "protection.outlook.com" in b or "microsoft" in b: return "ms"
    if "google.com" in b or "gmail" in b or "google" in b: return "google"
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
        # Fallback إلى A إذا مافي MX
        try:
            dns_resolve(domain, "A")
            return [(50, domain)]
        except Exception:
            return []

# ===================== Verifier Core =====================
class EmailVerifier:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    async def _smtp_probe(self, host: str, port: int, email: str) -> Tuple[str, str]:
        """
        Probe واحد إلى خادم SMTP:
        EHLO/HELO → (STARTTLS لو 587) → MAIL FROM → RCPT TO (+ كشف catch-all).
        يرجع (kind, reason).
        """
        client = None
        try:
            client = aiosmtplib.SMTP(
                hostname=host,
                port=port,
                timeout=self.cfg.SMTP_TIMEOUT,
                use_tls=(port == 465),
            )

            # Connect + خُد لمحة عن المزود من البانر
            banner = await asyncio.wait_for(client.connect(), timeout=self.cfg.CONNECT_TIMEOUT)
            hint = banner_hint(banner or client.server_greeting or "")

            # EHLO/HELO
            try:
                await asyncio.wait_for(client.ehlo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)
            except (SMTPHeloError, asyncio.TimeoutError):
                await asyncio.wait_for(client.helo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)

            # STARTTLS على 587
            if port == 587:
                try:
                    await asyncio.wait_for(client.starttls(), timeout=self.cfg.SMTP_TIMEOUT)
                    await asyncio.wait_for(client.ehlo(self.cfg.PROBE_DOMAIN), timeout=self.cfg.SMTP_TIMEOUT)
                except Exception:
                    # بعض الخوادم ترفض STARTTLS — اعتبرها سياسة
                    return "lock" if hint else "unknown", "STARTTLS Rejected"

            # MAIL FROM (عنوان فاحص)
            try:
                code_mail, msg_mail = await asyncio.wait_for(
                    client.mail(f"{rand_local()}@{self.cfg.PROBE_DOMAIN}"),
                    timeout=self.cfg.SMTP_TIMEOUT,
                )
                if code_mail >= 500:
                    return ("lock" if hint else "unknown", f"MAIL FROM {code_mail}")
            except SMTPException as e:
                return "unknown", f"MAIL FROM error {type(e).__name__}"

            # RCPT الحقيقي — امسك كمان حالة الاستثناء
            try:
                code_real, msg_real = await asyncio.wait_for(client.rcpt(email), timeout=self.cfg.SMTP_TIMEOUT)
                res_real = classify(code_real)
            except SMTPRecipientRefused as e:
                code = getattr(e, "code", 550)
                res_real = classify(code)
                msg_real = f"{code} {getattr(e, 'message', '')}".strip()
            except SMTPRecipientsRefused as e:
                # بعض الإصدارات ترمي هذا بدلاً عن واحد مفرد
                # خذ أول كود إن وجد
                code = None
                try:
                    # dict: {recipient: (code, message)}
                    code = next(iter(e.recipients.values()))[0]
                except Exception:
                    pass
                if code is None:
                    return "unknown", "RCPT refused"
                res_real = classify(code)
                msg_real = f"{code}"

            # كشف catch-all بعنوان مزيف
            domain = email.split("@", 1)[-1]
            fake = f"{rand_local()}@{domain}"
            try:
                code_fake, _ = await asyncio.wait_for(client.rcpt(fake), timeout=self.cfg.SMTP_TIMEOUT)
                res_fake = classify(code_fake)
            except SMTPRecipientRefused as e:
                res_fake = classify(getattr(e, "code", 550))
            except SMTPRecipientsRefused as e:
                try:
                    code = next(iter(e.recipients.values()))[0]
                except Exception:
                    code = 550
                res_fake = classify(code)

            # قرار نهائي
            if res_real == "ok" and res_fake == "ok":
                return "catch", "Accepts any address"
            if res_real == "ok":
                return "ok", f"RCPT {msg_real}"
            if res_real == "dead":
                return "dead", f"RCPT {msg_real}"
            if res_real == "temp":
                return "temp", f"RCPT {msg_real}"

            if hint in ("ms", "google", "mimecast", "proofpoint"):
                return "lock", f"Policy {hint}"

            return "unknown", f"RCPT {msg_real}"

        except SMTPConnectError:
            return "temp", "Connect Refused/Timeout"
        except asyncio.TimeoutError:
            return "temp", "Timeout"
        except SMTPException as e:
            return "unknown", f"SMTP Error: {type(e).__name__}"
        except Exception as e:
            return "unknown", f"Unexpected: {type(e).__name__}"
        finally:
            if client and client.is_connected:
                try:
                    await client.quit()
                except Exception:
                    pass

    async def verify(self, email: str) -> Tuple[str, str]:
        if not EMAIL_RE.match(email):
            return verdict_label("syntax"), "Invalid format"

        domain = email.split("@", 1)[-1]
        mx_records = await asyncio.get_running_loop().run_in_executor(None, cached_mx_lookup, domain)
        if not mx_records:
            return verdict_label("domain"), "No MX/A record"

        # جهّز مهام متعددة (MX * Ports)
        tasks = [
            asyncio.create_task(self._smtp_probe(host, port, email))
            for _, host in mx_records[:Config.MAX_MX]
            for port in Config.PORTS
        ]

        decisive = {"ok", "dead", "catch", "lock"}
        soft_reasons = []

        # أول نتيجة حاسمة تُنهي الباقي
        for t in asyncio.as_completed(tasks):
            try:
                kind, why = await t
                if kind in decisive:
                    for other in tasks:
                        if not other.done():
                            other.cancel()
                    return verdict_label(kind), why
                else:
                    soft_reasons.append(f"{kind}:{why}")
            except asyncio.CancelledError:
                pass

        if soft_reasons:
            return verdict_label("unknown"), " / ".join(soft_reasons[:3])
        return verdict_label("unknown"), "Undetermined"

# ===================== Telegram Handlers =====================
CFG = Config()
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
    text = (update.message.text or "").strip()
    emails = lines(text)[:25]
    if not emails:
        return

    msg = await update.message.reply_text("جاري التحقق… ⏳")
    results = []
    total = len(emails)

    for i, email in enumerate(emails, 1):
        bar = "▇" * (i * 10 // total) + " " * (10 - (i * 10 // total))
        try:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=msg.message_id,
                text=f"جاري التحقق… ⏳\n`[{bar}]` {i}/{total} - {email}",
                parse_mode="Markdown",
            )
        except Exception:
            pass

        verdict, reason = await VERIFIER.verify(email)
        # اعرض السبب المختصر للإيميلات غير المؤكدة/المؤقتة
        label = verdict
        if "غير مؤكد" in verdict or "مؤقت" in verdict or "يرفض" in verdict:
            label = f"{verdict} — {reason}"
        results.append(f"{email} — {label}")

    final_text = "\n".join(results)
    try:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=msg.message_id,
            text=final_text,
        )
    except Exception:
        await update.message.reply_text(final_text)

# ===================== Main =====================
def main():
    if not CFG.BOT_TOKEN:
        raise SystemExit("Error: BOT_TOKEN is not set.")
    app = Application.builder().token(CFG.BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    log.info("Email checker bot is running.")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()        "dead": "غير شغّال ❌",
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
