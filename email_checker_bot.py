# -*- coding: utf-8 -*-
import os, re, asyncio, random, string, logging
from typing import List, Tuple, Optional

import aiosmtplib
import dns.resolver

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ---------- إعدادات ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("email-check-bot")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

# مهلات واتصالات
CONNECT_TIMEOUT = 8
SMTP_TIMEOUT = 12
PORTS = (587, 25, 465)

# ---------- أدوات ----------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

def normalize_lines(text: str) -> List[str]:
    lines = [ln.strip() for ln in (text or "").splitlines()]
    return [ln for ln in lines if ln]

async def dns_mx(domain: str) -> List[Tuple[int, str]]:
    """يرجع [(priority, host), ...] أو []"""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        pairs = []
        for r in answers:
            try:
                pairs.append((int(r.preference), str(r.exchange).rstrip(".")))
            except Exception:
                continue
        pairs.sort(key=lambda x: x[0])
        return pairs
    except Exception as e:
        log.debug("MX lookup failed for %s: %s", domain, e)
        # fallback: جرّب A كملقم بريد
        try:
            dns.resolver.resolve(domain, "A")
            return [(50, domain)]
        except Exception:
            return []

def rand_local() -> str:
    return "probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

def classify_smtp_code(code: int, message: str) -> str:
    """يصنف كود SMTP إلى نتيجة عربية مختصرة."""
    if code in (250, 251):
        return "ok"  # شغّال
    if code in (550, 551, 552, 553, 554):
        return "dead"  # غير شغّال
    if code in (450, 451, 452, 421):
        return "temp"  # مؤقت/غير مؤكد
    # أي شيء غامض
    return "unknown"

async def smtp_probe(host: str, port: int, email: str, helo_name: str) -> Tuple[str, str]:
    """
    يرجع (result, reason)
    result ∈ {"ok", "dead", "temp", "unknown", "conn_refused"}
    """
    use_tls = (port == 465)
    try:
        client = aiosmtplib.SMTP(
            hostname=host,
            port=port,
            timeout=CONNECT_TIMEOUT if use_tls else SMTP_TIMEOUT,
            use_tls=use_tls,
            start_tls=(port == 587),
            tls_context=None,
        )
        await client.connect()
        try:
            await client.ehlo(helo_name)
        except Exception:
            # بعض السيرفرات تتقبل HELO فقط
            try:
                await client.helo(helo_name)
            except Exception:
                await client.quit()
                return "unknown", "لم يرد على HELO/EHLO"

        # من الأفضل MAIL FROM عنوان بسيط غير حقيقي
        mail_from = f"{rand_local()}@{helo_name}"
        code, msg = await client.mail(mail_from)
        if code >= 400:
            await client.quit()
            return "unknown", f"MAIL_FROM {code}"

        # RCPT الحقيقي
        code_rcpt, msg_rcpt = await client.rcpt(email)
        cls = classify_smtp_code(code_rcpt, msg_rcpt.decode() if isinstance(msg_rcpt, bytes) else str(msg_rcpt))

        # محاولة اكتشاف catch-all: جرّب عنوان عشوائي بنفس الدومين
        domain = email.split("@", 1)[-1]
        fake_rcpt = f"{rand_local()}@{domain}"
        code_fake, msg_fake = await client.rcpt(fake_rcpt)
        cls_fake = classify_smtp_code(code_fake, msg_fake.decode() if isinstance(msg_fake, bytes) else str(msg_fake))

        await client.quit()

        # إذا الاثنين OK -> catch-all
        if cls in ("ok",) and cls_fake in ("ok",):
            return "unknown", "Catch-all (السيرفر يقبل أي عنوان)"
        return cls, f"RCPT {code_rcpt}"

    except aiosmtplib.errors.SMTPConnectError as e:
        return "conn_refused", "رفض الاتصال"
    except asyncio.TimeoutError:
        return "conn_refused", "مهلة اتصال"
    except Exception as e:
        return "unknown", f"استثناء: {e.__class__.__name__}"

async def verify_email(email: str) -> Tuple[str, str]:
    """
    يرجع (تصنيف عربي, سبب مختصر)
    التصنيفات: "شغّال ✅" / "غير شغّال ❌" / "غير مؤكد ⚠️" / "صيغة غير صحيحة ❌" / "دومين غير صالح ❌"
    """
    if not EMAIL_RE.match(email):
        return "صيغة غير صحيحة ❌", "صيغة الإيميل"

    domain = email.split("@", 1)[-1]
    mx_list = await asyncio.get_event_loop().run_in_executor(None, dns_mx, domain)
    if not mx_list:
        return "دومين غير صالح ❌", "لا سجلات MX/A"

    helo_name = "validator.local"
    # جرّب أكثر من MX وأكثر من بورت حتى نصل لنتيجة واضحة
    uncertain_reasons = []
    for _, host in mx_list[:3]:  # خليك خفيف
        for port in PORTS:
            result, reason = await smtp_probe(host, port, email, helo_name)
            if result == "ok":
                return "شغّال ✅", f"{host}:{port} {reason}"
            if result == "dead":
                return "غير شغّال ❌", f"{host}:{port} {reason}"
            if result in ("temp", "unknown", "conn_refused"):
                uncertain_reasons.append(f"{host}:{port} {reason}")

    # لو مافي نتيجة قاطعة
    return "غير مؤكد ⚠️", " / ".join(uncertain_reasons[:3]) or "غير محدد"

# ---------- Telegram ----------
WELCOME = (
    "أهلًا! أرسل قائمة إيميلات (كل إيميل في سطر) وسأتحقق:\n"
    "✅ شغّال / ❌ غير شغّال / ⚠️ غير مؤكد / ❌ غير مؤكد صيغة/دومين\n\n"
    "مثال:\n"
    "user@gmail.com\n"
    "not-exist@nope-domain-xyz.com\n"
    "info@yourdomain.com"
)

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    emails = normalize_lines(text)
    if not emails:
        return
    # حد أقصى عشان ما نتخطى مهلة تيليجرام
    emails = emails[:20]

    await update.message.reply_text("جاري التحقق… ⏳")

    results = []
    for em in emails:
        try:
            status, why = await verify_email(em)
        except Exception as e:
            log.exception("verify failed")
            status, why = "غير مؤكد ⚠️", f"استثناء: {e.__class__.__name__}"
        results.append(f"{em} — {status}")

    await update.message.reply_text("\n".join(results))

def main():
    if not BOT_TOKEN:
        raise SystemExit("ضع BOT_TOKEN في المتغيرات.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    log.info("Email checker bot running…")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
