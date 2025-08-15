# -*- coding: utf-8 -*-
import os
import re
import asyncio
import random
import string
from typing import List, Tuple, Optional

import aiosmtplib
import dns.asyncresolver
from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters
)

# ========= إعدادات عامة =========
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

# الإيميل/الدومين الذي سنستخدمه في MAIL FROM خلال اختبار SMTP
# لا يحتاج أن يكون حقيقيًا ما دمنا لا نُسلّم الرسالة.
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "check@verifier.example")
SENDER_DOMAIN = SENDER_EMAIL.split("@")[-1] if "@" in SENDER_EMAIL else "verifier.example"

# مهلات الشبكة
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "6.0"))
SMTP_CONNECT_TIMEOUT = float(os.getenv("SMTP_CONNECT_TIMEOUT", "12.0"))
SMTP_TOTAL_TIMEOUT = float(os.getenv("SMTP_TOTAL_TIMEOUT", "18.0"))

HELP = (
    "أهلًا! أرسل قائمة إيميلات (كل إيميل في سطر) وسأتحقق لك:\n"
    "✅ شغال — ❌ غير شغال — ⚠️ Catch-all — ⏳ مهلة — 🔒 رفض الاتصال — 🧩 صيغة غير صالحة\n\n"
    "مثال:\n"
    "user@gmail.com\n"
    "not-exist@nope-domain-xyz.com\n"
    "info@yourdomain.com"
)

EMAIL_RE = re.compile(
    r"^(?P<local>[-!#$%&'*+/0-9=?A-Z^_`a-z{|}~.]+)@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})$"
)

def is_valid_format(email: str) -> bool:
    return bool(EMAIL_RE.match(email.strip()))

def split_lines(text: str) -> List[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]

async def resolve_mx(domain: str) -> List[Tuple[int, str]]:
    """يرجع [(priority, host), ...] مرتبًا بالأولوية."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        ans = await resolver.resolve(domain, "MX")
        out = []
        for r in ans:
            # r.exchange هو اسم السيرفر بنقطة في النهاية.
            host = str(r.exchange).rstrip(".")
            out.append((int(r.preference), host))
        out.sort(key=lambda x: x[0])
        return out
    except Exception:
        return []

def random_localpart(n: int = 10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(n))

async def smtp_handshake(
    mx_host: str, recipient: str, helo_domain: str
) -> Tuple[Optional[int], Optional[str]]:
    """
    يرجع (code, message) من خطوة RCPT TO.
    code قد يكون 250/251 قبول، أو 550/551/5xx رفض.
    """
    try:
        client = aiosmtplib.SMTP(
            hostname=mx_host,
            port=25,
            timeout=SMTP_CONNECT_TIMEOUT,
            use_tls=False,
            start_tls=True,  # جرّب STARTTLS إن كان متاحًا
        )
        await asyncio.wait_for(client.connect(), timeout=SMTP_CONNECT_TIMEOUT)
        # بعض السيرفرات تطلب EHLO/HELO
        await client.ehlo(helo_domain)
        try:
            await client.starttls()
            await client.ehlo(helo_domain)
        except aiosmtplib.errors.SMTPException:
            # لو السيرفر لا يدعم STARTTLS، نُكمل عادي
            pass

        await client.mail(SENDER_EMAIL)
        code, msg = await client.rcpt(recipient)
        await client.quit()
        # msg قد يكون bytes أو str حسب الخادم
        if isinstance(msg, bytes):
            msg = msg.decode("utf-8", "ignore")
        return code, (msg or "")
    except asyncio.TimeoutError:
        return None, "timeout"
    except aiosmtplib.errors.SMTPException as e:
        # أخطاء SMTP نفسها (رفض مبكر، إلخ)
        # قد تحتوي على code
        code = getattr(e, "code", None)
        return code, str(e)
    except Exception as e:
        return None, f"conn_error: {e}"

async def detect_catch_all(mx_host: str, domain: str) -> bool:
    """
    نختبر عنوانًا عشوائيًا غير موجود على نفس الدومين:
    إذا قَبِله السيرفر، غالبًا الدومين Catch-all.
    """
    fake_rcpt = f"{random_localpart()}@{domain}"
    code, _ = await smtp_handshake(mx_host, fake_rcpt, SENDER_DOMAIN)
    # قبول 250/251 يعني احتمال كبير Catch-all
    return code in (250, 251)

def classify(code: Optional[int], msg: Optional[str]) -> str:
    """
    يحوّل أكواد SMTP/الرسالة إلى تصنيف مفهوم.
    """
    if code is None and msg == "timeout":
        return "⏳ مهلة"
    if code is None and msg and msg.startswith("conn_error"):
        return "🔒 رفض الاتصال"

    if code in (250, 251):
        return "✅ شغال"

    # أشهر أكواد الرفض
    if code and (500 <= code < 600):
        return "❌ غير شغال"

    # fallback عام
    return "❌ غير شغال"

async def verify_single(email: str) -> str:
    """
    يتحقق من إيميل واحد ويُرجع سطر نتيجة: "<email> — <status>"
    """
    if not is_valid_format(email):
        return f"{email} — 🧩 صيغة غير صالحة"

    m = EMAIL_RE.match(email)
    domain = m.group("domain") if m else email.split("@")[-1]

    # حل MX
    mx_list = await resolve_mx(domain)
    if not mx_list:
        return f"{email} — ❌ دومين بلا MX"

    last_status = "🔒 رفض الاتصال"
    catch_all_flag = False

    # جرّب أكثر من MX حتى نصل لنتيجة واضحة
    for _, mx in mx_list[:3]:  # يكفي أول 3 خوادم
        # اكتشاف catch-all (مرة واحدة تكفي)
        if not catch_all_flag:
            try:
                catch_all_flag = await detect_catch_all(mx, domain)
            except Exception:
                pass

        code, msg = await smtp_handshake(mx, email, SENDER_DOMAIN)
        status = classify(code, msg)

        # لو شغال ✅ أو غير شغال ❌ — خلاص نرجع النتيجة
        if status in ("✅ شغال", "❌ غير شغال"):
            # لو الدومين Catch-all ننبه
            if catch_all_flag and status == "✅ شغال":
                return f"{email} — ⚠️ Catch-all (قد يقبل أي عنوان)"
            return f"{email} — {status}"

        last_status = status  # حفظ آخر وضع (مهلة/رفض اتصال)
        # وإلا نجرب MX آخر…

    # لو ما حصلنا نتيجة قاطعة:
    if catch_all_flag:
        return f"{email} — ⚠️ Catch-all (قد يقبل أي عنوان)"
    return f"{email} — {last_status}"

# ========= Telegram =========
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP)

async def verify_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    emails = split_lines(text)
    if not emails:
        await update.message.reply_text("أرسل إيميلات (كل إيميل في سطر).")
        return

    # تحديد حد معقول للدفعة
    if len(emails) > 50:
        await update.message.reply_text("الحد الأقصى في دفعة واحدة هو 50 إيميل.")
        return

    await update.message.reply_text("⏳ جاري التحقق…")

    # نتحقق بالتوازي لكن بدون إرهاق الشبكة (سِماح 8 مهام متزامنة)
    sem = asyncio.Semaphore(8)
    results: List[str] = []

    async def run_one(addr: str):
        async with sem:
            try:
                r = await asyncio.wait_for(verify_single(addr), timeout=SMTP_TOTAL_TIMEOUT + 6)
            except asyncio.TimeoutError:
                r = f"{addr} — ⏳ مهلة"
            results.append(r)

    tasks = [asyncio.create_task(run_one(e)) for e in emails]
    await asyncio.gather(*tasks)

    # حافظ على ترتيب الإدخال
    order = {e: i for i, e in enumerate(emails)}
    results.sort(key=lambda s: order.get(s.split(" — ")[0], 0))
    out = "\n".join(results)
    await update.message.reply_text(out)

def main():
    if not BOT_TOKEN:
        raise SystemExit("Set BOT_TOKEN env var.")

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, verify_handler))

    print("Email verifier bot running…")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
