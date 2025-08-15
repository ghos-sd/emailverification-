# -*- coding: utf-8 -*-
import os, re, ssl, time, logging, socket, asyncio
from typing import List, Tuple, Optional

import smtplib
import dns.resolver  # dnspython
from telegram import Update
from telegram.constants import ChatAction
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ----------------- إعدادات عامة -----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("email-checker-bot")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "validator@example.com")  # MAIL FROM أثناء الاختبار
CONCURRENCY = int(os.getenv("CONCURRENCY", "8"))
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "12"))  # ثواني
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "5"))

WELCOME = (
    "👋 أهلاً! أرسل قائمة إيميلات (كل إيميل في سطر) وسأرد:\n"
    "email — شغال ✅ / غير شغال ❌ / غير مؤكد ⚠️\n\n"
    "مثال:\nuser@gmail.com\nnot-exist@nope-domain-xyz.com\ninfo@yourdomain.com"
)

# ----------------- أدوات مساعدة -----------------
EMAIL_RE = re.compile(
    r"^(?!.{255,})([a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*)@"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})$", re.I
)

def parse_lines(text: str) -> List[str]:
    emails = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", line, re.I)
        if m:
            emails.append(m.group(0))
    # إزالة التكرارات مع الحفاظ على الترتيب
    seen = set(); out = []
    for e in emails:
        k = e.lower()
        if k not in seen:
            seen.add(k); out.append(e)
    return out

def syntax_ok(email: str) -> bool:
    return EMAIL_RE.match(email or "") is not None

# ----------------- DNS (MX) -----------------
async def resolve_mx(domain: str) -> List[Tuple[int, str]]:
    """يرجع قائمة [(priority, host), ...]"""
    loop = asyncio.get_running_loop()
    def _lookup():
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = DNS_TIMEOUT
            resolver.timeout = DNS_TIMEOUT
            answers = resolver.resolve(domain, "MX")
            res = []
            for r in answers:
                try:
                    prio = int(r.preference)
                    host = str(r.exchange).rstrip(".")
                    res.append((prio, host))
                except Exception:
                    pass
            return sorted(res, key=lambda x: x[0])
        except Exception:
            return []
    return await loop.run_in_executor(None, _lookup)

# ----------------- SMTP تحقق -----------------
def _smtp_check_on_host(host: str, recipient: str, mail_from: str, timeout: float) -> Tuple[str, str]:
    """
    يرجع (status, note):
    - deliverable (250/251)
    - rejected    (550/551/552/553/554)
    - unknown     (أي شيء آخر/مهلة/حظر)
    """
    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP(host=host, port=25, timeout=timeout)
        code, _ = server.ehlo()
        if server.has_extn("starttls"):
            server.starttls(context=context)
            server.ehlo()
        server.mail(mail_from)
        code, _ = server.rcpt(recipient)
        server.quit()
        if code in (250, 251):
            return "deliverable", f"RCPT {code}"
        if code in (550, 551, 552, 553, 554):
            return "rejected", f"RCPT {code}"
        return "unknown", f"RCPT {code}"
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
            smtplib.SMTPHeloError, smtplib.SMTPRecipientsRefused,
            smtplib.SMTPDataError, smtplib.SMTPResponseException,
            socket.timeout, TimeoutError, OSError) as e:
        return "unknown", type(e).__name__

async def smtp_verify(email: str) -> str:
    """
    يرجّع واحدة من: شغال ✅ / غير شغال ❌ / غير مؤكد ⚠️
    """
    if not syntax_ok(email):
        return "غير شغال ❌"

    domain = email.split("@", 1)[1].lower()
    mx_list = await resolve_mx(domain)
    if not mx_list:
        return "غير شغال ❌"

    # جرّب أول 3 MX
    for _, host in mx_list[:3]:
        status, _ = await asyncio.to_thread(_smtp_check_on_host, host, email, SENDER_EMAIL, SMTP_TIMEOUT)
        if status == "deliverable":
            return "شغال ✅"
        if status == "rejected":
            return "غير شغال ❌"
    return "غير مؤكد ⚠️"

# ----------------- Telegram Handlers -----------------
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    emails = parse_lines(text)
    if not emails:
        await update.message.reply_text("أرسل قائمة إيميلات — كل إيميل في سطر.")
        return

    await update.message.chat.send_action(ChatAction.TYPING)

    sem = asyncio.Semaphore(CONCURRENCY)
    async def checked(e):
        async with sem:
            status = await smtp_verify(e)
            return f"{e} — {status}"

    results = await asyncio.gather(*[checked(e) for e in emails])
    reply = "\n".join(results)
    await update.message.reply_text(reply if len(reply) <= 4000 else reply[:3990] + "…")

# ----------------- Run bot -----------------
def main():
    if not BOT_TOKEN:
        raise SystemExit("Set BOT_TOKEN environment variable.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    log.info("Email checker bot is running…")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
