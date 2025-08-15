# Email Checker Bot (Telegram)

بوت تيليجرام يتحقق من الإيميلات بدون أي API خارجي:
- يتحقق من الصيغة Regex
- يفحص سجلات MX عبر DNS
- يحاول تحقق SMTP (RCPT TO) على أول 1-3 مزوّدين MX

## المتطلبات
- Python 3.9+
- الحزم في requirements.txt

## الإعداد
1) نزّل الحزم:
   pip install -r requirements.txt

2) اضبط المتغيرات:
   - BOT_TOKEN: توكن البوت من BotFather
   - SENDER_EMAIL: الإيميل المستخدم في MAIL FROM أثناء اختبار SMTP (أي بريد صالح شكليًا)
   - CONCURRENCY: أقصى عدد مهام متوازية (افتراضي 8)
   - SMTP_TIMEOUT: مهلة محاولة SMTP بالثواني (افتراضي 12)
   - DNS_TIMEOUT: مهلة استعلام DNS بالثواني (افتراضي 5)

3) التشغيل محليًا:
   export BOT_TOKEN=... && python email_checker_bot.py

4) Railway
   - ارفع الملفات
   - أضف Variables المذكورة
   - Procfile: worker: python email_checker_bot.py
   - Deploy

## الاستخدام
- أرسل للبوت قائمة إيميلات (كل بريد في سطر).
- البوت يرد:
   email@example.com — شغال ✅ / غير شغال ❌ / غير مؤكد ⚠️

## ملاحظات
- بعض الدومينات الكبيرة (Gmail/Outlook) قد تُرجع "غير مؤكد ⚠️" لأنها تمنع التحقق المباشر (catch-all/greylisting).
- قلّل CONCURRENCY إذا واجهت rate limits.
