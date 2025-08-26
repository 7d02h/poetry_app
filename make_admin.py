# make_admin.py

import smtplib

sender = "hzft92925@gmail.com"   # بريدك
password = "yssr eyrj pefb sefq"     # كلمة مرور التطبيق (16 خانة)
receiver = "mohamadiaui@gmail.com"   # بريد للتجربة

try:
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()  # تفعيل التشفير
        server.login(sender, password)  # تسجيل الدخول
        subject = "Test"
        body = "Hello, this is a test email."
        msg = f"Subject: {subject}\n\n{body}"
        server.sendmail(sender, receiver, msg)

    print("✅ تم إرسال البريد بنجاح!")

except Exception as e:
    print("❌ خطأ:", e)

