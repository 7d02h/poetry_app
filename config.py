import os
from dotenv import load_dotenv

# تحميل متغيرات البيئة من ملف .env
load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # 🔑 مفتاح سرّي للتطبيق
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")

    # قاعدة البيانات
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "poetry.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # البريد الإلكتروني
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() in ["true", "1"]
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

    # الترجمة
    BABEL_DEFAULT_LOCALE = "ar"
    BABEL_TRANSLATION_DIRECTORIES = "translations"

    # رفع الملفات
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 2MB
    UPLOAD_FOLDER = os.path.join("static", "profile_pics")

    # CSRF
    WTF_CSRF_ENABLED = False
    WTF_CSRF_TIME_LIMIT = None

    # PayPal
    PAYPAL_CLIENT = os.getenv("PAYPAL_CLIENT")
    PAYPAL_SECRET = os.getenv("PAYPAL_SECRET")
    PAYPAL_API = "https://api-m.paypal.com"

    # Stripe
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET")
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC")