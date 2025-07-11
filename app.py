from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from datetime import date

app = Flask(__name__)

# إنشاء قاعدة البيانات إن لم تكن موجودة
def init_db():
    with sqlite3.connect("poetry.db") as conn:
        # جدول الأبيات الشعرية
        conn.execute('''
            CREATE TABLE IF NOT EXISTS poems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                likes INTEGER DEFAULT 0,
                created DATE DEFAULT CURRENT_DATE
            )
        ''')

        # جدول المستخدمين
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

@app.route("/")
def index():
    today = date.today().isoformat()
    with sqlite3.connect("poetry.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM poems WHERE created = ? ORDER BY likes DESC LIMIT 3", (today,))
        top_poems = cursor.fetchall()
        cursor.execute("SELECT * FROM poems ORDER BY id DESC")
        all_poems = cursor.fetchall()
    return render_template("index.html", top_poems=top_poems, all_poems=all_poems)

@app.route("/submit", methods=["POST"])
def submit():
    text = request.form.get("poem")
    if text.strip():
        with sqlite3.connect("poetry.db") as conn:
            conn.execute("INSERT INTO poems (text) VALUES (?)", (text.strip(),))
    return redirect(url_for("index"))

@app.route("/like/<int:poem_id>", methods=["POST"])
def like(poem_id):
    with sqlite3.connect("poetry.db") as conn:
        conn.execute("UPDATE poems SET likes = likes + 1 WHERE id = ?", (poem_id,))
    return redirect(url_for("index"))
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        if username and password:
            with sqlite3.connect("poetry.db") as conn:
                try:
                    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    return "⚠️ اسم المستخدم مستخدم من قبل. اختر اسمًا آخر."
        return "⚠️ يرجى تعبئة كل الحقول."
    
    @app.route("/login", methods=["GET", "POST"])
    def login():
     if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username and password:
            with sqlite3.connect("poetry.db") as conn:
                cursor = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
                user = cursor.fetchone()
                if user:
                    return redirect(url_for("index"))
                else:
                    return "❌ اسم المستخدم أو كلمة المرور غير صحيحة."
        return "⚠️ يرجى تعبئة كل الحقول."

    return render_template("login.html")
    return render_template("signup.html")
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
    @app.route("/signup", methods=["GET", "POST"])
    def signup():
      if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username and password:
            with sqlite3.connect("poetry.db") as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )
                ''')
                try:
                    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                    return redirect(url_for("index"))
                except sqlite3.IntegrityError:
                    return "⚠️ اسم المستخدم موجود مسبقًا. اختر اسمًا آخر."
      return render_template("signup.html")