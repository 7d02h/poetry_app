from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from datetime import date

app = Flask(__name__)

# إنشاء قاعدة البيانات إذا لم تكن موجودة
def init_db():
    with sqlite3.connect("poetry.db") as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS poems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                likes INTEGER DEFAULT 0,
                created DATE DEFAULT CURRENT_DATE
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

@app.route("/")
def index():
    with sqlite3.connect("poetry.db") as conn:
        today = date.today()
        top_poems = conn.execute('''
            SELECT * FROM poems
            WHERE created = ?
            ORDER BY likes DESC
            LIMIT 3
        ''', (today,)).fetchall()

        all_poems = conn.execute("SELECT * FROM poems ORDER BY id DESC").fetchall()

    return render_template("index.html", top_poems=top_poems, all_poems=all_poems)

@app.route("/submit", methods=["POST"])
def submit():
    poem = request.form.get("poem")
    if poem:
        with sqlite3.connect("poetry.db") as conn:
            conn.execute("INSERT INTO poems (text, created) VALUES (?, ?)", (poem, date.today()))
    return redirect(url_for("index"))

@app.route("/like/<int:poem_id>")
def like(poem_id):
    with sqlite3.connect("poetry.db") as conn:
        conn.execute("UPDATE poems SET likes = likes + 1 WHERE id = ?", (poem_id,))
    return redirect(url_for("index"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username and password:
            with sqlite3.connect("poetry.db") as conn:
                try:
                    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    return "⚠️ اسم المستخدم موجود مسبقًا. اختر اسمًا آخر."
        return "⚠️ يرجى تعبئة كل الحقول."
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        with sqlite3.connect("poetry.db") as conn:
            cursor = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
            user = cursor.fetchone()
            if user:
                return redirect(url_for("index"))
            else:
                return "❌ اسم المستخدم أو كلمة المرور غير صحيحة."
    return render_template("login.html")

if __name__ == "__main__":
    init_db()
    app.run(debug=True)