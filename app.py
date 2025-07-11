from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from datetime import date

app = Flask(__name__)

# إنشاء قاعدة البيانات إن لم تكن موجودة
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

if __name__ == "__main__":
    init_db()
    app.run(debug=True)