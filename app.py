from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import date
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "s3cr3t_2025_kjfh73hdf983hf"
app.config["UPLOAD_FOLDER"] = "static/profile_pics"

# إنشاء قاعدة البيانات
def init_db():
    with sqlite3.connect("poetry.db") as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS poems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                likes INTEGER DEFAULT 0,
                created DATE DEFAULT CURRENT_DATE,
                username TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                profile_image TEXT DEFAULT 'default.jpg'
            )
        ''')

# الصفحة الرئيسية
@app.route("/")
def homepage():
    if "username" not in session:
        return redirect("/login")

    with sqlite3.connect("poetry.db") as conn:
        today = date.today()
        top_poems = conn.execute('''
            SELECT * FROM poems
            WHERE created = ?
            ORDER BY likes DESC
            LIMIT 3
        ''', (today,)).fetchall()

        all_poems = conn.execute("SELECT * FROM poems ORDER BY id DESC").fetchall()

    return render_template("index.html", top_poems=top_poems, all_poems=all_poems, username=session["username"])

# إرسال بيت شعري
@app.route("/submit", methods=["POST"])
def submit():
    if "username" not in session:
        return redirect("/login")

    poem = request.form.get("poem")
    if poem:
        with sqlite3.connect("poetry.db") as conn:
            conn.execute("INSERT INTO poems (text, created, username) VALUES (?, ?, ?)", 
                         (poem, date.today(), session["username"]))
    return redirect(url_for("homepage"))

# الإعجاب ببيت
@app.route("/like/<int:poem_id>")
def like(poem_id):
    if "username" not in session:
        return redirect("/login")

    with sqlite3.connect("poetry.db") as conn:
        conn.execute("UPDATE poems SET likes = likes + 1 WHERE id = ?", (poem_id,))
    return redirect(url_for("homepage"))

# حذف بيت
@app.route("/delete/<int:poem_id>")
def delete(poem_id):
    if "username" not in session:
        return redirect("/login")

    with sqlite3.connect("poetry.db") as conn:
        poem = conn.execute("SELECT * FROM poems WHERE id = ?", (poem_id,)).fetchone()
        if poem and poem[4] == session["username"]:
            conn.execute("DELETE FROM poems WHERE id = ?", (poem_id,))
    return redirect(url_for("homepage"))

# تسجيل مستخدم جديد
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

# تسجيل الدخول
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        with sqlite3.connect("poetry.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
            user = cursor.fetchone()
            if user:
                session["username"] = username
                return redirect(url_for("homepage"))
            else:
                return "❌ اسم المستخدم أو كلمة المرور غير صحيحة."
    return render_template("login.html")

# تسجيل الخروج
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/login")

# عرض الملف الشخصي
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")

    with sqlite3.connect("poetry.db") as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()
        if user is None:
            flash("⚠️ لم يتم العثور على المستخدم.")
            return redirect("/login")

        total_likes = conn.execute("SELECT SUM(likes) FROM poems WHERE username = ?", (session["username"],)).fetchone()[0] or 0
        user_poems = conn.execute("SELECT * FROM poems WHERE username = ?", (session["username"],)).fetchall()

    return render_template("profile.html", user=user, total_likes=total_likes, user_poems=user_poems)

# تعديل الملف الشخصي
from werkzeug.utils import secure_filename  # تأكد أنك أضفت هذا في الأعلى
import os

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        new_username = request.form.get("username")
        new_password = request.form.get("password")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")

        profile_image_file = request.files.get("profile_image")
        profile_image_filename = None

        if profile_image_file and profile_image_file.filename != "":
            filename = secure_filename(profile_image_file.filename)
            profile_image_filename = filename
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            # تأكد أن المجلد موجود
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            profile_image_file.save(image_path)

        with sqlite3.connect("poetry.db") as conn:
            try:
                if profile_image_filename:
                    conn.execute("""
                        UPDATE users 
                        SET username = ?, password = ?, first_name = ?, last_name = ?, email = ?, profile_image = ?
                        WHERE username = ?
                    """, (new_username, new_password, first_name, last_name, email, profile_image_filename, session["username"]))
                else:
                    conn.execute("""
                        UPDATE users 
                        SET username = ?, password = ?, first_name = ?, last_name = ?, email = ?
                        WHERE username = ?
                    """, (new_username, new_password, first_name, last_name, email, session["username"]))

                conn.commit()

                if new_username:
                    session["username"] = new_username

                flash("✅ تم تحديث الملف الشخصي بنجاح!")
                return redirect(url_for("profile"))

            except sqlite3.IntegrityError:
                flash("⚠️ اسم المستخدم موجود مسبقًا. اختر اسمًا آخر.")
                return redirect(url_for("edit_profile"))

    # جلب بيانات المستخدم الحالية
    with sqlite3.connect("poetry.db") as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()

    return render_template("edit_profile.html", user=user)

# تشغيل السيرفر
if __name__ == "__main__":
    init_db()
    app.run(debug=True)