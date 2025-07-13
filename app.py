from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import date
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "s3cr3t_2025_kjfh73hdf983hf"
app.config["UPLOAD_FOLDER"] = "static/profile_pics"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # الحد الأقصى 2 ميغا للصور

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
        conn.execute('''
            CREATE TABLE IF NOT EXISTS followers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                followed_username TEXT NOT NULL
            )
        ''')

# التحقق من صلاحية اسم المستخدم وكلمة المرور
def valid_username(username):
    return username and len(username) >= 4

def valid_password(password):
    return password and len(password) >= 8

def get_user_image(username):
    # ترجع المسار الصحيح للصورة، مثال:
    return f"/static/images/{username}.png"
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

    return render_template(
    "index.html",
    top_poems=top_poems,
    all_poems=all_poems,
    username=session["username"],
    get_user_image=get_user_image  # ✅ أضف هذا السطر
)
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
            conn.commit()
        else:
            flash("⚠️ لا يمكنك حذف بيت ليس لك.")
    return redirect(url_for("homepage"))

# تسجيل مستخدم جديد
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not valid_username(username):
            flash("⚠️ اسم المستخدم يجب أن يكون 4 أحرف على الأقل.")
            return render_template("signup.html")

        if not valid_password(password):
            flash("⚠️ كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
            return render_template("signup.html")
        hashed_password = generate_password_hash(password)

        with sqlite3.connect("poetry.db") as conn:
            try:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                flash("✅ تم إنشاء الحساب بنجاح! يمكنك تسجيل الدخول الآن.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("⚠️ اسم المستخدم موجود مسبقًا. اختر اسمًا آخر.")
                return render_template("signup.html")

    return render_template("signup.html")

# تسجيل الدخول
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with sqlite3.connect("poetry.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row and check_password_hash(row[0], password):
                session["username"] = username
                flash("✅ تم تسجيل الدخول بنجاح!")
                return redirect(url_for("homepage"))
            else:
                flash("❌ اسم المستخدم أو كلمة المرور غير صحيحة.")
                return render_template("login.html")

    return render_template("login.html")

# تسجيل الخروج
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("تم تسجيل الخروج.")
    return redirect("/login")

# عرض الملف الشخصي عام
@app.route("/profile/<username>")
def public_profile(username):
    with sqlite3.connect("poetry.db") as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            flash("لم يتم العثور على المستخدم")
            return redirect("/")  # أو أي صفحة أخرى تريدها

        total_likes = conn.execute("SELECT SUM(likes) FROM poems WHERE username = ?", (username,)).fetchone()[0] or 0
        user_poems = conn.execute("SELECT * FROM poems WHERE username = ?", (username,)).fetchall()
        followers_count = conn.execute("SELECT COUNT(*) FROM followers WHERE followed = ?", (username,)).fetchone()[0]

        is_following = False
        if "username" in session and session["username"] != username:
            is_following = conn.execute(
                "SELECT 1 FROM followers WHERE follower = ? AND followed = ?",
                (session["username"], username)
            ).fetchone() is not None

    return render_template(
        "profile.html",
        user=user,
        user_poems=user_poems,
        total_likes=total_likes,
        followers_count=followers_count,
        is_following=is_following,
        current_user=session.get("username")
    )
# تعديل الملف الشخصي
@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً.")
        return redirect("/login")

    with sqlite3.connect("poetry.db") as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()

    if request.method == "POST":
        new_username = request.form.get("username").strip()
        new_password = request.form.get("password").strip()
        first_name = request.form.get("first_name").strip()
        last_name = request.form.get("last_name").strip()
        email = request.form.get("email").strip()

        # تحقق من صحة البيانات
        if not valid_username(new_username):
            flash("⚠️ اسم المستخدم يجب أن يكون 4 أحرف على الأقل.")
            return redirect(url_for("edit_profile"))
        if new_password and not valid_password(new_password):
            flash("⚠️ كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
            return redirect(url_for("edit_profile"))

        profile_image_file = request.files.get("profile_image")
        profile_image_filename = None
        if profile_image_file and profile_image_file.filename != "":
            filename = secure_filename(profile_image_file.filename)
            profile_image_filename = filename
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            # تأكد أن المجلد موجود
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            profile_image_file.save(image_path)
        else:
            profile_image_filename = user[6]  # صورة حالية

        try:
            with sqlite3.connect("poetry.db") as conn:
                if new_password:
                    hashed_password = generate_password_hash(new_password)
                    conn.execute("""
                        UPDATE users
                        SET username = ?, password = ?, first_name = ?, last_name = ?, email = ?, profile_image = ?
                        WHERE username = ?
                    """, (new_username, hashed_password, first_name, last_name, email, profile_image_filename, session["username"]))
                else:
                    conn.execute("""
                        UPDATE users
                        SET username = ?, first_name = ?, last_name = ?, email = ?, profile_image = ?
                        WHERE username = ?
                    """, (new_username, first_name, last_name, email, profile_image_filename, session["username"]))

                conn.commit()
                session["username"] = new_username
                flash("✅ تم تحديث الملف الشخصي بنجاح!")
                return redirect(url_for("public_profile", username=new_username))

        except sqlite3.IntegrityError:
            flash("⚠️ اسم المستخدم موجود مسبقًا. اختر اسمًا آخر.")
            return redirect(url_for("edit_profile"))

    return render_template("edit_profile.html", user=user)

# بحث عن مستخدمين (بدون إظهار البريد)
@app.route('/search', methods=["GET", "POST"])
def search():
    results = []
    if request.method == "POST":
        keyword = request.form.get("keyword")
        if keyword:
            with sqlite3.connect("poetry.db") as conn:
                conn.row_factory = sqlite3.Row
                results = conn.execute("""
                    SELECT username, first_name, last_name, profile_image
                    FROM users
                    WHERE username LIKE ? OR first_name LIKE ? OR last_name LIKE ?
                """, (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")).fetchall()

    return render_template("search.html", results=results)

# صفحة الملف الشخصي الحالي
@app.route("/profile")
def my_profile():
    if "username" not in session:
        return redirect("/login")
    return redirect(url_for("public_profile", username=session["username"]))

# متابعة مستخدم
@app.route("/follow/<username>")
def follow(username):
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً.")
        return redirect("/login")

    if username == session["username"]:
        flash("لا يمكنك متابعة نفسك.")
        return redirect(url_for("public_profile", username=username))

    with sqlite3.connect("poetry.db") as conn:
        already_following = conn.execute(
            "SELECT 1 FROM followers WHERE username = ? AND followed_username = ?",
            (session["username"], username)
        ).fetchone()

        if not already_following:
            conn.execute(
                "INSERT INTO followers (username, followed_username) VALUES (?, ?)",
                (session["username"], username)
            )
            conn.commit()
            flash("تمت المتابعة بنجاح.")
        else:
            flash("أنت تتابع هذا المستخدم بالفعل.")

    return redirect(url_for("public_profile", username=username))

# قوائم إضافية إن أردت (صفحة الاستكشاف - صفحة الرئيسية)
@app.route('/home')
def home():
    return redirect(url_for("homepage"))

@app.route('/explore')
def explore():
    # يمكنك إضافة منطق استكشاف هنا أو عرض قالب ثابت
    return render_template('explore.html')# تعديل عدد اللايكات (للمسؤول فقط)
@app.route('/admin/like/<int:poem_id>/<int:like_count>')
def admin_set_likes(poem_id, like_count):
    if 'username' not in session or session['username'] != 'admin':
        return "ممنوع الدخول!", 403

    with sqlite3.connect("poetry.db") as conn:
        conn.execute("UPDATE poems SET likes = ? WHERE id = ?", (like_count, poem_id))
        conn.commit()

    return f"✅ تم تعديل عدد اللايكات للمنشور رقم {poem_id} إلى {like_count}"

if __name__ == "__main__":
    init_db()
    app.run(debug=True)