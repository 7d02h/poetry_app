from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from flask import redirect, url_for
from flask_babel import Babel
import humanize
from datetime import datetime
from datetime import date
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['BABEL_DEFAULT_LOCALE'] = 'ar'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
babel = Babel(app)
@babel.localeselector
def get_locale():
    return session.get('lang', request.accept_languages.best_match(['ar', 'en']))
app.secret_key = "s3cr3t_2025_kjfh73hdf983hf"
app.config["UPLOAD_FOLDER"] = "static/profile_pics"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # الحد الأقصى 2 ميغا للصور
@app.template_filter('format_ar_date')
def format_ar_date(value):
    months_ar = [
        "يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو",
        "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"
    ]
    try:
        dt = datetime.strptime(value, "%d/%m/%Y %H:%M")
        return f"{dt.day} {months_ar[dt.month - 1]} {dt.year} - {dt.strftime('%I:%M %p').replace('AM', 'صباحًا').replace('PM', 'مساءً')}"
    except:
        return value
# إنشاء قاعدة البيانات
def init_db():
    with sqlite3.connect("poetry.db") as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS poems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                likes INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
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
        conn.execute('''
    CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poem_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        FOREIGN KEY(poem_id) REFERENCES poems(id),
        FOREIGN KEY(username) REFERENCES users(username)
    )
''')
        conn.execute('''
    CREATE TABLE IF NOT EXISTS saved_poems (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        poem_id INTEGER NOT NULL
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
@app.route('/')  
def home():  
    if 'username' not in session:  
        return redirect(url_for('login'))  
  
    conn = sqlite3.connect('poetry.db')  
    conn.row_factory = sqlite3.Row  
    c = conn.cursor()  
  
    current_user = session['username']  
  
    # جلب أفضل 3 أبيات بناءً على عدد الإعجابات  
    c.execute('''  
        SELECT poems.id, poems.text, poems.likes, users.username, users.profile_image, poems.created_at  
        FROM poems  
        JOIN users ON poems.username = users.username  
        ORDER BY poems.likes DESC  
        LIMIT 3  
    ''')  
    top_poems = c.fetchall()  
  
    for i in range(len(top_poems)):  
        created_at_raw = top_poems[i][5]  
        top_poems[i] = list(top_poems[i])  
  
        if created_at_raw:  
            if isinstance(created_at_raw, str):  
                created_at = datetime.strptime(created_at_raw, "%Y-%m-%d %H:%M:%S")  
            else:  
                created_at = created_at_raw  
  
            top_poems[i][5] = humanize.naturaltime(datetime.now() - created_at)  
        else:  
            top_poems[i][5] = "غير معروف"  
  
    # جلب جميع الأبيات بترتيب زمني  
    c.execute('''  
        SELECT poems.id, poems.text, poems.likes, users.username, users.profile_image, poems.created_at  
        FROM poems  
        JOIN users ON poems.username = users.username  
        ORDER BY poems.created_at DESC  
    ''')  
    all_poems = c.fetchall()  
  
    for i in range(len(all_poems)):  
        created_at = all_poems[i][5]  
        if isinstance(created_at, str):  
            created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")  
  
        all_poems[i] = list(all_poems[i])  
        all_poems[i][5] = humanize.naturaltime(datetime.now() - created_at)  
  
    conn.close()  
  
    return render_template('index.html',   
                           username=current_user,   
                           top_poems=top_poems,   
                           all_poems=all_poems)
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


@app.route('/set_lang/<lang_code>')
def set_language(lang_code):
    session['lang'] = lang_code
    return redirect(request.referrer or url_for('index'))

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
                return redirect(url_for("home"))
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
    conn = sqlite3.connect("poetry.db")
    conn.row_factory = sqlite3.Row

    is_following = False
    followers_count = 0

    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        return "User not found", 404

    if "username" in session and session["username"] != username:
        is_following = conn.execute(
            "SELECT 1 FROM followers WHERE username = ? AND followed_username = ?",
            (session["username"], username)
        ).fetchone() is not None

    followers_count = conn.execute(
        "SELECT COUNT(*) FROM followers WHERE followed_username = ?",
        (username,)
    ).fetchone()[0]

    user_poems = conn.execute("SELECT * FROM poems WHERE username = ?", (username,)).fetchall()
    total_likes = conn.execute(
        "SELECT COUNT(*) FROM likes WHERE poem_id IN (SELECT id FROM poems WHERE username = ?)",
        (username,)
    ).fetchone()[0]

    conn.close()

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
    try:
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

    except Exception as e:
        print("Error in /follow route:", e)
        traceback.print_exc()
        return "حدث خطأ في السيرفر.", 500
# قوائم إضافية إن أردت (صفحة الاستكشاف - صفحة الرئيسية)



@app.route('/explore')
def explore_page():
    # يمكنك إضافة منطق استكشاف هنا أو عرض قالب ثابت
    return render_template('explore.html')

# تعديل عدد اللايكات (للمسؤول فقط)
@app.route('/admin/setlike/<int:poem_id>/<int:like_count>')
def admin_set_likes(poem_id, like_count):
    if 'username' not in session or session['username'] != 'admin':
        return "ممنوع الدخول!", 403

    with sqlite3.connect("poetry.db") as conn:
        conn.execute("UPDATE poems SET likes = ? WHERE id = ?", (like_count, poem_id))
        conn.commit()

    return f"✅ تم تعديل عدد اللايكات للمنشور رقم {poem_id} إلى {like_count}"
@app.route('/explore')
def explore():
    conn = sqlite3.connect('poetry.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # ترتيب حسب عدد اللايكات + جلب صورة المستخدم مع كل بيت
    c.execute("""
        SELECT poems.id, poems.content, poems.likes,pomes.created_at, poems.author as username, users.profile_image
        FROM poems
        JOIN users ON poems.author = users.username
        ORDER BY poems.likes DESC
    """)
    poems = c.fetchall()

    # جلب المستخدمين المقترحين
    current_user = session.get("username")
    c.execute("SELECT username, first_name, last_name, profile_image FROM users WHERE username != ?", (current_user,))
    suggested_users = c.fetchall()

    conn.close()

    return render_template('explore.html', poems=poems, suggested_users=suggested_users)

@app.route('/delete/<int:poem_id>')
def delete(poem_id):
    import sqlite3
    conn = sqlite3.connect('poetry.db')
    c = conn.cursor()
    c.execute("DELETE FROM poems WHERE id = ?", (poem_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('explore_page')) 


@app.route('/submit', methods=['POST'])
def submit():
    # تأكد أنك تستقبل البيانات من النموذج
    text = request.form.get('text')
    username = session.get('username', 'guest')

    conn = sqlite3.connect("poetry.db")
    c = conn.cursor()
    c.execute("INSERT INTO poems (text, username) VALUES (?, ?)", (text, username))
    conn.commit()
    conn.close()

    return redirect(url_for('explore_page'))  # أو أي صفحة بدك ترجع لها

@app.route('/like/<int:poem_id>')
def like(poem_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    conn = sqlite3.connect('poetry.db')
    c = conn.cursor()

    # تحقق إذا المستخدم أعجب بهذا البيت مسبقاً
    c.execute('SELECT 1 FROM likes WHERE username = ? AND poem_id = ?', (username, poem_id))
    already_liked = c.fetchone()

    if not already_liked:
        # إضافة إعجاب
        c.execute('INSERT INTO likes (username, poem_id) VALUES (?, ?)', (username, poem_id))
        c.execute('UPDATE poems SET likes = likes + 1 WHERE id = ?', (poem_id,))
        conn.commit()

        # تحقق إذا محفوظ مسبقاً
        c.execute('SELECT 1 FROM saved_poems WHERE username = ? AND poem_id = ?', (username, poem_id))
        already_saved = c.fetchone()

        # إذا مش محفوظ، خزّنه تلقائيًا
        if not already_saved:
            c.execute('INSERT INTO saved_poems (username, poem_id) VALUES (?, ?)', (username, poem_id))
            conn.commit()

    conn.close()
    return redirect(url_for('home'))

import sqlite3

with sqlite3.connect("poetry.db") as conn:
  
  if __name__ == "__main__":
    init_db()
    app.run(debug=True)