from flask import Flask, render_template, request, redirect, url_for, session,flash
import sqlite3
from flask import redirect, url_for
from flask_babel import Babel
import humanize
from flask import jsonify, request
from flask import session
from datetime import datetime
created_at = datetime.now()
from datetime import date
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['BABEL_DEFAULT_LOCALE'] = 'ar'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
@app.context_processor
def inject_blocked_users():
    if 'username' not in session:
        return {}
    
    conn = sqlite3.connect("poetry.db")
    conn.row_factory = sqlite3.Row
    blocked_users = conn.execute("""
        SELECT users.*
        FROM users
        JOIN blocks ON blocks.blocked = users.username
        WHERE blocks.blocker = ?
    """, (session['username'],)).fetchall()
    conn.close()

    return {'blocked_users_sidebar': blocked_users}
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


import sqlite3

def init_db():
    with sqlite3.connect("poetry.db") as conn:
        # جدول القصائد + عدد المشاهدات
        conn.execute('''
            CREATE TABLE IF NOT EXISTS poems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                likes INTEGER DEFAULT 0,
                views INTEGER DEFAULT 0,               
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
                username TEXT NOT NULL
            )
        ''')
        
        # جدول المستخدمين
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

        # جدول المتابعين
        conn.execute('''
            CREATE TABLE IF NOT EXISTS followers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                followed_username TEXT NOT NULL
            )
        ''')

        # جدول الإعجابات
        conn.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poem_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                FOREIGN KEY(poem_id) REFERENCES poems(id),
                FOREIGN KEY(username) REFERENCES users(username)
            )
        ''')

        # جدول القصائد المحفوظة
        conn.execute('''
            CREATE TABLE IF NOT EXISTS saved_poems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                poem_id INTEGER NOT NULL
            )
        ''')

        # جدول الإبلاغات على الأبيات
        conn.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poem_id INTEGER NOT NULL,
                reported_by TEXT NOT NULL,
                reason TEXT,
                report_date TEXT DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY(poem_id) REFERENCES poems(id),
                FOREIGN KEY(reported_by) REFERENCES users(username)
            )
        ''')

        # جدول الحظر بين المستخدمين
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                blocker TEXT NOT NULL,
                blocked TEXT NOT NULL,
                block_date TEXT DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY(blocker) REFERENCES users(username),
                FOREIGN KEY(blocked) REFERENCES users(username)
            )
        ''')
        conn.execute('''
             CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                content TEXT,
                file_path TEXT,
                message_type TEXT DEFAULT 'text',  -- 'text', 'image', 'video', 'file', 'link'
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT 0,
                FOREIGN KEY(sender) REFERENCES users(username),
                FOREIGN KEY(receiver) REFERENCES users(username)
            )
        ''')
        conn.execute('''
CREATE TABLE IF NOT EXISTS message_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter TEXT NOT NULL,
    reported_username TEXT NOT NULL,
    message_id INTEGER,
    reason TEXT,
    report_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(reporter) REFERENCES users(username),
    FOREIGN KEY(reported_username) REFERENCES users(username),
    FOREIGN KEY(message_id) REFERENCES messages(id)
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

def user_liked(poem_id):
    username = session.get('username')
    if not username:
        return False

    conn = sqlite3.connect('poetry.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM likes WHERE username = ? AND poem_id = ?", (username, poem_id))
    result = c.fetchone()
    conn.close()

    return result is not None


def is_blocked(current_user, target_user):
    with sqlite3.connect("poetry.db") as conn:
        c = conn.cursor()
        c.execute('''
            SELECT 1 FROM blocks
            WHERE blocker = ? AND blocked = ?
        ''', (current_user, target_user))
        return c.fetchone() is not None

def get_blocked_users(current_username):
    conn = sqlite3.connect('poetry.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT blocked FROM blocks WHERE blocker = ?", (current_username,))
    users = c.fetchall()
    conn.close()
    return [{"username": row["blocked"]} for row in users]

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    conn = sqlite3.connect('poetry.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # جلب أفضل 3 أبيات حسب عدد الإعجابات
    c.execute('''
        SELECT poems.id, poems.text, poems.likes, poems.views, users.username, users.profile_image, poems.created_at
        FROM poems
        JOIN users ON poems.username = users.username
        ORDER BY poems.likes DESC
        LIMIT 3
    ''')
    top_poems = c.fetchall()

    # فلترة الأبيات التي كتبها مستخدمون حظروك أو انت حظرتهم
    filtered_poems = []
    for poem in top_poems:
        poem_author = poem["username"]
        c.execute('''
            SELECT 1 FROM blocks 
            WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)
        ''', (current_user, poem_author, poem_author, current_user))
        is_blocked = c.fetchone()
        if not is_blocked:
            filtered_poems.append(poem)

    top_poems = filtered_poems

    # تنسيق الوقت للأبيات المفضلة
    for i in range(len(top_poems)):
        created_at_raw = top_poems[i][6]
        top_poems[i] = list(top_poems[i])
        if created_at_raw:
            if isinstance(created_at_raw, str):
                created_at = datetime.strptime(created_at_raw, "%Y-%m-%d %H:%M:%S")
            else:
                created_at = created_at_raw
            top_poems[i][6] = humanize.naturaltime(datetime.now() - created_at)
        else:
            top_poems[i][6] = "غير معروف"

    # جلب كل الأبيات مع استثناء المحظورين
    c.execute('''
        SELECT poems.id, poems.text, poems.likes, poems.views,
               users.username, users.profile_image, poems.created_at
        FROM poems
        JOIN users ON poems.username = users.username
        WHERE poems.username NOT IN (
            SELECT blocked FROM blocks WHERE blocker = ?
        )
        ORDER BY poems.created_at DESC
    ''', (current_user,))
    all_poems = c.fetchall()

    # تنسيق الوقت للأبيات العامة
    for i in range(len(all_poems)):
        created_at = all_poems[i][6]
        if isinstance(created_at, str):
            created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
        all_poems[i] = list(all_poems[i])
        all_poems[i][6] = humanize.naturaltime(datetime.now() - created_at)

    # تحديث عدد المشاهدات
    for poem in all_poems:
        poem_id = poem[0]
        c.execute("UPDATE poems SET views = views + 1 WHERE id = ?", (poem_id,))

    # جلب الأبيات التي أعجب بها المستخدم
    c.execute("SELECT poem_id FROM likes WHERE username = ?", (current_user,))
    user_liked_rows = c.fetchall()
    user_liked = [row[0] for row in user_liked_rows]

    # جلب المحظورين للقائمة الجانبية
    c.execute("SELECT blocked FROM blocks WHERE blocker = ?", (current_user,))
    blocked_users_sidebar = [{"username": row["blocked"]} for row in c.fetchall()]

    conn.commit()
    conn.close()

    return render_template('index.html',
                           username=current_user,
                           top_poems=top_poems,
                           all_poems=all_poems,
                           user_liked=user_liked,
                           blocked_users_sidebar=blocked_users_sidebar)
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

@app.route("/profile/<username>")
def public_profile(username):
    conn = sqlite3.connect("poetry.db")
    conn.row_factory = sqlite3.Row

    is_following = False
    followers_count = 0

    # الحصول على بيانات المستخدم
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        return "User not found", 404

    # المستخدم الحالي
    current_user = session.get("username")

    # التحقق إذا كنت تتابعه
    if current_user and current_user != username:
        is_following = conn.execute(
            "SELECT 1 FROM followers WHERE username = ? AND followed_username = ?",
            (current_user, username)
        ).fetchone() is not None

    # عدد المتابعين
    followers_count = conn.execute(
        "SELECT COUNT(*) FROM followers WHERE followed_username = ?",
        (username,)
    ).fetchone()[0]

    # قصائد المستخدم
    user_poems = conn.execute(
        "SELECT * FROM poems WHERE username = ?", (username,)
    ).fetchall()

    # عدد الإعجابات على قصائده
    total_likes = conn.execute(
        "SELECT COUNT(*) FROM likes WHERE poem_id IN (SELECT id FROM poems WHERE username = ?)",
        (username,)
    ).fetchone()[0]

    # هل محظور؟
    blocked = False
    if current_user:
        result = conn.execute(
            "SELECT 1 FROM blocks WHERE blocker = ? AND blocked = ?",
            (current_user, username)
        ).fetchone()
        blocked = result is not None

    conn.close()

    # إرسال البيانات إلى القالب
    return render_template(
        "profile.html",
        user=user,
        user_poems=user_poems,
        total_likes=total_likes,
        followers_count=followers_count,
        is_following=is_following,
        current_user=current_user,
        blocked=blocked
    )
@app.route("/profile")
def my_profile():
    if "username" not in session:
        return redirect("/login")
    return redirect(url_for("public_profile", username=session["username"]))

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

@app.route('/search', methods=["GET", "POST"])
def search():
    results = []
    current_user = session.get("username")

    if request.method == "POST":
        keyword = request.form.get("keyword")
        if keyword and current_user:
            with sqlite3.connect("poetry.db") as conn:
                conn.row_factory = sqlite3.Row
                results = conn.execute("""
                    SELECT username, first_name, last_name, profile_image
                    FROM users
                    WHERE (username LIKE ? OR first_name LIKE ? OR last_name LIKE ?)
                    AND username NOT IN (
                        SELECT blocked FROM blocks WHERE blocker = ?
                    )
                    AND username != ?
                """, (
                    f"%{keyword}%", f"%{keyword}%", f"%{keyword}%",
                    current_user, current_user
                )).fetchall()

    return render_template("search.html", results=results)
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
            c = conn.cursor()

            # تحقق من وجود حظر بين المستخدمين
            c.execute('''
                SELECT 1 FROM blocks
                WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)
            ''', (session["username"], username, username, session["username"]))
            is_blocked = c.fetchone()

            if is_blocked:
                flash("لا يمكنك متابعة هذا المستخدم بسبب الحظر.")
                return redirect(url_for("public_profile", username=username))

            already_following = c.execute(
                "SELECT 1 FROM followers WHERE username = ? AND followed_username = ?",
                (session["username"], username)
            ).fetchone()
            
            if not already_following:
                c.execute(
                    "INSERT INTO followers (username, followed_username) VALUES (?, ?)",
                    (session["username"], username)
                )
                conn.commit()
                flash()
            else:
                flash()
        return redirect(url_for("public_profile", username=username))

    except Exception as e:
        print("Error in /follow route:", e)
        traceback.print_exc()
        return "حدث خطأ في السيرفر.", 500
    

# قوائم إضافية إن أردت (صفحة الاستكشاف - صفحة الرئيسية)




@app.route('/explore')
def explore_page():
    current_user = session.get("username")

    conn = sqlite3.connect("poetry.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # جلب الأبيات الأكثر إعجابًا (من غير المحظورين)
    c.execute('''
        SELECT poems.id, poems.text, poems.likes, poems.created_at,
               users.username, users.profile_image
        FROM poems
        JOIN users ON poems.username = users.username
        WHERE poems.username NOT IN (
            SELECT blocked FROM blocks WHERE blocker = ?
        )
        ORDER BY poems.likes DESC
    ''', (current_user,))
    top_poems = c.fetchall()

    # جلب مستخدمين مقترحين (من غير المحظورين)
    c.execute('''
        SELECT username, first_name, last_name, profile_image
        FROM users
        WHERE username != ?
        AND username NOT IN (
            SELECT blocked FROM blocks WHERE blocker = ?
        )
        ORDER BY RANDOM()
        LIMIT 10
    ''', (current_user, current_user))
    suggested_users = c.fetchall()

    conn.close()

    return render_template('explore.html', top_poems=top_poems, suggested_users=suggested_users)
# تعديل عدد اللايكات (للمسؤول فقط)
@app.route('/admin/setlike/<int:poem_id>/<int:like_count>')
def admin_set_likes(poem_id, like_count):
    if 'username' not in session or session['username'] != 'admin':
        return "ممنوع الدخول!", 403

    with sqlite3.connect("poetry.db") as conn:
        conn.execute("UPDATE poems SET likes = ? WHERE id = ?", (like_count, poem_id))
        conn.commit()

    return f"✅ تم تعديل عدد اللايكات للمنشور رقم {poem_id} إلى {like_count}"




@app.route('/delete/<int:poem_id>')
def delete(poem_id):
    import sqlite3
    conn = sqlite3.connect('poetry.db')
    c = conn.cursor()
    c.execute("DELETE FROM poems WHERE id = ?", (poem_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('home'))



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

    return redirect(url_for('home'))  # أو أي صفحة بدك ترجع لها

from flask import jsonify, request, session, redirect, url_for
import sqlite3

@app.route('/like/<int:poem_id>')
def like(poem_id):
    if 'username' not in session:
        # إذا مش مسجّل دخول نرجع رابط تسجيل الدخول
        return jsonify({'success': False, 'redirect': url_for('login')})

    username = session['username']

    conn = sqlite3.connect('poetry.db')
    c = conn.cursor()

    # تحقق إذا المستخدم أعجب مسبقًا
    c.execute('SELECT 1 FROM likes WHERE username = ? AND poem_id = ?', (username, poem_id))
    already_liked = c.fetchone()

    if already_liked:
        # إذا معجب، نشيله
        c.execute('DELETE FROM likes WHERE username = ? AND poem_id = ?', (username, poem_id))
        c.execute('UPDATE poems SET likes = likes - 1 WHERE id = ?', (poem_id,))
    else:
        # إذا مش معجب، نضيفه
        c.execute('INSERT INTO likes (username, poem_id) VALUES (?, ?)', (username, poem_id))
        c.execute('UPDATE poems SET likes = likes + 1 WHERE id = ?', (poem_id,))

    # نجيب عدد الإعجابات الجديد
    c.execute('SELECT likes FROM poems WHERE id = ?', (poem_id,))
    likes = c.fetchone()[0]

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'likes': likes})
    

@app.route('/report/<int:poem_id>')
def report_poem(poem_id):
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    conn = sqlite3.connect("poetry.db")
    c = conn.cursor()

    # تأكد ما بلغ قبل
    c.execute("SELECT * FROM reports WHERE poem_id = ? AND reported_by = ?", (poem_id, username))
    if c.fetchone():
        conn.close()
        return "تم الإبلاغ مسبقًا عن هذا البيت."

    c.execute("INSERT INTO reports (poem_id, reported_by) VALUES (?, ?)", (poem_id, username))
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for('explore_page'))


@app.route('/block/<username>')
def block_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    if current_user == username:
        return "لا يمكنك حظر نفسك.", 400

    conn = sqlite3.connect('poetry.db')
    conn.execute("INSERT OR IGNORE INTO blocks (blocker, blocked) VALUES (?, ?)", (current_user, username))
    conn.commit()
    conn.close()

    return redirect(request.referrer or url_for('home'))


@app.route('/unblock/<username>')
def unblock_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    conn = sqlite3.connect('poetry.db')
    conn.execute("DELETE FROM blocks WHERE blocker = ? AND blocked = ?", (current_user, username))
    conn.commit()
    conn.close()

    return redirect(request.referrer or url_for('home'))


@app.route("/report_message", methods=["POST"])
def report_message():
    if 'username' not in session:
        return redirect(url_for("login"))

    reporter = session['username']
    reported_username = request.form.get("reported_username")
    message_id = request.form.get("message_id")  # ممكن يكون فارغ
    reason = request.form.get("reason", "غير محدد")

    conn = sqlite3.connect("poetry.db")
    conn.execute(
        "INSERT INTO message_reports (reporter, reported_username, message_id, reason) VALUES (?, ?, ?, ?)",
        (reporter, reported_username, message_id, reason)
    )
    conn.commit()
    conn.close()

    flash("تم إرسال البلاغ بنجاح.", "success")
    return redirect(request.referrer or url_for("inbox"))
    
    
   
@app.route("/messages/<username>")
def view_messages(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    conn = sqlite3.connect('poetry.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # تحقق من وجود حظر بين المستخدمين
    c.execute('''
        SELECT 1 FROM blocks
        WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)
    ''', (current_user, username, username, current_user))
    is_blocked = c.fetchone()

    display_name = "User is unavailable" if is_blocked else username

    # جلب الرسائل
    c.execute('''
        SELECT sender, receiver, content, file_path, timestamp
        FROM messages
        WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
        ORDER BY timestamp
    ''', (current_user, username, username, current_user))
    rows = c.fetchall()
    conn.close()

    messages = [
        {
            'sender': row['sender'],
            'receiver': row['receiver'],
            'content': row['content'],
            'file_path': row['file_path'],
            'timestamp': row['timestamp']
        }
        for row in rows
    ]

    return render_template("messages.html",
                       messages=messages,
                       other_user=display_name,
                       real_username=username,
                       is_blocked=is_blocked,
                       current_user=current_user)
# 📤 إرسال رسالة جديدة
@app.route("/send_message/<username>", methods=["POST"])
def send_message(username):
    if 'username' not in session:
        return redirect(url_for("login"))

    sender = session['username']
    receiver = username
    content = request.form.get("content")
    file_path = None

    # إذا كان فيه ملف مرفق
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            upload_folder = os.path.join('static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            file.save(os.path.join(upload_folder, filename))
            file_path = f"uploads/{filename}"  # المسار داخل static

    conn = sqlite3.connect("poetry.db")
    conn.execute('''
        INSERT INTO messages (sender, receiver, content, file_path)
        VALUES (?, ?, ?, ?)
    ''', (sender, receiver, content, file_path))
    conn.commit()
    conn.close()

    return redirect(url_for("view_messages", username=receiver))


# 🚨 كود البلاغ عن محادثة
@app.route("/report_conversation/<username>")
def report_conversation(username):
    if 'username' not in session:
        return redirect(url_for("login"))
    
    # ممكن تسجل البلاغ في جدول خاص أو تطبع رسالة فقط
    return f"تم الإبلاغ عن المحادثة مع {username} بنجاح!"


@app.route('/inbox')
def inbox():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    conn = sqlite3.connect('poetry.db')
    c = conn.cursor()
    c.execute('''
        SELECT DISTINCT 
            CASE 
                WHEN sender = ? THEN receiver 
                ELSE sender 
            END AS other_user
        FROM messages
        WHERE sender = ? OR receiver = ?
    ''', (current_user, current_user, current_user))
    rows = c.fetchall()
    conn.close()

    users = [row[0] for row in rows]
    return render_template('inbox.html', users=users)


@app.route("/unfollow/<username>")
def unfollow(username):
    try:
        if "username" not in session:
            flash("يجب تسجيل الدخول أولاً.")
            return redirect("/login")

        with sqlite3.connect("poetry.db") as conn:
            conn.execute(
                "DELETE FROM followers WHERE username = ? AND followed_username = ?",
                (session["username"], username)
            )
            conn.commit()
            flash("تم إلغاء المتابعة.")
        return redirect(url_for("public_profile", username=username))

    except Exception as e:
        print("Error in /unfollow route:", e)
        traceback.print_exc()
        return "حدث خطأ في السيرفر.", 500

if __name__ == "__main__":
    init_db()
    app.run(debug=True)