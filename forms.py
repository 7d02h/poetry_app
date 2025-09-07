from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, Length, Optional, EqualTo
from flask_wtf.file import FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField
from flask_wtf import FlaskForm
from wtforms import SubmitField

class TermsForm(FlaskForm):
    submit = SubmitField("أوافق")


# 🟢 فورم تسجيل الدخول
class LoginForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired(), Length(min=3, max=25)])
    password = PasswordField('كلمة المرور', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('تسجيل الدخول')


# 🟢 فورم إنشاء حساب

class SignupForm(FlaskForm):
    first_name = StringField("الاسم الأول", validators=[DataRequired(), Length(min=2, max=30)])
    last_name = StringField("اسم العائلة", validators=[DataRequired(), Length(min=2, max=30)])
    email = StringField("البريد الإلكتروني", validators=[DataRequired(), Email()])
    username = StringField("اسم المستخدم", validators=[DataRequired(), Length(min=4, max=25)])
    
    birth_day = SelectField("اليوم", choices=[(str(d), str(d)) for d in range(1, 32)], validators=[DataRequired()])
    birth_month = SelectField("الشهر", choices=[
        ("1", "يناير"), ("2", "فبراير"), ("3", "مارس"), ("4", "أبريل"),
        ("5", "مايو"), ("6", "يونيو"), ("7", "يوليو"), ("8", "أغسطس"),
        ("9", "سبتمبر"), ("10", "أكتوبر"), ("11", "نوفمبر"), ("12", "ديسمبر")
    ], validators=[DataRequired()])
    birth_year = SelectField("السنة", choices=[(str(y), str(y)) for y in range(1950, 2024)], validators=[DataRequired()])

    password = PasswordField("كلمة المرور", validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField("تأكيد كلمة المرور", validators=[
        DataRequired(), EqualTo('password', message="كلمتا المرور غير متطابقتين")
    ])

    submit = SubmitField("✨ إنشاء الحساب")


# 🟢 فورم تعديل الملف الشخصي
class EditProfileForm(FlaskForm):
    first_name = StringField("الاسم الأول", validators=[DataRequired()])
    last_name = StringField("اسم العائلة", validators=[DataRequired()])
    email = StringField("البريد الإلكتروني", validators=[DataRequired(), Email()])
    username = StringField("اسم المستخدم", validators=[DataRequired(), Length(min=4)])
    new_password = PasswordField("كلمة المرور الجديدة", validators=[Optional(), Length(min=8)])
    profile_image = FileField("صورة الملف الشخصي", validators=[
        FileAllowed(['jpg', 'png', 'jpeg'], 'يُسمح فقط بصور jpg أو png أو jpeg')
    ])
    submit = SubmitField("حفظ التعديلات")


   # 🟢 فورم نسيت كلمة المرور
class ForgotPasswordForm(FlaskForm):
    email = StringField("البريد الإلكتروني", validators=[DataRequired(), Email()])
    submit = SubmitField("📩 إرسال رابط إعادة التعيين") 