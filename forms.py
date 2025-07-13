from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, Length, Optional
from flask_wtf.file import FileAllowed

class LoginForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired()])
    password = PasswordField('كلمة المرور', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('تسجيل الدخول')

class SignupForm(FlaskForm):
    username = StringField("اسم المستخدم", validators=[DataRequired(), Length(min=4)])
    password = PasswordField("كلمة المرور", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("تسجيل")

class EditProfileForm(FlaskForm):
    first_name = StringField("الاسم الأول", validators=[DataRequired()])
    last_name = StringField("اسم العائلة", validators=[DataRequired()])
    email = StringField("البريد الإلكتروني", validators=[DataRequired(), Email()])
    username = StringField("اسم المستخدم", validators=[DataRequired(), Length(min=4)])
    password = PasswordField("كلمة المرور الجديدة", validators=[Optional(), Length(min=8)])
    profile_image = FileField("صورة الملف الشخصي", validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'صيغة الصور يجب أن تكون jpg أو png أو jpeg')])
    submit = SubmitField("حفظ التعديلات")