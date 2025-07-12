from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class SignupForm(FlaskForm):
    username = StringField("اسم المستخدم", validators=[DataRequired()])
    password = PasswordField("كلمة المرور", validators=[DataRequired()])
    submit = SubmitField("تسجيل")

class EditProfileForm(FlaskForm):
    first_name = StringField("الاسم الأول", validators=[DataRequired()])
    last_name = StringField("اسم العائلة", validators=[DataRequired()])
    email = StringField("البريد الإلكتروني", validators=[DataRequired(), Email()])
    submit = SubmitField("حفظ التعديلات")