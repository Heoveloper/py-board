from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

class SignUpForm(FlaskForm):
    userid = StringField("아이디",
                         validators=[DataRequired(), Length(min=4, max=16)])
    pw = PasswordField("비밀번호",
                       validators=[DataRequired(), Length(min=4, max=16)])
    pwc = PasswordField("비밀번호 확인",
                        validators=[DataRequired(), EqualTo("password")])
    nickname = StringField("닉네임",
                           validators=[DataRequired(), Length(min=4, max=16)])
    submit = SubmitField("가입")