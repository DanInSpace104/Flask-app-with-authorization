from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    name = StringField('Имя', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Оставаться в системе')
    submit = SubmitField('Войти')
    next_page = StringField('Next_url')
