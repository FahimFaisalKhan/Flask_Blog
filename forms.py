from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField
from wtforms.widgets import PasswordInput

# WTForm


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = EmailField('Enter Your Email', validators=[DataRequired()])
    name = StringField('Enter Your Name', validators=[DataRequired()])
    password = PasswordField('Enter Your Password',
                             validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = EmailField('Enter Your Email', validators=[DataRequired()])
    password = StringField('Password', widget=PasswordInput(
        hide_value=False), validators=[DataRequired()])
    submit = SubmitField("Login")


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
