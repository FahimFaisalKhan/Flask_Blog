import email
from linecache import lazycache

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os
from dotenv import load_dotenv
from flask_migrate import Migrate

from functools import wraps
app = Flask(__name__)

# NOTE: initializing loginManeger() class to
login_manager = LoginManager()
login_manager.init_app(app)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# NOTE: This class to user different gravatars ,, as comment image, see dtail in post.html
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL').replace("://", "ql://", 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# CONFIGURE TABLES
# migrate = Migrate(app, db)

# using UserMixin to use login_manager properties/attributes/methods from this table


class Users(UserMixin, db.Model):
    __tablename__ = "user_final"
    # __table_args__ = ({"schema": "flask_blog"})
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.Text(), nullable=False)
    child = relationship('BlogPost', back_populates="author", lazy=True)
    comment = relationship('Comment', back_populates="parent", lazy=True)


class BlogPost(db.Model):
    __tablename__ = "blog_posts_final"
    # __table_args__ = ({'schema': 'flask_blog'})
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(
        db.Integer, db.ForeignKey("user_final.id"))
    author = relationship('Users', back_populates='child', lazy=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(1000), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.Text, nullable=False)
    comment = relationship('Comment', back_populates="parent_2", lazy=True)


class Comment(db.Model):
    __tablename__ = "comments"
    # __table_args__ = ({'schema': 'flask_blog'})
    id = db.Column(db.Integer, primary_key=True)
    commenter_id = db.Column(
        db.Integer, db.ForeignKey("user_final.id"))
    parent = relationship('Users', back_populates='comment', lazy=True)
    comment_of_post = db.Column(
        db.Integer, db.ForeignKey("blog_posts_final.id"))
    parent_2 = relationship('BlogPost', back_populates='comment', lazy=True)
    text = db.Column(db.Text, nullable=False)


# NOTE: making the login_manager to load the current user .. so that we can  later user TODO:current_user method ..


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# IMPORTANT:IMPORTANT:IMPORTANT: making a decorator so that later we can use it to those routes which can be accessed only by admin
# docs  https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/#login-required-decorator
# https://flask.palletsprojects.com/en/1.1.x/patterns/errorpages/


def adimn_only(func):
    @wraps(func)
    def wrapper_func(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403, description="ForBidden")

    return wrapper_func

# NOTE:TODO:processing the routes so that any user can not go the blog page by clicking back button in browser after logging out


@app.after_request
def after_request(response):
    response.headers.add(
        'Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0')
    return response


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    admin_name = ''
    if Users.query.get(1):

        admin_name = Users.query.get(1).name
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user=current_user, admin_name=admin_name)


@app.route('/register', methods=['GET', 'POST'])
def register():

    reg_form = RegisterForm()
    if reg_form.validate_on_submit():
        user_exist = Users.query.filter_by(email=reg_form.email.data).first()
        if not user_exist:
            hashed_salted_pass = generate_password_hash(
                password=reg_form.password.data, method="pbkdf2:sha256", salt_length=16)
            new_user = Users(email=reg_form.email.data,
                             name=reg_form.name.data, password=hashed_salted_pass)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login', email=reg_form.email.data, pas=reg_form.password.data))

        else:
            flash('Email Already Exists , try to Login Instead')
            return redirect(url_for('login'))
    return render_template("register.html", form=reg_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.args.get('email') and request.args.get('pas'):
        form = LoginForm(email=request.args.get('email'),
                         password=request.args.get('pas'))
    if form.validate_on_submit():
        user_exist = Users.query.filter_by(email=form.email.data).first()
        if user_exist:
            correct_pass = check_password_hash(
                pwhash=user_exist.password, password=form.password.data)
            if correct_pass:
                login_user(user_exist)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect Password")

                return redirect(url_for('login'))
        else:

            flash('Incorrect Email')
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(
        comment_of_post=requested_post.id).all()

    form = CommentForm()
    if form.validate_on_submit():
        # IMPORTANT:IMPORTANT: HERE comment_of_post is the foreign key of Comment table, which connect to primary key id of BlogPost table
        new_comment = Comment(
            commenter_id=current_user.id, text=form.comment_text.data, comment_of_post=requested_post.id)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))

    return render_template("post.html", post=requested_post, user=current_user, form=form, comments=comments, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@adimn_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # IMPORTANT:IMPORTANT: HERE author_id is the foreign-key of BlogPost table which is connected  to primary_key id of Users table
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@adimn_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    # NOTE: sending data preattached with the form
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data

        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, user=current_user)


@app.route("/delete/<int:post_id>")
@login_required
@adimn_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
