from __future__ import annotations
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, get_flashed_messages, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, ForeignKey
import requests
import datetime as dt
import smtplib
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateTimeField, DateField, EmailField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Email, Length
from flask_ckeditor import CKEditor, CKEditorField
from dateutil import parser as date_parser
import dateutil
import hashlib
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from sqlalchemy.exc import NoResultFound
from functools import wraps
from typing import List
import os

app = Flask(__name__)
# WTFORMS Config
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
ckeditor = CKEditor(app)
print(app.secret_key)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQL_ALCHEMY_DATABASE_URI')
# app.config['SQLALCHEMY_BINDS'] = {"posts" : 'sqlite:///posts.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False




# FORMS
class AddBlogForm(FlaskForm):
    title    = StringField("Blog Title", validators=[DataRequired()])
    subtitle = StringField("Blog Subtitle", validators=[DataRequired()])
    image    = StringField("Image URL", validators=[DataRequired()])
    body     = CKEditorField("Body", validators=[DataRequired()])
    submit   = SubmitField("Submit Post")

class SignUpForm(FlaskForm):
    name     = StringField("Name", validators=[DataRequired(), Length(min=3, max=25, message="Name should be between %(min)d and %(max)d characters long")])
    email    = EmailField("Email", validators=[DataRequired(), Email(message='Please Enter a Valid Email Address')])
    password = PasswordField("Password", validators=[DataRequired(), EqualTo('confirm', message='Passwords must match!')])
    confirm  = PasswordField("Repeat Password", validators=[DataRequired()])
    submit   = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email    = EmailField("Email", validators=[DataRequired(), Email(message='Please Enter a Valid Email Address')])
    password = PasswordField("Password", validators=[DataRequired()])
    submit2  = SubmitField('Log In')

class CommentForm(FlaskForm):
    comment  = CKEditorField("Comment", validators=[DataRequired()])
    submit   = SubmitField("Submit Comment")


# Database Tables
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)
migrate = Migrate(app, db)


class User(db.Model, UserMixin):
    __tablename__ = "users"
    # __bind_key__  = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    admin: Mapped[bool] = mapped_column(Boolean, nullable=True) 

    def get_id(self):
        return self.id
    
    def is_admin(self):
        return self.id == 1
    
class Post(db.Model):   
    __tablename__ = "blog_posts"
    # __bind_key__  = 'posts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
        
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    users = relationship('User', backref='users')
    # Create reference to the User object. The "posts" refers to the posts property in the User class.
    
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(String, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    posts = relationship('Post', backref='blog_posts')
    users = relationship('User', backref='comments')
    comment: Mapped[str] = mapped_column(String, nullable=False)
    date: Mapped[str] = mapped_column(String, nullable=False)

with app.app_context():
    db.create_all()


# Flask login 
login_manager  = LoginManager()
# initialize the login with app
login_manager.init_app(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, user_id)
    return user

def encrypt_password(password):
    # Convert the password string to bytes
    password_bytes = password.encode('utf-8')
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    # Update the hash object with the password bytes
    sha256_hash.update(password_bytes)
    # Get the hexadecimal representation of the digest (hashed value)
    encrypted_password = sha256_hash.hexdigest()
    return encrypted_password

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter(User.email == form.email.data).one()
            if user:
                if encrypt_password(form.password.data) == user.password:
                    login_user(user)
                    return redirect(url_for('home'))
                else:
                    flash("Wrong Password - please try again", "password_error")
        except NoResultFound:
            flash("Email does not exist - please try a different email", "email_error")
    
    
    return render_template('login.html', form=form)


@app.route('/logout', methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect(url_for('login'))


def admin_only(func):
    @wraps(func)
    def decorated_func(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return func(*args, **kwargs)
    return decorated_func
            

@app.route('/')
@app.route('/index')
def home():
    all_blogs = Post.query.all()
    for blog in all_blogs:
        parsed_date = date_parser.parse(blog.date)
        formatted_date = parsed_date.strftime("%B %d, %Y")
        blog.date = formatted_date
    
    user_id=None
    if current_user.is_authenticated:
        user_id = User.get_id(current_user)

    return render_template('index.html', blogs=all_blogs, user_id=user_id)

@app.route('/header')
def header():
    return render_template('header.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/formSubmission', methods=['POST', 'GET'])
def get_contact():
    if request.method == 'POST':
        name = request.form['name']
        user_email = request.form['email']
        phone = request.form['phone']
        message = request.form['message']
        EMAIL    = os.environ.get("SMTP_EMAIL")
        PASSWORD = os.environ.get("SMTP_PASS")
        smtp_server = 'smtp.gmail.com'
        # SEND TO DATABASE AND SEND EMAIL TO USER
        with smtplib.SMTP(smtp_server) as server:
            server.starttls()
            server.login(EMAIL, PASSWORD)
            server.sendmail(from_addr= EMAIL,
                        to_addrs=EMAIL,
                        msg=f"Subject:Blog New Message\n\nName:{name}\nEmail:{user_email}\nPhone:{phone}\nMessage:{message}")
            
        return jsonify({"success": True})
    return jsonify({})

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/post/<blog_id>', methods=["GET", "POST"])
@login_required
def post(blog_id):
    form = CommentForm()
    user_id=None
    if current_user.is_authenticated:
        user_id = User.get_id(current_user)
    blog = Post.query.filter(Post.id == blog_id).one()
    parsed_date = date_parser.parse(blog.date)
    formatted_date = parsed_date.strftime("%B %d, %Y")
    blog.date = formatted_date

    if request.method == "POST":
        if form.validate_on_submit():
            today_date = dt.datetime.now().date()
            f_date = today_date.strftime("%Y-%m-%d")
            print("Form validated successfully.")
            new_comment = Comment(
                post_id  = blog.id,
                author_id = current_user.id,
                comment  = form.comment.data,
                date = f_date,
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("post", blog_id=blog.id))
        else:
            print("Form validation failed. Errors:", form.errors)
    
    comments = Comment.query.filter(Comment.post_id == blog_id).all()
    comments.reverse()

    for comment in comments:
        parsed_date_cmt = date_parser.parse(comment.date)
        formatted_date_cmt = parsed_date_cmt.strftime("%B %d, %Y")
        comment.date = formatted_date_cmt

    
    return render_template('post.html', blog=blog, user_id=user_id, form=form, comments=comments)


@app.route('/deletecomment/<comment_id>', methods=["POST", "GET"])
def delete_comment(comment_id):
    print(comment_id)
    comment = Comment.query.filter(Comment.id==comment_id).one()
    if comment:
        db.session.delete(comment)
        db.session.commit()
        return redirect(url_for("post", blog_id=comment.post_id))

@app.route("/createpost", methods=["GET", "POST"])
@admin_only
def add_post():
    form = AddBlogForm(author=current_user.name.title())
    today_date_obj = dt.datetime.now().date()
    today_date = today_date_obj.strftime("%Y-%m-%d")
    print(today_date)
    print(type(today_date))
    if request.method == "POST":
        if form.validate_on_submit():
            new_post = Post(title = form.title.data, 
                            subtitle = form.subtitle.data,
                            author_id = current_user.id,
                            body = form.body.data,
                            img_url = form.image.data,
                            date = today_date)
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for('home'))

    return render_template("create.html", form=form)

@app.route("/deleteblog/<blog_id>", methods=["GET", "POST"])
@admin_only
def delete(blog_id):
    blog = Post.query.filter(Post.id == blog_id).one()

    if blog:
        db.session.delete(blog)
        db.session.commit()
        return redirect('/index')
    else:
        return jsonify(error= 'Blog Not Found'), 404


@app.route("/editblog/<blog_id>", methods=["POST", "GET"])
@admin_only
def edit_post(blog_id):
    blog = Post.query.filter(Post.id == blog_id).one()

    edit_form = AddBlogForm(title = blog.title,
                       subtitle = blog.subtitle,
                       image = blog.img_url,
                       body = blog.body)
    if edit_form.validate_on_submit():
        blog.title = edit_form.title.data
        blog.subtitle = edit_form.subtitle.data
        blog.img_url = edit_form.image.data
        blog.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("post", blog_id=blog.id))
        # return 'True'
        
    return render_template("edit_post.html", blog=blog, form=edit_form)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = SignUpForm()
    if request.method == "POST":
            if form.validate_on_submit():
                email_entered = form.email.data
                try:
                    user = User.query.filter(User.email == email_entered).one()
                    flash("Email already exists", "email_error")

                except NoResultFound:
                    password = encrypt_password(form.password.data)
                    print(password)
                    new_user = User(name=form.name.data,
                                    email=form.email.data,
                                    password= password)
                    db.session.add(new_user)
                    db.session.commit()
                    
                    return redirect("/login")
    else:
        print("Form validation failed. Errors:", form.errors)
        
    return render_template("register.html", form=form)


if __name__ == "__main__":
    app.run(debug=True)