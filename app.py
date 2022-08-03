from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import request
from flask import jsonify
import os
from flask import render_template
from flask_migrate import Migrate
from flask import redirect
from flask import url_for
from flask_login import UserMixin
# from flask_user import login_required, UserManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import flash
from flask import session
from flask_login import login_required, current_user, LoginManager, login_user, logout_user

app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)

app.secret_key = 'my-secret-key-3476t'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:akhil123@localhost:5432/BookSuggestion"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    print('user loaded')
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))


# Define the User data-model.
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default='')
    # User information
    first_name = db.Column(db.String(100, ), nullable=False, server_default='')
    last_name = db.Column(db.String(100), nullable=False, server_default='')
    # Define the relationship to Role via UserRoles
    roles = db.relationship('Role', secondary='user_roles')
    user_book_suggestions = db.relationship('UserBookSuggestions', backref='users',
                                            cascade='all, delete, delete-orphan')

    def verify_password(self, pwd):
        return check_password_hash(self.password, pwd)


# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)


# Define the UserRoles association table
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))


class UserBookSuggestions(db.Model):
    __tablename__ = 'user_book_suggestions'
    id = db.Column(db.Integer, primary_key=True)
    book_title = db.Column(db.String(80), unique=True, nullable=False)
    book_author = db.Column(db.String(80), unique=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    # def __init__(self, book_title, book_author, user_id):
    #     self.user_id = user_id
    #     self.book_title = book_title
    #     self.book_author = book_author

    # def __repr__(self):
    #     return f"Book {self.book_title}"


# db.create_all()

@app.route('/', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        # login code goes here
        email = request.form.get('user_email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        print(user)
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))  # if the user doesn't exist or password is wrong, reload the page
        login_user(user)
        # if the above check passes, then we know the user has the right credentials
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    try:
        if request.method == "POST":
            data = request.form
            new_book = UserBookSuggestions(
                                           book_title=data['book_title'],
                                           book_author=data.get('book_author', None),
                                           user_id=current_user.id
                                           )
            db.session.add(new_book)
            db.session.commit()
            print('data saved successfully...')
            return redirect(url_for('show_books', current_user=current_user))
        else:
            # print('going to else')
            return render_template('home.html', current_user=current_user)
    except Exception as inst:
        return render_template('error.html')


@app.route('/books', methods=['GET'])
@login_required
def show_books():
    try:
        print(current_user.roles[0].name == 'user')
        if current_user.roles[0].name == 'user':
            books = UserBookSuggestions.query.filter_by(user_id=current_user.id)
            results = [
                {
                    "user_id": data.user_id,
                    "user_name": User.query.get(data.user_id).first_name,
                    "user_email": User.query.get(data.user_id).email,
                    "book_title": data.book_title,
                    "book_author": data.book_author
                } for data in books]
            return render_template('book_list.html', books=results)
        else:
            books = UserBookSuggestions.query.all()
            results = [
                {
                    "user_id": data.user_id,
                    "user_name": User.query.get(data.user_id).first_name,
                    "user_email": User.query.get(data.user_id).email,
                    "book_title": data.book_title,
                    "book_author": data.book_author
                } for data in books]
            return render_template('book_list.html', books=results)
    except Exception as inst:
        return render_template('error.html')
