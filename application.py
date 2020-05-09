import os

from flask import Flask, session, render_template, request, redirect, url_for
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

ph = PasswordHasher()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register")
def get_registration_form():
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email")
    username = request.form.get("username")
    first_name = request.form.get("firstName")
    last_name = request.form.get("lastName")
    password = request.form.get("password")
    password_confirmation = request.form.get("passwordConfirmation")

    email_already_exists = db.execute("SELECT * FROM users WHERE email = :email", {"email": email}).rowcount > 0
    if email_already_exists:
        return render_template("register.html")

    username_already_exists = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).rowcount > 0
    if username_already_exists:
        return render_template("register.html")

    if password != password_confirmation:
        return render_template("register.html")

    hash = ph.hash(password)

    db.execute("INSERT INTO users (first_name, last_name, username, email, password) VALUES (:first_name, :last_name, "
               ":username, :email, :password)",
               {"first_name": first_name, "last_name": last_name, "username": username, "email": email, "password": hash})

    db.commit()

    return render_template("index.html")

@app.route("/login")
def get_login_form():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("userEmail")
    password = request.form.get("userPassword")

    user = db.execute('SELECT * FROM users WHERE email = :email', {"email": email}).fetchone()

    if not user:
        message = "Sorry, we don't recognise that email address, please try again"
        return render_template("login.html", message=message)

    try:
        ph.verify(user['password'], password)
    except VerifyMismatchError:
        message = "Your password was incorrect, please try again."
        return render_template("login.html", message=message)

    session['loggedin'] = True
    session['id'] = user['id']
    session['username'] = user['username']

    return redirect(url_for('home'))


@app.route("/logout")
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)

    return render_template("logout.html")

@app.route("/home")
def home():
    print(session)
    if 'loggedin' in session:
        return render_template("home.html", username=session['username'])
    return redirect(url_for('login'))



if __name__ == "__main__":
    app.run()
