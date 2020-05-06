import os

from flask import Flask, session, render_template, request
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from argon2 import PasswordHasher

from users import *

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

    ph = PasswordHasher()
    hash = ph.hash(password)

    db.execute("INSERT INTO users (first_name, last_name, username, email, password) VALUES (:first_name, :last_name, "
               ":username, :email, :password)",
               {"first_name": first_name, "last_name": last_name, "username": username, "email": email, "password": hash})

    db.commit()

    return render_template("index.html")


if __name__ == "__main__":
    app.run()
