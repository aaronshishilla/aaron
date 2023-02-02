from flask import Flask, request, redirect, url_for, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SECRET_KEY'] = 'secret-key'

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    company = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    unique_id = db.Column(db.String(10), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


db.create_all()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        company = request.form.get("company")
        email = request.form.get("email")
        password = request.form.get("password")

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # Generate a unique ID code
        unique_id = bcrypt.hashpw(username.encode(), bcrypt.gensalt())[:10]

        user = User(username=username, company=company, email=email, password=password_hash, unique_id=unique_id)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))
    return render_template("register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode(), user.password.encode()):
            session["username"] = username
            session["company_id"] = user.company_id
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" in session:
        company_id = session["company_id"]
        return render_template("dashboard.html", username=session["username"], company_id=company_id)
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("company_id", None)
