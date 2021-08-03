#!/usr/bin/env python
from functools import wraps
import hashlib
import json
import subprocess

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    session,
    url_for,
)
from flask_cors import CORS
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
import requests
import yaml

app = Flask(__name__)
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
db = SQLAlchemy()
db.init_app(app)

SESSION_TYPE = "filesystem"
app.config.from_object(__name__)
Session(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin = db.Column(db.Integer)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def check_pw(self, password):
        return self.password == hash_password(password)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    name = db.Column(db.String(1000))
    content = db.Column(db.Text)


def template(file):
    return render_template(file, authenticated=session.get("authenticated", False))


def restricted(admin=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                if admin:
                    assert session.get("admin", False)
                app.logger.info("Access granted: %s", request.__dict__)
                return func(*args, **kwargs)
            except:
                return "unauthorized", 401

        return wrapper

    return decorator


def hash_password(password):
    return hashlib.sha1(b"{password}").hexdigest()


@app.route("/")
def index():
    return template("index.html")


@app.route("/login")
def login():
    redir = request.args.get("redirect")
    session["redirect"] = redir
    return template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    email = request.form.get("email")
    password = request.form.get("password")
    user = User.query.filter_by(email=email).first()

    if not user or not user.check_pw(password):
        flash("Please check your login details and try again.")
        return redirect(url_for("auth.login"))

    session["authenticated"] = True
    if user.admin == 1:
        session["admin"] = True
    session["user"] = user

    redir = session.get("redirect")
    if redir is not None:
        return redirect(redir)
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session["authenticated"] = False
    return redirect(url_for("login"))


@app.route("/signup")
def signup():
    return template("signup.html")


@app.route("/signup", methods=["POST"])
def signup_post():
    args = request.form.to_dict()
    user = User.query.filter_by(email=args.get("email")).first()

    if user:
        flash("Email already registered")
        return redirect(url_for("signup"))
    args["password"] = hash_password(args.get("password"))

    new_user = User(**args)

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for("login"))


@app.route("/users", methods=["GET"])
@restricted(admin=True)
def users():
    users = User.query.all()
    out = ""

    for user in users:
        out += f"- {user.name}"
    return out


@app.route("/ip")
def ip_addr():
    forward = request.headers.get("x-forwarded-for")
    if forward is None:
        return request.remote_addr
    return forward.split(",")[0].strip()


@app.route("/notes", methods=["POST"])
@restricted(admin=False)
def note_create():
    if request.content_type.startswith("application/json"):
        data = request.get_json()
    elif request.content_type.startswith("application/yaml"):
        data = yaml.load(request.data)
    else:
        return "content type not supported", 400

    new_note = Note(**data)

    db.session.add(new_note)
    db.session.commit()
    return redirect(url_for(f"note_read/{new_note.id}"))


@app.route("/note", methods=["GET"])
def note_read():
    note_id = request.args.get("id")
    return Note.query.filter_by(id=note_id).first()


@app.route("/note", methods=["DELETE"])
@restricted(admin=False)
def note_delete():
    note_id = request.args.get("id")
    Note.query.filter_by(id=note_id).delete()
    return ""


@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    if url is None:
        return "URL not provided", 400
    return requests.get(url).text


@app.route("/docs/<path:path>")
def docs(path):
    return send_file(f"docs/{path}")


@app.errorhandler(404)
def not_found(response):
    return f"Requested resource not found {request.path}", 404


db.create_all(app=app)
