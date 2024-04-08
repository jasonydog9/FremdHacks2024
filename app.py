import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///journal.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    logs = db.execute("SELECT username, journal, date FROM logs WHERE Public=:Public ORDER BY date DESC", Public=1)
    return render_template("index.html", logs=logs)

@app.route("/personalLog", methods=["GET", "POST"])
@login_required
def personalLog():
    if request.method == "POST":
        fields = request.form
        fields = fields.to_dict(flat=False)
        for key in fields:
            db.execute("DELETE FROM logs WHERE journalid=:journalid", journalid=key)

    logs = db.execute("SELECT journal, date, journalid FROM logs WHERE id=:id ORDER BY date DESC", id=session["user_id"])

    return render_template("personalLog.html", size=len(logs), logs=logs)

@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    if request.method == "POST":

        if not request.form.get("journal"):
            return apology("Write something in your journal!!!")
        anon = False
        pub = False
        if request.form.get("unknown"):
            anon = True
        if request.form.get("public"):
            pub = True


        journal = request.form.get("journal")
        username = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])[0]["username"]
        if anon:
            db.execute(
                "INSERT INTO logs (id, journal, date, username, Anonymous, Public) VALUES (:id, :journal, :date, :username, :Anonymous, :Public)",
                id=session["user_id"], journal=journal, date=datetime.now(), username="Anonymous", Anonymous=anon,
                Public=1)
        else:
            db.execute(
                "INSERT INTO logs (id, journal, date, username, Anonymous, Public) VALUES (:id, :journal, :date, :username, :Anonymous, :Public)",
                id=session["user_id"], journal=journal, date=datetime.now(), username=str(username), Anonymous=anon,
                Public=pub)
        size = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])[0]["size"] + 1
        db.execute("UPDATE users SET size=:size WHERE id=:id", size=size, id=session["user_id"])
        return redirect("/")
    else:
        return render_template("post.html")

@app.route("/about", methods=["GET", "POST"])
@login_required
def about():
    return render_template("about.html")












@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide password")

        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("Confirmed password must match password")

        hashPassword = generate_password_hash(request.form.get("password"))

        if len(db.execute('SELECT username FROM users WHERE username = ?', request.form.get("username"))) > 0: # help from a friend
            return apology("Username already exists", 400)

        else:
            Name = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", # help from a friend
                              username=request.form.get("username"), hash=hashPassword)
            session["user_id"] = Name

            return redirect("/")

    if request.method == "GET":
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/change_username", methods=["GET", "POST"])
@login_required
def change_username():
    if request.method == "POST":
        if not request.form.get("new_username") or not request.form.get("password"):
            return apology("Input invalid")

        rows = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
        if check_password_hash(rows[0]["hash"], request.form.get("password")):
            db.execute("UPDATE users SET username=:username WHERE id=:id", username=request.form.get("new_username"), id=session["user_id"])
            return redirect("/")
        else:
            return apology("Invalid Password")
    else:
        return render_template("settings.html")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        if not request.form.get("new_password") or not request.form.get("old_password"):
            return apology("Input invalid")

        rows = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
        if check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            db.execute("UPDATE users SET hash=:hash WHERE id=:id", hash=generate_password_hash(request.form.get("new_password")), id=session["user_id"])
            return redirect("/")
        elif request.form.get("new_password") == request.form.get("old_password"):
            return apology("Input a new password.")
        else:
            return apology("Invalid Password")
    else:
        return render_template("settings.html")








































