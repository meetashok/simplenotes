import os
import sqlite3

from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, humanize_ts
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["humanize_ts"] = humanize_ts

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
# db = sqlite3.connect("simplenotes.db", check_same_thread=False).cursor()
# with sqlite3.connect("simplenotes.db").cursor() as db:
# db = SQL("sqlite:///finance.db")

# Make sure API key is set
# if not os.environ.get("API_KEY"):
#     raise RuntimeError("API_KEY not set")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    with sqlite3.connect("simplenotes.db") as conn:
        db = conn.cursor()
        data = db.execute("""SELECT note_id, title, body, created_at, updated_at
        FROM notes where user_id = ? order by updated_at desc""", (session["user_id"], )).fetchall()

    return render_template("home.html", data=data)

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    print(session)
    if request.method == "GET":
        return render_template("search.html", data=None)
    
    if request.method == "POST":
        s = request.form.get("searchstring")
        if s:
            s = f'%{s}%'
        else:
            s = '%%'

        with sqlite3.connect("simplenotes.db") as conn:
            db = conn.cursor()
            data = db.execute("""SELECT * FROM notes WHERE user_id = ? 
            AND lower(body) like ? or lower(title) like ?""",
            (session["user_id"], s, s)).fetchall()
        
        return render_template("search.html", data=data)


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
        with sqlite3.connect("simplenotes.db") as conn:
            db = conn.cursor()
            rows = db.execute("SELECT * FROM users WHERE username = ?",
                            (request.form.get("username"), )).fetchall()

        if len(rows) == 0:
            return apology("username not found", 403)

        row = rows[0]    
        # Ensure username exists and password is correct
        if not check_password_hash(row[2], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = row[0]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/delete/<id>", methods=["GET", "POST"])
@login_required
def delete(id=None):
    with sqlite3.connect("simplenotes.db") as conn:
        db = conn.cursor()
        db.execute("delete from notes where note_id = ?", (id, ))
    return redirect("/")

@app.route("/write", methods=["GET", "POST"])
@app.route("/write/<id>", methods=["GET", "POST"])
@login_required
def write(id=None):
    """Writing a new note"""
    session["note_id"] = id
    # User reached route via POST (as by submitting a form via POST)
    print(id, session["note_id"])
    if request.method == "GET":
        if id:
            with sqlite3.connect("simplenotes.db") as conn:
                db = conn.cursor()
                data = db.execute("select * from notes where note_id = ?", (id, )).fetchall()[0]
        else:
            data = None
        
        return render_template("write.html", data=data)

    if request.method == "POST":
        body = request.form.get("body")
        title = request.form.get("title")

        if body:
            body = body.strip()

        if title:
            title = title.strip()

        # Query database for username
        if session["note_id"]:
            with sqlite3.connect("simplenotes.db") as conn:
                db = conn.cursor()
                now = datetime.utcnow()
                now = now.strftime("%Y-%m-%d %H:%M:%S")
                if title:
                    db.execute("UPDATE notes set title=?, body=?, updated_at=? where note_id = ?",
                        (title, body, now, session["note_id"])
                    )
                else:
                    db.execute("UPDATE notes set body=?, updated_at=? where note_id = ?",
                        (body, now, session["note_id"])
                    )
        else:
            if not title:
                title = "Untitled"

            with sqlite3.connect("simplenotes.db") as conn:
                db = conn.cursor()
                db.execute("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                    (session["user_id"], title, body, )
                )
        session["note_id"] = None
        return redirect("/")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Username is required")

        if (not password) or (not confirmation):
            return apology("Password fields cannot be empty")

        if (password != confirmation):
            return apology("Passwords don't match")
        print(username)
        with sqlite3.connect("simplenotes.db") as conn:
            db = conn.cursor()
            rows = db.execute("SELECT * from users where username = ?", (username, )).fetchall()
        print(rows, type(rows))
        if len(rows) > 0:
            return apology("Username already exists")

        password_hash = generate_password_hash(password)
        with sqlite3.connect("simplenotes.db") as conn:
            db = conn.cursor()
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))

        return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
