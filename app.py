import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    rows = db.execute("SELECT * FROM purchases WHERE user_id = ? GROUP BY symbol, shares, amount", session["user_id"])
    return render_template("index.html", rows=rows)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol or lookup(symbol) == None:
            return apology("Input stock symbol")
        if not shares or shares < 0:
            return apology("Input at least 1 share")

        stats = lookup(symbol)
        price = stats["price"]
        priceTot = price*shares
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        userCash = rows[0]["cash"]
        if priceTot > userCash:
            return apology("Cannot afford")
        date = datetime.datetime.now()
        month = date.month
        day = date.day
        year = date.year
        updatedCash = userCash - price
        username = rows[0]["username"]
        purchaseRows = db.execute("SELECT * FROM purchases WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updatedCash, session["user_id"])
        if len(purchaseRows) < 1:
            db.execute(
                "INSERT INTO purchases (user_id, amount, shares, symbol, month, day, year, total, username, history) VALUES(?,?,?,?,?,?,?,?,?,?)",
                session["user_id"], price, shares, symbol, month, day, year, updatedCash, username, shares)
        else:
            db.execute(
                "INSERT INTO purchases (user_id, amount, shares, symbol, month, day, year, total, username, history) VALUES(?,?,?,?,?,?,?,?,?,?)",
                session["user_id"], price, shares, symbol, month, day, year, updatedCash, username, shares)
            db.execute("UPDATE purchases SET shares = ? WHERE symbol = ?", purchaseRows[0]["shares"] + shares, symbol)
            db.execute("UPDATE purchases SET total = ? WHERE user_id = ?", updatedCash, session["user_id"])
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    rows = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])
    return render_template("history.html", rows=rows)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Input a stock symbol")
        stats = lookup(symbol)
        stats["price"] = usd(stats["price"])
        return render_template("quoted.html", stats=stats)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT * FROM users WHERE username = ?", name)
        if not name or len(rows) == 1:
            return apology("Invalid username")
        elif not password or password != confirmation:
            return apology("Invalid password")

        hashed = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name, hashed)
        return render_template("login.html")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        rows = db.execute("SELECT * FROM purchases WHERE id = ? AND symbol = ?", session["user_id"], symbol)
        if not symbol or len(rows) < 1:
            return apology("Input or buy stock")
        elif not shares or len(rows) < 1 or rows[0]["shares"] - shares < 0:
            return apology("No shares")

        rows2 = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        stats = lookup(symbol)
        price = stats["price"] * shares
        updatedCash = rows2[0]["cash"] + price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updatedCash, session["user_id"])
        db.execute("UPDATE purchases SET shares = ? WHERE symbol = ?", rows[0]["shares"] - shares, symbol)
        return redirect("/")
    else:
        rows = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])
        symbols = []
        for row in rows:
            symbol = row["symbol"]
            if symbol not in symbols:
                symbols.append(symbol)
        return render_template("sell.html", symbols=symbols)
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if not username or len(rows) < 1 or not password or not confirm:
            return apology("Enter a value")
        if password != confirm:
            return apology("Passwords don't match")
        if len(rows) == 1:
            hashed = generate_password_hash(password)
            db.execute("UPDATE users SET hash = ? WHERE username = ?", hashed, username)
    else:
        return render_template("forgot.html")
