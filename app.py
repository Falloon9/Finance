import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    shares = db.execute(
        "SELECT symbol, name, price, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash[0]["cash"]

    total = cash

    for share in shares:
        total += share["price"] * share["total_shares"]

    return render_template("index.html", shares=shares, usd=usd, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Must be an integer")

        stock = lookup(symbol)

        if symbol == None:
            return apology("Please enter a symbol")
        if stock == None:
            return apology("Stock not found")
        if shares <= 0:
            return apology("Share amount cannot be negative")

        user_id = session["user_id"]
        user_cash = db.execute("SELECT cash from users WHERE id = ?", user_id)
        cash = user_cash[0]["cash"]

        total_price = shares * stock["price"]
        if cash < total_price:
            return apology("Not enough balance")
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price, user_id)
        date = datetime.datetime.now()
        db.execute("INSERT INTO transactions (user_id, name, shares, price, symbol, date) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, stock["name"], shares, stock["price"], stock["symbol"], date)

        flash("Transaction successful!")

        return redirect('/')
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT date, symbol, name, shares, price FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions)


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
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Please enter a symbol")

        stock = lookup(symbol)

        if stock == None:
            return apology("stock does not exist")

        return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
  # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("please provide a username")

        # Ensure password was submitted
        password = request.form.get("password")
        if not password:
            return apology("please provide a password")

        # Ensure password confirmation was submitted
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("please confirm the password")

        # Ensure password and confirmation matches
        if password != confirmation:
            return apology("passwords do not match")

        # Require users’ passwords to have some number of letters
        if len(password) < 8:
            return apology("Make sure your password is at least 8 letters")

        hash = generate_password_hash(password)

        try:
            new = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("username already exists")

        session["user_id"] = new

        return redirect('/')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]

        symbol = request.form.get("symbol")
        if symbol == None:
            return apology("Please enter a symbol")

        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("Share amount cannot be negative")

        stock = lookup(symbol)

        total_price = shares * stock["price"]

        user_id = session["user_id"]
        user_cash = db.execute("SELECT cash from users WHERE id = ?", user_id)
        cash = user_cash[0]["cash"]

        available_shares = db.execute(
            "SELECT SUM(shares) AS shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)
        remaining_shares = available_shares[0]["shares"]

        if shares > remaining_shares:
            return apology("Not enough shares")

        updt_cash = cash + total_price

        db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, user_id)
        date = datetime.datetime.now()
        db.execute("INSERT INTO transactions (user_id, name, shares, price, symbol, date) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, stock["name"], (-1) * shares, stock["price"], stock["symbol"], date)

        flash("Transaction successful!")

        return redirect('/')

    else:
        user_id = session["user_id"]
        available_symbols = db.execute(
            "SELECT symbol from transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
        return render_template("sell.html", symbols=[row["symbol"] for row in available_symbols])
