import os
from tempfile import mkdtemp

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError # importing modules for the code
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# configuring the application for flask
app = Flask(__name__)

# making sure the html immediately refreshes
app.config["TEMPLATES_AUTO_RELOAD"] = True


# makes sure the users data is not collected
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


#creating tables for the share buy/sell history
db.execute("""
CREATE TABLE IF NOT EXISTS history (
    id       INTEGER PRIMARY KEY,
    username TEXT    NOT NULL,
    price    NUMERIC NOT NULL,
    side     TEXT    NOT NULL,
    symbol     TEXT    NOT NULL,
    shares   INTEGER NOT NULL,
    current_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);""")


# home page that shows the stock portfolio
db.execute("""
CREATE TABLE IF NOT EXISTS portfolio (
    id       INTEGER PRIMARY KEY,
    username TEXT    NOT NULL,
    symbol     TEXT    NOT NULL,
    shares   INTEGER NOT NULL
);""")
print()
os.environ["API_KEY"] = "pk_740fb1654293483bac5687384ebd9ad3"
# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index(): #more info of the home page
    """Show portfolio of stocks"""
    # Query database for username
    rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    username = rows[0]['username']
    current_cash = rows[0]['cash']

    total_assets = current_cash

    rows = db.execute("SELECT * FROM portfolio WHERE username=?", username)

    for each in rows:
        temp_data = lookup(each['symbol'])
        each["name"] = temp_data["name"]
        each["price"] = temp_data["price"]
        each["total"] = each["price"] * each["shares"]
        total_assets += each["total"]
    # print("hi", rows)

    return render_template("index.html", total_cash=current_cash, results=rows, total_assets=total_assets)


@app.route("/buy", methods=["GET", "POST"]) #all the code that makes the buy stock part run
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # Ensure symbol exists
        symbol_data = lookup(request.form.get("symbol"))
        if symbol_data is None:
            return apology("must provide a valid symbol name", 400)

        # Ensure shares was submitted
        elif not request.form.get("shares").isdigit():
            return apology("shares must be a positive integer", 400)

        # Ensure shares is positive integer
        elif int(request.form.get("shares")) <= 0:
            return apology("shares must be a positive integer", 400)

        total_price = int(request.form.get("shares")) * symbol_data["price"]

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        # print(rows, session["user_id"])
        current_cash = rows[0]['cash']
        current_username = rows[0]['username']

        if current_cash < total_price:
            return apology("insufficient cash", 400)

        # Subtract the value of purchase from the user's cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_price, session['user_id'])

        # Add the transaction to the user's history
        db.execute(
            "INSERT INTO history (username, side, symbol, price, shares) VALUES (?, 'BUY', ?, ?, ?)", current_username,
            symbol_data['symbol'], symbol_data['price'], request.form.get('shares'))

        db.execute("INSERT INTO portfolio (username, symbol, shares) VALUES (?, ?, ?)", current_username,
                   symbol_data['symbol'], request.form.get('shares'))
        flash("Bought!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Store the username of the user logged
    username = db.execute("SELECT username FROM users WHERE id =?", session['user_id'])[0]["username"]
    # print("I am username", username)

    # Put information from 'history' into a list
    rows = db.execute("SELECT * FROM history WHERE username=? ORDER BY id DESC", username)
    # print("I am rows", rows)

    # Iterate over the stocks list to append the faulty information needed in history.html table
    for each in rows:
        each["name"] = lookup(each["symbol"])["name"]

    return render_template("history.html", results=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = int(rows[0]["id"])

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
    if request.method == "GET": #check if user is going onto the quote page
        return render_template("quote.html")
    elif request.method == "POST": #if posting, get symbols
        symbols = request.form.get("symbol")
        results = []
        if "," in symbols:
            symbols = symbols.split(",")
            for each in symbols:
                temp = lookup(each)
                if temp is not None:
                    results.append(temp)
        else:
            temp = lookup(symbols)
            if temp is not None:
                results.append(temp)

        # print(results) into table
        return render_template("quoted.html", results=results)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirm password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirm password", 400)

        special_symbols = ['!', '#', '$', '%', '.', '_', '&']

        if len(request.form.get("password")) < 8:
            return apology("Your password must contain 8 or more characters.")

        elif not any(char.isdigit() for char in request.form.get("password")):
            return apology("Your password must contain at least 1 number.")

        elif not any(char.isupper() for char in request.form.get("password")):
            return apology("Your password must contain at least uppercase letter.")

        elif not any(char in special_symbols for char in request.form.get("password")):
            return apology("Your password must contain at least 1 approved symbol.")

        # Ensure confirm password was submitted
        if request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords must match", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) == 1:
            return apology("username already exists", 400)

        rows = db.execute("INSERT INTO users (username,hash) VALUES(?,?)", request.form.get("username"),
                          generate_password_hash(request.form.get("password")))
        if rows > 0:
            return render_template("login.html")
        else:
            return apology("Error with database", 500)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Query database for username
    username = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["username"]

    if request.method == "GET":
        rows = db.execute("SELECT symbol FROM portfolio WHERE username=?", username)
        return render_template("sell.html", results=rows)
    elif request.method == "POST":
        if request.form.get("symbol") is None:
            return apology("select correct symbol", 400)

        # Ensure shares was submitted
        if not request.form.get("shares").isdigit():
            return apology("shares must be a positive integer", 400)

        # Ensure shares is positive integer
        elif int(request.form.get("shares")) <= 0:
            return apology("shares must be a positive integer", 400)

        # Store the symbol
        symbol_data = lookup(request.form.get("symbol"))

        # Store the number of shares the user has
        user_shares = db.execute("SELECT shares FROM portfolio WHERE username=? and symbol=?", username,
                                 request.form.get("symbol"))[0]["shares"]

        if int(request.form.get("shares")) > user_shares:
            return apology("You do not have sufficient shares")

        # Store the value of sale
        new_price = symbol_data["price"] * int(request.form.get("shares"))
        print("new price", new_price)

        # Add the value of sale to the user's cash
        db.execute("UPDATE users SET cash=cash+:new_price WHERE id=:id", new_price=new_price, id=session['user_id'])

        # Add the transaction to the user's history
        db.execute(
            "INSERT INTO history (username, side, symbol, price, shares) VALUES (?,'SELL',?,?,?)", username,
            symbol_data['symbol'], symbol_data['price'], request.form.get('shares'))

        # If the user is selling all of their shares, then remove the stock from the user's portfolio
        if int(user_shares) == int(request.form.get("shares")):
            db.execute("DELETE FROM portfolio WHERE username=? and symbol=?", username, request.form.get("symbol"))

        # If the user is selling few of their shares, then update the portfolio
        elif user_shares > int(request.form.get("shares")):
            db.execute("UPDATE portfolio SET shares=? WHERE username=? and symbol=?",
                       user_shares - int(request.form.get("shares")),
                       username, request.form.get("symbol"))
        flash("Sold!")
        return redirect("/")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format""" #checks if the username is available or not for registration

    # Define username as the input in the form
    username = request.args.get('username')

    # Identify if that input is in the database
    other_username = db.execute("SELECT username FROM users WHERE username=?", username)
    # print(other_username)

    # If the username is in database, return false, if not return true and proceed
    try:
        result = other_username[0]['username']
        if not result:
            return jsonify(True)
        else:
            return jsonify(False)
    except IndexError:
        return jsonify(True)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Change account settings."""
    if request.method == "POST":
        # ensure all fields are completed
        if not request.form.get("old_password") or not request.form.get("new_password") or not request.form.get(
                "confirm_password"):
            return render_template("account.html")

        # retrieve user data
        user = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])

        # ensure old password is correct and no errors
        if len(user) != 1 or not check_password_hash(user[0]["hash"], request.form.get("old_password")):
            return apology("password is incorrect")

        # ensure new passwords match
        if request.form.get("new_password") != request.form.get("confirm_password"):
            return apology("new passwords do not match")

        # commit new password to db
        db.execute("UPDATE users SET hash=? WHERE id=?",
                   generate_password_hash(request.form.get("new_password")), session["user_id"])
        flash("Password Changed!")
        return render_template("account.html", success=1)

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("account.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)