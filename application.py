import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# export API_KEY=pk_e20c175e2c334315a68bd56b2eca27fe

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
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":

        TOTAL = 0.00
        ownedShares = db.execute(
            "SELECT share_name, cuantity, symbol, price, finalprice FROM shares WHERE user_id= ?", session.get("user_id"))
        CASH = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))[0]["cash"]
        cash = usd(CASH)
        for share in ownedShares:
            symbol = share.get("symbol")
            stockInfo = lookup(symbol)
            name = stockInfo.get("name")
            price = usd(stockInfo.get("price"))
            total = usd(stockInfo.get("price") * share.get("cuantity"))
            TOTAL = TOTAL + (stockInfo.get("price") * share.get("cuantity"))
            db.execute("UPDATE shares SET price = ?, finalprice = ? WHERE user_id = ? AND share_name = ?",
                       price, total, session.get("user_id"), name)
        TOTAL = TOTAL + CASH
        TOTAL = usd(TOTAL)
        return render_template("index.html", ownedShares=ownedShares, cash=cash, TOTAL=TOTAL)


@app.route("/addCash", methods=["GET", "POST"])
@login_required
def addCash():
    """Add cash to user account"""

    if request.method == "POST":
        cash = request.form.get("cashAdded")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cash, session.get("user_id"))
        return redirect("/")
    else:
        userCash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
        return render_template("addCash.html", userCash=userCash[0]["cash"])


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        date = datetime.now()
        dt_string = date.strftime("%d/%m/%Y %H:%M:%S")
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stockInfo = lookup(symbol)
        if symbol == "":
            return apology("Quote not provided")
        elif stockInfo is None:
            return apology("Invalid Quote")
        elif shares.isdigit(): 
            symbol = symbol.upper()
            price = usd(stockInfo.get("price"))
            userCash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
            total = stockInfo.get("price") * float(shares)
            tot = usd(total)
            if userCash[0]["cash"] >= total:
                db.execute("UPDATE users SET cash=cash- ? WHERE id= ?", total, session.get("user_id"))

                if not db.execute("SELECT share_name from shares WHERE user_id=? AND share_name=?",
                                  session.get("user_id"), stockInfo.get("name")):
                    db.execute("INSERT INTO shares (share_name, cuantity, user_id, symbol, price, finalprice) VALUES (?,?,?,?,?,?)", 
                               stockInfo.get("name"), shares, session.get("user_id"), symbol, price, tot)
                    db.execute("INSERT INTO history (trxType, name, cuantity, user_id, datetime, price,symbol) VALUES('BUY', ?, ?, ?, ?, ?, ?)", 
                               stockInfo.get("name"), shares, session.get("user_id"), dt_string, price, symbol)

                else:
                    db.execute("UPDATE shares SET cuantity=cuantity + ?, price = ?, finalprice = ? WHERE user_id= ? AND share_name= ?",
                               shares, price, tot, session.get("user_id"), stockInfo.get("name"))
                    db.execute("INSERT INTO history (trxType, name, cuantity, user_id, datetime, price, symbol, price) VALUES('BUY', ?, ?, ?, ?, ?, ?, ?)", 
                               stockInfo.get("name"), shares, session.get("user_id"), dt_string, price, symbol, price)

                return redirect("/")

            else:
                return apology("Insuficient Balance")
            
        else:
            return apology("Invalid Shares")
    else:
        date = datetime.now()
        dt_string = date.strftime("%d/%m/%Y %H:%M:%S")
        user_id = session.get("user_id")
        userCash = db.execute("SELECT cash FROM users WHERE id=?", session.get("user_id"))
        return render_template("buy.html", date=dt_string, userid=user_id, userCash=userCash[0]["cash"])


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT trxType, name, cuantity, price, symbol, datetime FROM history WHERE user_id=?",
                         session.get("user_id"))
    return render_template("history.html", history=history)


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
        stockInfo = lookup(symbol)
        if symbol == "":
            return apology("Quote not provided")
        elif stockInfo is None:
            return apology("Invalid Quote")
        else:
            price = usd(stockInfo.get("price"))
            return render_template("quoted.html", stockInfo=stockInfo, price=price)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        for user in db.execute("SELECT username from users"):
            if user.get("username") == username:
                return apology("Username already exist", 400)
        if username == "":
            return apology("must provide username", 400)
        elif password != confirmation:
            return apology("Passwords do not match", 400)
        elif password == "" or confirmation == "":
            return apology("must provide password", 400)
        else:
            passwordHash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, passwordHash)
            return render_template("login.html")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        date = datetime.now()
        dt_string = date.strftime("%d/%m/%Y %H:%M:%S")
        symbol = request.form.get("symbol")
        shares = request.form.get("shares") 
        stockInfo = lookup(symbol)
        if symbol == "":
            return apology("Symbol not provided")
        elif stockInfo is None:
            return apology("Invalid Quote")
        elif shares.isdigit():
            symbol = symbol.upper()
            price = usd(stockInfo.get("price"))
            userShares = db.execute("SELECT cuantity FROM shares WHERE user_id=? AND share_name=?", 
                                    session.get("user_id"), stockInfo.get("name"))
            total = stockInfo.get("price") * float(shares)
            tot = usd(total)
            shares = int(shares) 
            if userShares[0]["cuantity"] >= shares:
                db.execute("UPDATE users SET cash=cash + ? WHERE id= ?", total, session.get("user_id"))
                db.execute("UPDATE shares SET cuantity=cuantity - ?, price = ?, finalprice = ? WHERE user_id= ? AND share_name= ?",
                           shares, price, tot, session.get("user_id"), stockInfo.get("name")) 
    
                shareCuantity = db.execute("SELECT cuantity FROM shares WHERE share_name=? AND user_id=?", 
                                           stockInfo.get("name"), session.get("user_id"))
    
                if shareCuantity[0]["cuantity"] == 0:
                    db.execute("DELETE FROM shares WHERE share_name=? AND user_id=?", stockInfo.get("name"), session.get("user_id"))
    
                db.execute("INSERT INTO history (trxType, name, cuantity, user_id, datetime, price, symbol) VALUES('SELL', ?, ?, ?, ?, ?, ?)", 
                           stockInfo.get("name"), shares, session.get("user_id"), dt_string, price, symbol)
                return redirect("/")
    
            else:
                return apology("Insuficient Balance")
                
        else:
            return apology("Invalid Shares")
            
    else:
        date = datetime.now()
        dt_string = date.strftime("%d/%m/%Y %H:%M:%S")
        user_id = session.get("user_id")
        userCash = db.execute("SELECT cash FROM users WHERE id=?", user_id)
        symbolsName = db.execute("SELECT symbol FROM shares WHERE user_id=?", user_id)
        return render_template("sell.html", date=dt_string, userid=user_id, userCash=userCash[0]["cash"], symbolsName=symbolsName)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# Add comments!!
