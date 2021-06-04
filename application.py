import os
from PIL import Image
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

app = Flask(__name__)
path = "static/pictures/"
sample = "static/pictures/download.png"

app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("postgresql://amiqogrhexwqlj:766a20b4e86d01b5b9e87ebcfb2639d79a6ff00bc5ead005870c41b4ea0b620c@ec2-54-155-35-88.eu-west-1.compute.amazonaws.com:5432/da98djjslr4uvq")

@app.route("/")
def index():
    if session.get("user_id") is None:
        return render_template("index.html")
    else:
        display = db.execute("SELECT display FROM users WHERE id = ?", session.get("user_id"))[0]['display']
        latest = db.execute("SELECT * FROM articles WHERE author_id != ? ORDER BY datetime(time, '+05 hours','+30 minutes') DESC LIMIT 1", session.get("user_id"))[0]
        viewed_id = db.execute("SELECT article_id FROM views GROUP BY article_id ORDER BY sum(view) DESC LIMIT 1")[0]['article_id']
        viewed = db.execute("SELECT * FROM articles WHERE id = ?", viewed_id)[0]

        articles = []
        articles.append(latest)
        articles.append(viewed)


        content = ""
        spaces = 0
        for article in articles:
            content = ""
            spaces = 0
            for c in article['content']:
                if c == " ":
                    spaces += 1
                    if spaces == 15:
                        break
                content += c
            content += "..."
            article['content'] = content
        return render_template("home.html", display=display, latest=articles[0], viewed=articles[1])

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("No username!")
            return render_template("login.html")
        elif not password:
            flash("No password!")
            return render_template("login.html")

        rows = db.execute("SELECT hash, id FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Invalid username or password")
            return render_template("login.html")

        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()

    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()

    if request.method == "POST":
        display = request.form.get("display")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        img = request.files["picture"]
        if not img:
            img = Image.open(sample)
        checkusername = db.execute("SELECT * FROM users WHERE username = ?", username)
        filename, ext = os.path.splitext(img.filename)

        if not username or not password or not confirmation or not display:
            flash("All fields are required!")
            return render_template("register.html")
        elif len(checkusername) != 0:
            flash("Username already exists!")
            return render_template("register.html")
        elif len(password) < 8:
            flash("Password must contain atleast 8 characters!")
            return render_template("register.html")
        elif password != confirmation:
            flash("Passwords don't match!")
            return render_template("register.html")
        elif ext not in [".png", ".jpg", ".jpeg"]:
            flash("File format not supported!")
            return render_template("register.html")
        else:
            hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)

            img.save(path + username + ext)

            db.execute("INSERT INTO users (username, hash, display, extension) VALUES (?, ?, ?, ?)", username, hash, display, ext)

            return redirect("/login")
    else:
        return render_template("register.html")

@app.route("/profile")
@login_required
def profile():
    userId = session.get("user_id")
    user = db.execute("SELECT * FROM users WHERE id = ?", userId)[0]
    articles = db.execute("SELECT * FROM articles WHERE author_id = ? ORDER BY upper(title)", userId)

    content = ""
    spaces = 0
    for article in articles:
        content = ""
        spaces = 0
        for c in article['content']:
            if c == " ":
                spaces += 1
                if spaces == 15:
                    break
            content += c
        content += "..."
        article['content'] = content
    return render_template("profile.html", user=user, articles=articles)

fields = ["picture", "display", "password"]

@app.route("/change/<field>", methods=["GET", "POST"])
@login_required
def change(field):
    if field not in fields:
        flash("Not a valid field!")
        return redirect("/profile")
    if request.method == "POST":
        if field == "display":
            new = request.form.get("new")
            rows = db.execute("SELECT * FROM users WHERE display = ?", new)
            if not new:
                flash("All fields are required!")
                return redirect("/change/display")
            if len(rows) != 0:
                flash("Display name exists!")
                return redirect("/change/display")
            else:
                db.execute("UPDATE users SET display = ? WHERE id = ?", new, session.get("user_id"))
                flash("Display name changed successfully!")
                return redirect("/profile")
        if field == "picture":
            new = request.files["new"]
            a, ext = os.path.splitext(new.filename)
            if not new:
                flash("All fields are required!")
                return redirect("/change/picture")
            if ext not in [".png", ".jpg", ".jpeg"]:
                flash("File format not supported!")
                return redirect("/change/picture")
            else:
                user = db.execute("SELECT * FROM users WHERE id = ?", session.get("user_id"))[0]
                os.remove(path + user["username"] + user["extension"])
                new.save(path + user["username"] + ext)
                db.execute("UPDATE users SET extension = ? WHERE id = ?", ext, session.get("user_id"))
                flash("Profile picture changed successfully!")
                return redirect("/profile")
        if field == "password":
            old = request.form.get("old")
            new = request.form.get("new")
            confirmation = request.form.get("confirmation")
            if not new or not old or not confirmation:
                flash("All fields are required!")
                return redirect("/change/password")
            hash = db.execute("SELECT hash FROM users WHERE id = ?", session.get("user_id"))[0]['hash']
            if not check_password_hash(hash, old):
                flash("Incorrect password!")
                return redirect("/change/password")
            if len(new) < 8:
                flash("Password must contain atleast 8 characters!")
                return redirect("/change/password")
            if new != confirmation:
                flash("Passwords don't match!")
                return redirect("/change/password")
            else:
                hash = generate_password_hash(new, method="pbkdf2:sha256", salt_length=8)
                db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session.get("user_id"))
                flash("Password changed successfully!")
                return redirect("/profile")

    else:
        display = db.execute("SELECT display FROM users WHERE id = ?", session.get("user_id"))[0]['display']
        return render_template("change.html", field=field, display=display)

@app.route("/write", methods=["GET", "POST"])
@login_required
def write():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")

        if not title or not content:
            flash("All fields required!")
            return redirect("/write")
        else:
            db.execute("INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)", title, content, session.get("user_id"))
            return redirect("/")
    else:
        display = db.execute("SELECT display FROM users WHERE id = ?", session.get("user_id"))[0]['display']
        return render_template("write.html", display=display)

@app.route("/read/<title>/<id>")
@login_required
def article(title, id):
    user_id = session.get("user_id")
    display = db.execute("SELECT display FROM users WHERE id = ?", user_id)[0]['display']
    article = db.execute("SELECT * FROM articles WHERE title = ? AND id = ?", title, id)[0]
    author = db.execute("SELECT display, username FROM users WHERE id = ?", article['author_id'])[0]
    rows = db.execute("SELECT * FROM views WHERE article_id = ? AND user_id = ?", id, user_id)


    if user_id != article['author_id'] and len(rows) == 0:
        db.execute("INSERT INTO views (user_id, article_id) VALUES (?, ?)", user_id, id)

    return render_template("article.html", display=display, article=article, author=author)

@app.route("/authors/<username>")
@login_required
def author(username):
    author = db.execute("SELECT * FROM users WHERE username = ?", username)[0]
    user_id = session.get("user_id")
    if user_id == author['id']:
        return redirect("/profile")
    display = db.execute("SELECT display FROM users WHERE id = ?", user_id)[0]['display']
    articles = db.execute("SELECT * FROM articles WHERE author_id = ? ORDER BY upper(title)", author['id'])

    content = ""
    spaces = 0
    for article in articles:
        content = ""
        spaces = 0
        for c in article['content']:
            if c == " ":
                spaces += 1
                if spaces == 15:
                    break
            content += c
        content += "..."
        article['content'] = content
    return render_template("author.html", author=author, display=display, articles=articles)

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    q = request.args.get("q")
    if not q:
        q = ""
    authors = db.execute("SELECT * FROM users WHERE display LIKE ? AND id != ? ORDER BY upper(display)", "%" + q + "%", session.get("user_id"))
    articles = db.execute("SELECT * FROM articles WHERE title LIKE ? AND author_id != ? ORDER BY upper(title)", "%" + q + "%", session.get("user_id"))
    display = db.execute("SELECT display FROM users WHERE id = ?", session.get("user_id"))[0]['display']

    content = ""
    spaces = 0
    for article in articles:
        content = ""
        spaces = 0
        for c in article['content']:
            if c == " ":
                spaces += 1
                if spaces == 15:
                    break
            content += c
        content += "..."
        article['content'] = content

    return render_template("search.html", authors=authors, articles=articles, display=display, q=q)

@app.route("/read")
@login_required
def read():
    user_id = session.get("user_id")
    display = db.execute("SELECT display FROM users WHERE id = ?", user_id)[0]['display']
    articles = db.execute("SELECT * FROM articles WHERE author_id != ? ORDER BY upper(title)", user_id)

    content = ""
    spaces = 0
    for article in articles:
        content = ""
        spaces = 0
        for c in article['content']:
            if c == " ":
                spaces += 1
                if spaces == 15:
                    break
            content += c
        content += "..."
        article['content'] = content

    return render_template("read.html", display=display, articles=articles)
