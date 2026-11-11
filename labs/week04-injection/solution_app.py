"""Secure version — Week 4 Injection. Shows the fixes for the flaws in vulnerable_app.py."""
import os
import sqlite3
import subprocess
from flask import Flask, request, g

app = Flask(__name__)
DB = "/tmp/week04_fixed.db"
UPLOAD_DIR = "/tmp/uploads_fixed"
ALLOWED_EXT = {".txt", ".png", ".jpg", ".pdf"}  # FIX CWE-434: extension allow-list
os.makedirs(UPLOAD_DIR, exist_ok=True)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
    return g.db


@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def seed():
    con = sqlite3.connect(DB)
    con.execute("DROP TABLE IF EXISTS users")
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    con.executemany("INSERT INTO users (username, password) VALUES (?, ?)",
                    [("alice", "alicepw"), ("bob", "bobpw")])
    con.commit()
    con.close()


@app.route("/")
def index():
    return (
        "Week 4 — Injection lab (FIXED)\n"
        "Endpoints:  /login?user=&pw=   /search?q=   /ping?host=   /upload\n"
        "The same payloads from the vulnerable app should now fail.\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.route("/login")
def login():
    user = request.args.get("user", "")
    pw = request.args.get("pw", "")
    # FIX CWE-89: parameterized query — input is bound, never concatenated.
    row = db().execute(
        "SELECT id, username FROM users WHERE username = ? AND password = ?", (user, pw)
    ).fetchone()
    return ("Welcome %s\n" % row[1]) if row else "Login failed\n"


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # FIX CWE-89: bind the LIKE pattern as a parameter.
    rows = db().execute(
        "SELECT id, username FROM users WHERE username LIKE ?", ("%" + term + "%",)
    ).fetchall()
    return "\n".join("%s:%s" % r for r in rows) + "\n"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX CWE-78: no shell; pass an argument array so input can't be interpreted as a command.
    # FIX: validate input against an allow-list pattern as defence in depth.
    import re
    # FIX CWE-88: host must start with a letter/digit, and "--" ends option parsing,
    # so input like "-h" can't be read by ping as a flag.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        return "invalid host\n", 400
    out = subprocess.run(["ping", "-c", "1", "--", host], shell=False, capture_output=True, text=True)
    return "<pre>%s</pre>" % (out.stdout + out.stderr)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return '<form method=post enctype=multipart/form-data><input type=file name=f><input type=submit></form>'
    f = request.files["f"]
    # FIX CWE-434: sanitize the name and enforce an extension allow-list.
    from werkzeug.utils import secure_filename
    name = secure_filename(f.filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        return "file type not allowed\n", 400
    dest = os.path.join(UPLOAD_DIR, name)
    f.save(dest)
    return "saved to %s\n" % dest


if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=5000, debug=False)
