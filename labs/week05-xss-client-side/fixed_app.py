"""Secure version — Week 5 XSS. Shows escaping, CSP, and hardened cookies."""
from flask import Flask, request, Response, render_template_string
from markupsafe import escape
import hmac
import secrets

app = Flask(__name__)

COMMENTS = []
# FIX CWE-352: one CSRF token per session id, kept server-side.
CSRF_TOKENS = {}


def secure(resp: Response) -> Response:
    # FIX CWE-79: strict Content-Security-Policy blocks inline/injected script execution.
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # FIX CWE-79: contextual output encoding — escape() neutralizes <, >, &, etc.
    html = "<h1>Hello, " + str(escape(name)) + "!</h1>"
    return secure(Response(html, mimetype="text/html"))


@app.route("/comments", methods=["GET", "POST"])
def comments():
    sid = request.cookies.get("session", "")
    if request.method == "POST":
        # FIX CWE-352: only accept a POST that carries the session cookie AND the
        # CSRF token we issued for it. A forged cross-site form has neither (SameSite=Strict
        # drops the cookie, and the attacker's page can't read our token).
        sent = request.form.get("csrf_token", "")
        expected = CSRF_TOKENS.get(sid)
        if not sid or not expected or not hmac.compare_digest(sent, expected):
            return secure(Response("CSRF check failed\n", status=403, mimetype="text/plain"))
        COMMENTS.append(request.form.get("body", ""))
    token = CSRF_TOKENS.setdefault(sid, secrets.token_urlsafe(32)) if sid else ""
    # FIX CWE-79: Jinja autoescaping renders stored comments as text, not markup.
    tmpl = """<h2>Comments</h2>
    <form method=post><input type=hidden name=csrf_token value="{{ token }}"><input name=body><input type=submit value=Post></form><hr>
    {% for c in comments %}<div class=comment>{{ c }}</div>{% endfor %}"""
    page = render_template_string(tmpl, comments=COMMENTS, token=token)
    return secure(Response(page, mimetype="text/html"))


@app.route("/")
def index():
    resp = Response("<a href=/hello?name=you>hello</a> | <a href=/comments>comments</a>",
                    mimetype="text/html")
    # FIX: HttpOnly stops JS from reading the cookie; SameSite curbs cross-site send; Secure for HTTPS.
    resp.set_cookie("session", "abc123", httponly=True, samesite="Strict", secure=True)
    return secure(resp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
