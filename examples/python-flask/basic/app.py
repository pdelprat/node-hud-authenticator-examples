import os
import time
from pathlib import Path

import requests
from flask import Flask, redirect, render_template_string, request, session, url_for

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.environ.get("AUTH_APP_TOKEN", "change-me"))

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "https://mfa.node-hub.com").rstrip("/")
AUTH_APP_TOKEN = os.environ.get("AUTH_APP_TOKEN")
AUTH_USER_HINT = os.environ.get("AUTH_USER_HINT", "demo@example.local")


@app.get("/")
def home():
    return page("<h1>Flask basic</h1><p><a href='/protected'>Open protected page</a></p>")


@app.route("/protected", methods=["GET", "POST"])
def protected():
    if session.get("mfa_ok"):
        return page("<h1>Protected page</h1><p>Access granted.</p><p><a href='/logout'>Logout</a></p>")

    if request.method == "POST":
        user_hint = request.form["user_hint"].strip().lower()
        challenge = create_challenge(user_hint, "Flask basic /protected")
        return redirect(url_for("protected", challenge=challenge["id"], user=user_hint))

    challenge_id = request.args.get("challenge")
    if challenge_id:
        challenge = get_challenge(challenge_id)
        status = challenge["status"]

        if status == "approved":
            session["mfa_ok"] = True
            session["user_hint"] = request.args.get("user")
            return redirect(url_for("protected"))

        if status in ("denied", "expired"):
            return page(f"<h1>Access refused</h1><p>Status: <code>{escape(status)}</code></p><p><a href='/protected'>Retry</a></p>")

        number = challenge.get("numberMatch")
        number_html = f"<p>Confirm this number: <strong>{escape(number)}</strong></p>" if number else ""
        return page(f"<h1>MFA required</h1>{number_html}<p>Status: <code>{escape(status)}</code></p><script>setTimeout(() => location.reload(), 2000)</script>")

    return page(
        f"""
        <h1>Protected page</h1>
        <form method="post">
          <label>Email <input name="user_hint" type="email" value="{escape(AUTH_USER_HINT)}" required></label>
          <button type="submit">Request access</button>
        </form>
        """
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


def create_challenge(user_hint, resource):
    if not AUTH_APP_TOKEN:
        raise RuntimeError("AUTH_APP_TOKEN is required.")

    response = requests.post(
        f"{AUTH_SERVER_URL}/api/challenges",
        headers={"Authorization": f"Bearer {AUTH_APP_TOKEN}"},
        json={
            "userHint": user_hint,
            "resource": resource,
            "mode": "push_with_number",
            "location": "Flask basic",
            "ipAddress": request.headers.get("X-Forwarded-For", request.remote_addr),
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["challenge"]


def get_challenge(challenge_id):
    response = requests.get(f"{AUTH_SERVER_URL}/api/challenges/{challenge_id}", timeout=10)
    response.raise_for_status()
    return response.json()["challenge"]


def page(body):
    return render_template_string(
        "<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Flask basic</title><body>{{ body|safe }}</body></html>",
        body=body,
    )


def escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#039;")


def load_dotenv():
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))
