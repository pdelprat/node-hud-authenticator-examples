import json
import os
import secrets
import uuid
from pathlib import Path

import requests
from flask import Flask, redirect, render_template_string, request, session, url_for

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.environ.get("AUTH_APP_TOKEN", "change-me"))

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "https://mfa.node-hub.com").rstrip("/")
AUTH_APP_TOKEN = os.environ.get("AUTH_APP_TOKEN")
AUTH_TENANT_ADMIN_TOKEN = os.environ.get("AUTH_TENANT_ADMIN_TOKEN")
AUTH_TENANT_ID = os.environ.get("AUTH_TENANT_ID", "default")
AUTH_ADMIN_USER_HINT = os.environ.get("AUTH_ADMIN_USER_HINT", "admin@example.local")
DATA_PATH = Path(os.environ.get("DATA_PATH", ".data/users.json"))


@app.get("/")
def home():
    return page("<h1>Flask complete</h1><p><a href='/admin'>Admin</a> - <a href='/app'>User app</a></p>")


@app.route("/admin", methods=["GET"])
def admin():
    if session.get("admin_ok"):
        return redirect(url_for("admin_users"))

    challenge_id = request.args.get("challenge")
    if not challenge_id:
        return page(f"<h1>Admin access</h1><p><code>{escape(AUTH_ADMIN_USER_HINT)}</code></p><form method='post' action='/admin/start'><button>Request access</button></form>")

    challenge = get_challenge(challenge_id)
    if challenge["status"] == "approved":
        session["admin_ok"] = True
        return redirect(url_for("admin_users"))

    return page(render_challenge(challenge, "/admin"))


@app.post("/admin/start")
def admin_start():
    challenge = create_challenge(AUTH_ADMIN_USER_HINT, "Flask complete admin")
    return redirect(url_for("admin", challenge=challenge["id"]))


@app.get("/admin/logout")
def admin_logout():
    session.pop("admin_ok", None)
    return redirect(url_for("home"))


@app.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    if not session.get("admin_ok"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        name = request.form["name"].strip()
        users = read_users()
        if any(user["email"] == email for user in users):
            return page("<h1>User already exists</h1>"), 409

        enrollment_url = create_enrollment(email)
        token = secrets.token_urlsafe(32)
        users.append({
            "id": str(uuid.uuid4()),
            "email": email,
            "name": name,
            "status": "invited",
            "token": token,
            "enrollmentUrl": enrollment_url,
        })
        write_users(users)
        return redirect(url_for("admin_invite", token=token))

    rows = "".join(
        f"<tr><td>{escape(user['email'])}</td><td>{escape(user['name'])}</td><td>{escape(user['status'])}</td><td><a href='/admin/invite/{escape(user['token'])}'>Invite</a></td></tr>"
        for user in read_users()
    )
    return page(f"<h1>Users</h1><p><a href='/admin/logout'>Logout</a></p><form method='post'><input name='email' type='email' placeholder='email' required> <input name='name' placeholder='name' required> <button>Create + enroll</button></form><table>{rows}</table>")


@app.get("/admin/invite/<token>")
def admin_invite(token):
    if not session.get("admin_ok"):
        return redirect(url_for("admin"))

    user = find_user_by_token(token)
    if not user:
        return page("<h1>Invite not found</h1>"), 404

    invite_url = request.url_root.rstrip("/") + url_for("invite", token=token)
    return page(f"<h1>Invitation</h1><p>User: <code>{escape(user['email'])}</code></p><p><a href='{escape(invite_url)}'>{escape(invite_url)}</a></p>")


@app.get("/invite/<token>")
def invite(token):
    user = find_user_by_token(token)
    if not user:
        return page("<h1>Invite not found</h1>"), 404

    qr = "https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=" + requests.utils.quote(user["enrollmentUrl"], safe="")
    return page(f"<h1>Invite {escape(user['name'])}</h1><p>Scan this enrollment QR code.</p><p><img src='{qr}' width='280' height='280' alt='Enrollment QR'></p><p><a href='/app?user={escape(user['email'])}'>Open app</a></p>")


@app.route("/app", methods=["GET"])
def user_app():
    if session.get("user_email"):
        return page(f"<h1>User app</h1><p>Access granted for <code>{escape(session['user_email'])}</code>.</p><p><a href='/app/logout'>Logout</a></p>")

    challenge_id = request.args.get("challenge")
    email = request.args.get("user", "")
    if challenge_id and email:
        challenge = get_challenge(challenge_id)
        if challenge["status"] == "approved":
            activate_user(email)
            session["user_email"] = email
            return redirect(url_for("user_app"))
        return page(render_challenge(challenge, "/app"))

    return page(f"<h1>User access</h1><form method='post' action='/app/start'><input name='email' type='email' value='{escape(email)}' required> <button>Request access</button></form>")


@app.post("/app/start")
def user_app_start():
    email = request.form["email"].strip().lower()
    if not find_user_by_email(email):
        return page("<h1>User not found</h1>"), 404

    challenge = create_challenge(email, "Flask complete user app")
    return redirect(url_for("user_app", challenge=challenge["id"], user=email))


@app.get("/app/logout")
def user_logout():
    session.pop("user_email", None)
    return redirect(url_for("home"))


def create_challenge(user_hint, resource):
    if not AUTH_APP_TOKEN:
        raise RuntimeError("AUTH_APP_TOKEN is required.")

    response = requests.post(
        f"{AUTH_SERVER_URL}/api/challenges",
        headers={"Authorization": f"Bearer {AUTH_APP_TOKEN}"},
        json={"userHint": user_hint, "resource": resource, "mode": "push_with_number", "location": "Flask complete"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["challenge"]


def get_challenge(challenge_id):
    response = requests.get(f"{AUTH_SERVER_URL}/api/challenges/{challenge_id}", timeout=10)
    response.raise_for_status()
    return response.json()["challenge"]


def create_enrollment(email):
    if not AUTH_TENANT_ADMIN_TOKEN:
        raise RuntimeError("AUTH_TENANT_ADMIN_TOKEN is required.")

    response = requests.get(
        f"{AUTH_SERVER_URL}/api/enrollments/new",
        params={"tenant": AUTH_TENANT_ID, "user": email},
        headers={"Authorization": f"Bearer {AUTH_TENANT_ADMIN_TOKEN}"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["enrollmentUrl"]


def read_users():
    if not DATA_PATH.exists():
        return []
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def write_users(users):
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATA_PATH.write_text(json.dumps(users, indent=2) + "\n", encoding="utf-8")


def find_user_by_token(token):
    return next((user for user in read_users() if user.get("token") == token), None)


def find_user_by_email(email):
    return next((user for user in read_users() if user.get("email") == email and user.get("status") != "disabled"), None)


def activate_user(email):
    users = read_users()
    for user in users:
        if user["email"] == email and user["status"] == "invited":
            user["status"] = "active"
            write_users(users)
            return


def render_challenge(challenge, retry_path):
    number = challenge.get("numberMatch")
    number_html = f"<p>Confirm: <strong style='font-size:42px'>{escape(number)}</strong></p>" if number else ""
    return f"<h1>MFA required</h1>{number_html}<p>Status: <code>{escape(challenge['status'])}</code></p><script>setTimeout(() => location.reload(), 2000)</script><p><a href='{retry_path}'>Cancel</a></p>"


def page(body):
    return render_template_string("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Flask complete</title><body>{{ body|safe }}</body></html>", body=body)


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
