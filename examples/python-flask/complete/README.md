# Python Flask complete example

Complete Flask integration flow:

- admin MFA;
- local user creation for an already enrolled Authenticator identity;
- enrollment invitation for a new Authenticator identity;
- public invite page;
- user MFA.

In the admin page, use **Add existing enrolled user** when the email is already enrolled in the same tenant. Use **Create user and enrollment invite** only when the person needs a new device enrollment.

## Run

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask --app app run --port 4026
```

Open `http://localhost:4026`.
