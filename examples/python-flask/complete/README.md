# Python Flask complete example

Complete Flask integration flow:

- admin MFA;
- user creation;
- enrollment invitation;
- public invite page;
- user MFA.

## Run

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask --app app run --port 4026
```

Open `http://localhost:4026`.
