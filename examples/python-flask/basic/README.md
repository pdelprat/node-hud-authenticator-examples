# Python Flask basic example

Small Flask server with one protected page.

## Run

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask --app app run --port 4022
```

Open `http://localhost:4022`.
