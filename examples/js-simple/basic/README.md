# JavaScript fetch basic example

Minimal command-line example using only Node.js `fetch`.

## Run

```sh
cp .env.example .env
node index.mjs demo@example.local
```

The script creates a MFA challenge, displays the number matching value when present, then polls until the challenge is approved, denied, or expired.
