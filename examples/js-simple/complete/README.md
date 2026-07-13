# JavaScript no-framework complete example

Complete example using only Node.js built-ins:

- admin access protected by MFA;
- local user creation for an already enrolled Authenticator identity;
- enrollment invitation generation for a new Authenticator identity;
- public invite page with a QR code;
- user access protected by MFA.

In the admin page, use **Add existing enrolled user** when the email is already enrolled in the same tenant. Use **Create user and enrollment invite** only when the person needs a new device enrollment.

## Run

```sh
cp .env.example .env
node server.mjs
```

Open `http://localhost:4024`.
