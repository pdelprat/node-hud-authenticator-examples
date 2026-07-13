# PHP complete example

Single-file PHP example for classic hosting:

- admin MFA;
- local user creation for an already enrolled Authenticator identity;
- enrollment invitation for a new Authenticator identity;
- public invite page;
- user MFA.

In the admin page, use **Add existing enrolled user** when the email is already enrolled in the same tenant. Use **Create user and enrollment invite** only when the person needs a new device enrollment.

## Run locally

```sh
cp .env.example .env
php -S localhost:4027 index.php
```

Open `http://localhost:4027`.
