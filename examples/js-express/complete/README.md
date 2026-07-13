# JavaScript Express complete example

Express version of the complete integration flow:

- admin MFA;
- local user creation for an already enrolled Authenticator identity;
- enrollment invitation for a new Authenticator identity;
- public invite page;
- user MFA.

In the admin page, use **Add existing enrolled user** when the email is already enrolled in the same tenant. Use **Create user and enrollment invite** only when the person needs a new device enrollment.

## Run

```sh
cp .env.example .env
npm install
npm start
```

Open `http://localhost:4025`.
