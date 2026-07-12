# Node-hud Authenticator integration examples

Public examples for integrating an external application with Node-hud Authenticator.

The examples are intentionally small and framework-light. Each stack has two variants:

- `basic`: validate a user identity with a MFA challenge.
- `complete`: protect a small admin area, create users, generate enrollment invitations, and protect a user area.

## Examples

| Stack | Basic | Complete |
| --- | --- | --- |
| JavaScript fetch | [`examples/js-simple/basic`](examples/js-simple/basic) | [`examples/js-simple/complete`](examples/js-simple/complete) |
| JavaScript Express | [`examples/js-express/basic`](examples/js-express/basic) | [`examples/js-express/complete`](examples/js-express/complete) |
| Python Flask | [`examples/python-flask/basic`](examples/python-flask/basic) | [`examples/python-flask/complete`](examples/python-flask/complete) |
| PHP | [`examples/php/basic`](examples/php/basic) | [`examples/php/complete`](examples/php/complete) |

## Authenticator API used by the examples

Basic examples use:

- `POST /api/challenges`
- `GET /api/challenges/:id`

Complete examples also use:

- `GET /api/enrollments/new?tenant=<tenantId>&user=<email>`

## Common environment

Copy the `.env.example` file from an example directory to `.env`, then fill in the values created in your Authenticator tenant admin.

```env
AUTH_SERVER_URL=https://mfa.node-hub.com
AUTH_APP_TOKEN=<tenant application token>
AUTH_TENANT_ADMIN_TOKEN=<tenant admin token, complete examples only>
AUTH_TENANT_ID=<tenant id, complete examples only>
AUTH_USER_HINT=demo@example.local
AUTH_ADMIN_USER_HINT=admin@example.local
```

Never publish real tokens in this repository.
