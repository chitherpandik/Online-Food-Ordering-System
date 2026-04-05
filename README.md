# Project backend

1. Copy `.env.example` to `.env` and fill DB credentials.
2. Install dependencies:

```bash
npm install
```

3. Run server:

```bash
npm start
```

The server serves static files from the project root and exposes:
- `POST /api/register` { fullname, email, password }
- `POST /api/login` { email, password }

Make sure `create_db.sql` has been executed (it creates `project_db` and `users` table).
