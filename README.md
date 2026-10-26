# Taskboard — clean source snapshot

**Source archived; run not verified.** Original academic program/deployment provenance is unconfirmed. Node/Express/EJS, Mongoose/MongoDB sessions and bcrypt; source implements signup/login, workspace membership/invitations, tasks/priorities and notifications.

This fresh source snapshot excludes the tracked legacy database, .env, original Git history and deployment workflows. Exposed session fallback and private Lambda function configuration were removed. This does **not** remediate historical exposure in projects-portfolio: its tracked account database and historical credential-bearing environment files still require a separate owner-approved response.

**Cloud behavior remains in code:** server.js invokes emailService.js for authentication/workspace/task flows; AWS SDK uses the default credential chain. An alternate HTTP helper reads EMAIL_LAMBDA_URL. Blank example settings are not a verified no-send mode. Do not run with real AWS credentials/accounts/recipients; isolate or mock outbound email before a demo. No cloud service or account tested.

Declared runtime Node >=18/npm >=9; actual dependency compatibility/run unverified. Known manifest setup: `npm ci`, then `npm start`, only after deliberately safe local MongoDB/session/email configuration. .env.example is synthetic/local-only guidance, not a working service config. No auth-security or deployment certification. Existing public legacy source URLs are not changed by this snapshot.
