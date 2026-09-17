# Ripple — private one-to-one messenger

Ripple is a complete small messaging website with its own Node.js server. It uses no third-party API, Supabase project, database account, or npm dependency.

Features:

- multi-page website architecture with real URL routes and automatic redirection
- account creation and password login (`/login`)
- forgot / reset password flow (`/forgot-password`)
- home messages and chat interface (`/` and `/?chat=:id`)
- user discovery and search (`/discover`)
- incoming and outgoing connection requests (`/requests`)
- user profile and password management (`/profile`)
- searchable usernames
- a request/accept flow before a conversation exists
- strictly one-to-one conversations; there is no group model or group UI
- text, image, video, and audio messages (up to 25 MB each)
- emoji picker
- private media routes: only a participant in the matching conversation can open shared media


## Run locally

Install [Node.js 18 or later](https://nodejs.org/), then open a terminal in this folder and run:

```powershell
npm start
```

Open [http://localhost:3000](http://localhost:3000). Create two accounts in separate browser profiles/incognito windows to test the request and chat flow.

The server stores users, conversations, and messages in `data/messenger.json`. Uploaded files are stored in `data/uploads`. Back these folders up before moving the app to a different computer.

## Easiest deployment: Railway

For a small group of friends, Railway is the least fiddly option because its dashboard lets you deploy the repository and attach persistent storage in one place. It requires no API key and no third-party database.

1. Push this folder to a private GitHub repository.
2. Create a [Railway](https://railway.app/) account and choose **New Project → Deploy from GitHub Repo**.
3. Select the repository. Railway detects Node and uses `npm start`.
4. Add a **Volume**, mount it at `/app/data`, and add the Railway variable `DATA_DIR=/app/data`.
5. In **Settings → Networking**, generate a public domain and share that HTTPS link with friends.

The volume matters: it retains accounts, messages, and uploaded media when the service restarts or redeploys. Keep this as one service/one volume; the app is deliberately designed for a small private group, not horizontal scaling.

## Alternative: Render

This route does not need API keys or a database integration.

1. Create a GitHub repository and push this folder to it.
2. Create a free [Render](https://render.com/) account and choose **New → Blueprint**.
3. Connect the repository and approve the detected `render.yaml` file.
4. Render builds and starts the app. Open the URL it gives you.

For a real public app, add a Render persistent disk mounted at the project root (or use a paid host with persistent storage). Free web services have temporary disk storage, so account and media data can disappear after a redeploy/restart. This project intentionally needs no API keys, but production-scale messaging should eventually use a managed database and object storage.
