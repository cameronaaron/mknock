# Knock

> **Out‑of‑band room invites for Matrix / Beeper – *because good doors deserve a knock***

Knock is a micro‑service that lets people request to join a private Matrix room **without exposing the room address or relying on admins being online**. Think of it as the digital equivalent of knocking on a closed door: the “knock” (invite request) happens out‑of‑band via a simple webhook form, while Knock takes care of validating, rate‑limiting, and delivering the Matrix invite on your behalf.

---

## ✨ Features

| Feature                        | Description                                                                                                 |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| **Out‑of‑band requests**       | Accepts webhook calls from forms (e.g. Tally, Typeform) so users never see the real room ID.                |
| **Fuzzy block‑list**           | Prevents ban evasion by detecting leet‑speak and numeric variants of blocked user IDs.                      |
| **Rate‑limiting & spam traps** | Keeps trolls and bots at bay with honeypot fields, sliding‑window request limits, and exponential back‑off. |
| **Pending‑invite tracker**     | Reminds latecomers, rescinds stale invites, and sends a personalised welcome message once they join.        |
| **Background watchdogs**       | Periodically scans joined members and pending invites to enforce your block‑list.                           |
| **Single‑sign‑on with Beeper** | Uses Beeper’s private JWT flow to obtain a Matrix access‑token, then caches it to disk.                     |
| **Fully async**                | Built on FastAPI + httpx + asyncio; can handle thousands of concurrent knocks on modest hardware.           |

---

## Table of Contents

1. [Architecture](#architecture)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Running](#running)
5. [API Reference](#api-reference)
6. [Background Tasks](#background-tasks)
7. [Security Notes](#security-notes)
8. [Contributing](#contributing)
9. [Roadmap](#roadmap)
10. [License](#license)

---

## Architecture

```
          ┌───────────────┐        (1) webhook
User ───▶ │  Form (Tally) │ ──────────────────┐
          └───────────────┘                   │
                                             ▼
                                        ┌─────────┐   HTTP  ❱❱❱❱❱
                                        │ Knock   │──────────────────┐
                                        │ FastAPI │                  │
                                        └─────────┘                  │
                               async tasks ▲  ▲ background   Matrix  │
                                            │  │                API  │
                                            │  │                      ▼
                              block‑list ✔  │  │ welcome msg ✔   ┌────────────┐
                                            │  │ invite / kick ✔  │    Room    │
                                            ▼  ▼                      └────────────┘
                              JSON / txt on disk (tokens, block‑list, pending‑invites)
```

* **Invite flow:**

  1. User submits matrix ID in a public form.
  2. Form platform POSTs to `/invite_from_form`.
  3. Knock validates, spam‑checks, and (if allowed) calls Matrix `/invite`.
  4. Once the user joins, Knock sends them a friendly welcome message.
* **Admin actions:**

  * `/block_user`, `/unblock_user`, `/rescind_invite` allow real‑time moderation.
  * CSV‑style files on disk keep state across restarts.

---

## Quick Start

### 1. Clone & configure

```bash
git clone https://github.com/your‑org/knock.git && cd knock
cp .env.example .env # then edit values
```

### 2. Run with Docker Compose

```bash
docker compose up -d
```

The service will be available on **[http://localhost:8000](http://localhost:8000)**.

### 3. Point your form

Add a form integration that POSTs its payload (unchanged!) to

```
POST http://localhost:8000/invite_from_form
```

That’s it – start sharing the form link instead of your room ID.

---

## Configuration

All configuration happens through **environment variables**; a `dotenv` file is recommended for local dev.

| Variable             | Required | Default                     | Description                                                    |
| -------------------- | -------- | --------------------------- | -------------------------------------------------------------- |
| `NEW_ROOM_ID`        | ✔︎       | —                           | Matrix room ID to invite users to (e.g. `!abcdef:beeper.com`). |
| `BEEPER_API_BASE`    |          | `https://api.beeper.com`    | Base URL for Beeper private API.                               |
| `MATRIX_BASE_URL`    |          | `https://matrix.beeper.com` | Base URL of your homeserver.                                   |
| `BEEPER_LOGIN_EMAIL` | ✔︎\*     | —                           | Email for Beeper account.                                      |
| `BEEPER_LOGIN_CODE`  | ✔︎\*     | —                           | 6‑digit login code (set once during deployment).               |
| `API_KEY`            |          | —                           | Optional bearer token securing admin endpoints.                |
| `REQUEST_DELAY`      |          | `0.5`                       | Seconds between outbound HTTP calls.                           |
| `BLOCKLIST_FILE`     |          | `blocked_users.txt`         | Path where blocked MXIDs are stored.                           |

\* *If you already have long‑lived tokens you can instead set `BEEPER_LOGIN_TOKEN` and `MATRIX_ACCESS_TOKEN` and skip the email flow.*

See [`docs/env_vars.md`](docs/env_vars.md) for the full matrix.

---

## Running

### Development

```bash
uvicorn mknock:app --reload --port 8000
```

### Production (systemd excerpt)

```ini
[Service]
EnvironmentFile=/opt/knock/.env
ExecStart=/usr/local/bin/uvicorn mknock:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
```

Health‑check endpoint: `GET /` → `{"status":"running"}`

---

## API Reference

| Method | Path                | Auth?    | Purpose                                   |
| ------ | ------------------- | -------- | ----------------------------------------- |
| `GET`  | `/`                 | No       | Simple health probe.                      |
| `POST` | `/invite_from_form` | Optional | Process a form payload & invite user.     |
| `POST` | `/block_user`       | Bearer   | Add user to block‑list and kick.          |
| `POST` | `/unblock_user`     | Bearer   | Remove user from block‑list.              |
| `POST` | `/rescind_invite`   | Bearer   | Cancel a pending invite & kick if joined. |
| `GET`  | `/blocklist`        | Bearer   | Current block‑list.                       |
| `GET`  | `/pending_invites`  | Bearer   | Users still deciding whether to join.     |
| `GET`  | `/room_members`     | Bearer   | List of current members.                  |
| `GET`  | `/room_state`       | Bearer   | Raw room state snapshot (debug).          |

All admin endpoints expect `Authorization: Bearer <API_KEY>` if `API_KEY` is set.

---

## Background Tasks

| Task                | Interval | What it does                                                              |
| ------------------- | -------- | ------------------------------------------------------------------------- |
| **Invite checker**  | 5 min    | Welcomes new joiners; rescinds invites > 7 days; prunes block‑listed IDs. |
| **Block‑list scan** | 10 min   | Iterates all joined members; kicks or bans those on the list.             |

Both tasks run inside the same process – no external workers needed.

---

## Security Notes

* **Bearer auth** – Set `API_KEY` to protect moderation endpoints.
* **Stored credentials** – Tokens are cached unencrypted in `tokens.json`; use file permissions or secrets mounts.
* **Rate limits** – Adjust `REQUEST_DELAY`, `MAX_REQUESTS_PER_WINDOW`, etc. to suit your traffic.
* **Spoof protection** – The invite flow validates that the MXID exists on the homeserver and matches a regex.

---

## Contributing

1. Fork the repo & create a branch.
2. Run `make lint && make test` – tests must pass.
3. Submit a pull‑request; describe *why* the change is needed.
4. Keep commits small & focused.


---

## Roadmap

* [ ] Web UI for moderators.
* [ ] Redis / Postgres back‑ends (replace JSON + txt).
* [ ] Helm chart for Kubernetes.
* [ ] Support for non‑Beeper homeservers.
