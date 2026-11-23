# Security

Night Desk is pre-alpha software. Only the newest release and the `main` branch get fixes.

## Reporting a problem

Please report security problems privately, not in a public issue.

1. Open this repository's **Security** tab on GitHub.
2. Choose **Report a vulnerability** (GitHub's private vulnerability reporting).
3. Say what you found, which version or commit, and the steps that show it.

Leave out real data from your own network: addresses, host names, logs and screenshots of your dashboard. A
made-up example that shows the problem is enough.

You'll get an answer when the report has been read, and a fix or a decision with the reason. This is a small
project, so there is no fixed response time.

## What counts

In scope: the Night Desk app (the `osinthub` package and its web client), the local AI helper, the one-line
installer (`deploy/install.sh`), the Docker Compose setup and its Caddy configuration.

Out of scope: problems in the data sources themselves, and anything that needs the password or a shell on the machine
that runs Night Desk, since those already give full control (see below).

## How Night Desk is meant to be run

* **This computer only, by default.** The app listens on `127.0.0.1`. It refuses to listen on any other address
  unless a password is set (`OSINTHUB_PASSWORD`, or the Caddy sign-in that the installer sets up for local-network
  use).
* **One password, full control.** There are no user accounts. Anyone with the password can do everything the app
  can do, so share it only with people you trust with your data.
* **Plain HTTP can be read on the wire.** Use the HTTPS address from the Docker install, or keep a native run on
  this computer.
* **The SQL console is off** unless Night Desk is started with `OSINTHUB_SQL_CONSOLE=1`. When it is on, it can read
  only Night Desk's own data folder.
* **Offline mode** (`OSINTHUB_OFFLINE=1`) makes no network connections at all.
* **Your data stays on your machine.** Night Desk sends no telemetry. It contacts only the data sources you turn on,
  the article pages it reads for news, and the download sites for the reference files it needs (IP locations and
  country shapes).

The full security model, the protections in the code and the known limits are in
[`okf/architecture/deployment.md`](okf/architecture/deployment.md#security-model-and-hardening).
