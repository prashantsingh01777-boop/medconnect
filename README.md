# MedConnect

MedConnect is a self-hosted medicine-schedule tracker with a limited, rule-based health-information assistant. It is not a medical provider, emergency dispatch service, or guaranteed reminder service.

## Public deployment (Docker Compose)

The production stack runs the app as a non-root container, keeps SQLite on a named persistent volume, and places Caddy in front for automatic HTTPS. It assumes a Linux server/VPS with a public IP address. This repository does **not** create a hosting account, register a domain, configure DNS, or deploy itself.

### Run the Docker app on this Windows PC with the existing Cloudflare Quick Tunnel

This option keeps the app in Docker while Cloudflare supplies a temporary public URL. Docker Desktop, Python (for the one-time database copy), and `cloudflared` must be installed. The supervisor starts Docker Desktop at sign-in if needed and waits for the Engine before starting the container. The PC must stay awake and online; a Quick Tunnel URL can change when its connection is recreated, and Cloudflare offers no uptime guarantee for Quick Tunnels.

Create `%LOCALAPPDATA%\MedConnect\docker-tunnel.env` with a private, persistent secret and the support contact shown on the legal pages:

```dotenv
MEDCONNECT_SECRET_KEY=replace-with-at-least-64-random-hex-characters
MEDCONNECT_SUPPORT_EMAIL=your-monitored-support-address
MEDCONNECT_GMAIL_ADDRESS=your-gmail-address@gmail.com
MEDCONNECT_GMAIL_APP_PASSWORD=your-16-character-google-app-password
```

Generate the secret with `python -c "import secrets; print(secrets.token_hex(32))"`. For Gmail, enable 2-Step Verification on the sender account and create an App Password at `https://myaccount.google.com/apppasswords`; use that App Password, not your normal Gmail password. Password-reset emails will not send until both Gmail settings are configured. Keep this file private. After changing it, recreate the app container so it reads the new settings:

```powershell
$environmentFile = Join-Path $env:LOCALAPPDATA 'MedConnect\docker-tunnel.env'
docker compose --project-name medconnect-tunnel --env-file $environmentFile -f .\compose.tunnel.yaml up -d --force-recreate app
```

Caregiver alerts require a Twilio account and incur messaging charges. Add `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_SMS_FROM`, `TWILIO_WHATSAPP_FROM`, and `TWILIO_WHATSAPP_CONTENT_SID` to the same private `docker-tunnel.env` before recreating the app. Use a Twilio SMS-capable sender and an approved WhatsApp sender. Submit and approve a WhatsApp template with these three variables: `{{1}}` the account holder's name, `{{2}}` the scheduled time, and `{{3}}` the 15-minute delay. A template body can be: `MedConnect: {{1}}'s medicine dose scheduled for {{2}} was not marked as taken {{3}} minutes after the alarm. Please check with them. Not emergency monitoring.` Configure the WhatsApp sender as `whatsapp:+<number>` and set the approved template's Content SID. Keep all Twilio credentials private.

The `start_medconnect_docker.ps1` supervisor runs the app container and restarts the Quick Tunnel after failures. The Windows Task Scheduler entry named **MedConnect Public Tunnel** is configured to run that script at sign-in and continue on battery.

The Docker setup uses a separate named data volume. The existing `medconnect.db` was copied into that volume using SQLite's online backup API, preserving its accounts, medicines, and dose history. Do not initialize a fresh empty volume if you need those records. The Windows startup task's previous native-Python version used port 5101; the Docker Quick Tunnel uses port 5103.

### Before deployment

1. Choose a server and domain that you control. Point the domain's `A` record to the server's public IPv4 address. Configure an `AAAA` record only if the server has working public IPv6. Allow inbound TCP ports 80 and 443 (and UDP 443 for HTTP/3) in the server firewall and hosting-provider firewall.
2. Install Docker Engine and the Docker Compose plugin on that server.
3. Configure an email address for support/privacy requests. Update `templates/privacy.html` and `templates/terms.html` and have both notices reviewed for the countries where people will use the service. They are starter notices, not legal advice or a compliance certification. Consider qualified privacy/health-law review before collecting real patient information.
4. Decide how long production and off-site backups will be retained, who can access them, and how they will be securely removed. The included backup script keeps local backups for 30 days; it does not encrypt or copy them off the server.

### Configure and start

From the project directory on the server:

```sh
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Edit `.env` and set your real `MEDCONNECT_DOMAIN`, `ACME_EMAIL`, `MEDCONNECT_SUPPORT_EMAIL`, and the generated `MEDCONNECT_SECRET_KEY`. Keep `.env` private and out of source control. The Gmail variables are optional, but password-reset email will not work until a Gmail sender and app password are configured.

On the Linux host, start the stack:

```sh
docker compose config --quiet
docker compose up -d --build
docker compose ps
```

Verify `https://YOUR_DOMAIN/healthz` returns `{"status":"ok"}` and open the site on a phone. Caddy obtains and renews the TLS certificate; the domain must already resolve to the server and ports 80/443 must be reachable. Docker's `restart: unless-stopped` restarts containers after server reboots while Docker is enabled.

### Data, updates, and backups

- The live SQLite database is in the `medconnect-data` Docker volume. Do not remove that volume when updating the app. This SQLite deployment is for a **single app instance**; do not scale it horizontally. For multiple instances or substantial traffic, migrate to a managed database and re-evaluate the rate-limit storage before scaling.
- Before updating, create and copy a backup somewhere safe. The Windows helper `.\backup.ps1` copies a consistent SQLite backup into `backups\`, removes local copies older than 30 days, and requires Docker Compose to be running. Schedule it with Task Scheduler or run an equivalent SQLite online backup on the server. Copy backups off-host and encrypt them using your organization's key-management process.
- Test restoring a backup to a separate, non-public test deployment before relying on it. A backup contains account emails and medicine information and must be protected like production data.
- Update with `docker compose up -d --build`; then check `docker compose ps`, `/healthz`, sign-in, data deletion, and the public site. Review `docker compose logs --tail=100 app caddy` without sharing logs that could contain sensitive operational information.

## Privacy and account deletion

The Privacy Policy and Terms of Use in `templates/privacy.html` and `templates/terms.html` are served at `/privacy` and `/terms`. Set `MEDCONNECT_SUPPORT_EMAIL` in `.env` so the pages show a monitored contact. New account creation requires acknowledgement of the terms/privacy notice. Signed-in users can open **Account and privacy** to permanently remove their account, medicine schedules, dose history, and password-reset records from the live database after confirming their current password.

Backups are separate copies; the operator must enforce and communicate a backup-retention period. Do not claim that deleting an account immediately purges backups or third-party infrastructure logs. The assistant question is processed by this server but is not saved by the assistant feature. Browser speech recognition may process microphone audio using the browser's own provider; the app receives text only when submitted.

The public SOS link opens the device dialer for `108`; it does not place or dispatch a call automatically. Confirm that 108 is the right emergency number for the launch region. Medication alarms run in the user's browser and may be delayed or prevented by device/browser settings; they are not a safety-critical notification service.

On the signed-in medicine alarms page, users can take or choose a prescription photo. English/Hindi OCR runs in the browser using Tesseract.js and language data downloaded from jsDelivr; the image itself is not uploaded. Detected lines and possible times must be checked and corrected before each medicine is saved. OCR does not interpret handwriting or dosing instructions reliably and must not replace the doctor's prescription.

The same page can estimate the visible color of a single pill from a separate close-up photo. Color analysis runs locally in the browser and does not upload or save the image. Use the result only as a rough visual description, not to identify a medicine; lighting, shadows, and the background can change it.

Signed-in users can add up to five family/caregiver phone numbers in international format and must confirm each recipient agreed to both SMS and WhatsApp alerts. With Twilio configured, a server worker checks each schedule in the user's browser-reported time zone and attempts both messages 15 minutes after the scheduled time if that dose has not been marked taken. The worker retries failed provider requests up to three times. This requires the single app instance to stay running; provider delivery may be delayed or fail, and the feature is not an emergency or guaranteed notification service. The alert includes the user's name and scheduled time, not the medicine name. Remove contacts in the alarms section to stop future alerts.

## Production settings

- Production startup fails if `MEDCONNECT_SECRET_KEY` is missing or shorter than 32 characters. Keep the same randomly generated key across restarts or existing signed-in sessions become invalid.
- The production setup forces secure session cookies, trusts one reverse proxy for client IP/protocol handling, sets browser security headers, limits request size, and applies SQLite-backed per-IP rate limits to sign-up, login, password reset, and assistant requests.
- IPs in rate-limit and password-reset controls are keyed hashes, not stored as plain IPs. The reset email provider and the speech-recognition provider are separate services with their own processing and retention policies.
- Keep server, Docker, and domain accounts patched and protected with MFA. Limit administrative access to the host and backups. Monitor health and disk capacity. This starter deployment is not a certification or substitute for a professional security/privacy review.

## Local development

```powershell
python -m pip install -r requirements.txt
python app.py
```

The app listens on port 5000 by default. Local development uses a temporary session secret unless `MEDCONNECT_SECRET_KEY` is set; do not use that mode for a public deployment.

Run the focused production-readiness tests with `python -m unittest -v test_app.py`.
