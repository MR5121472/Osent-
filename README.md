# Faizan™ OSINT Intelligence Suite v4.0

Render-ready, evidence-oriented OSINT console.

## Render
Create the service from `render.yaml`, or manually use:
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app`
- Health: `/health`
- Set `ADMIN_PASSWORD` to a strong secret.
- Keep `SECRET_KEY` secret.

## v4 features
- Investigator login / role field
- Case management
- Evidence records with SHA-256 integrity hashes
- Audit log
- Phone metadata
- Approximate public IP geolocation
- DNS/WHOIS domain intelligence
- Public username checks
- CSV evidence index
- PostgreSQL support

## Important
This is not a telecom/government subscriber database. It cannot and should not derive live GPS, private accounts, passwords, OTPs or private subscriber records from a phone number. For official investigations, integrate only vetted providers and legally authorized records through controlled APIs, with retention/access policies.
