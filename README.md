# Faizan™ OSINT Intelligence Suite v2.0

A lawful, evidence-oriented OSINT toolkit for investigating publicly available information and user-authorized data.

## Safety boundary
This project does NOT attempt to:
- obtain live GPS from a phone number
- break into private social-media accounts
- obtain passwords, OTPs, private emails, or private IP logs
- bypass authentication, carrier controls, or platform privacy settings
- deanonymize people from non-public government/telecom databases

## Working modules
- Phone metadata: country/region, carrier/type when available through `phonenumbers`
- IP intelligence: public IP geolocation/ASN lookup through ip-api.com
- Domain intelligence: DNS records and WHOIS when installed
- Username checks: public profile URL checks on a small set of platforms
- Evidence records: timestamped JSON
- CSV export
- Local web dashboard

## Install
```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
pip install -r requirements.txt
python -m app.server
```

Open http://127.0.0.1:8000

## Intended use
Use only for lawful investigations, public-interest research, or data for which you have authorization. Findings are leads, not proof of identity or guilt. Verify through appropriate legal procedures and authoritative records.
