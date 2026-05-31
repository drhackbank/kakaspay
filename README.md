# kakaspay

A secure owner portal for managing ICICI Bank payment APIs — built for designated application owners to initiate and monitor IMPS, NEFT and RTGS transactions from a single dashboard.

---

## What this project does

kakaspay is a private web portal that gives authorised application owners direct access to ICICI Bank's corporate payment API suite. It is purpose-built for high-volume payment workflows, covering three fund transfer modes with full operational controls:

- **IMPS** — Immediate Payment Service, instant 24x7 transfers up to ₹5 lakh per transaction
- **NEFT** — National Electronic Funds Transfer, batch-based transfers settled in half-hourly cycles during banking hours
- **RTGS** — Real Time Gross Settlement, for high-value transfers of ₹2 lakh and above, settled in real time

Additionally the portal includes:

- **Transaction Status** — query the real-time status of any initiated payment by reference number or UTR
- **Account Validation** — verify a beneficiary account holder name before sending any payment using penny-drop or name-match
- **Fetch VPA** — resolve and validate a UPI Virtual Payment Address before a transfer
- **Beneficiary Management** — register and manage beneficiaries for repeat transfers

---

## How it works

The portal is a static single-page application. When an owner logs in, the dashboard loads a live API test console for each payment module.

Each module has three sections — Params (all required and optional API fields), Headers (editable HTTP headers), and Body (pre-filled editable JSON payload). Clicking Send Request fires a real HTTP call to ICICI Bank's API gateway at `apigw.icicibank.com`. The raw JSON response appears immediately with the HTTP status code and response time.

Without a Bearer token the console returns a sandbox mock response. With a valid token, real transactions execute against ICICI Bank's live systems.

The portal tracks every call in a session history log and shows live metrics — total calls, success count, errors and average response time — on the dashboard.

---

## Security

Access is restricted to one designated owner account. Credentials are never stored in plain text — login uses SHA-256 hash comparison in the browser. Three failed attempts trigger a 30-second lockout. No tokens or credentials are stored in browser memory or localStorage.

---

*kakaspay — Private and confidential. Unauthorised access is prohibited.*
