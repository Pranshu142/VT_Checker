# VT Checker

Chat-style VirusTotal checker. Each visitor pastes their own VirusTotal API key; nothing is
configured on the server. Check one indicator, a pasted list, or attach an Excel file and get
an Excel report back.

## How the key is handled
The browser keeps the key in sessionStorage (cleared when the tab closes), or in localStorage
if "Remember my key" is ticked. Each lookup sends it in an `X-VT-Key` header to `/api/vt`, which
forwards it to virustotal.com for that one request. It is never stored or logged. VirusTotal
blocks direct browser calls (no CORS), which is why the relay exists.

## Excel input
Needs a heading `indicator` (and `severity`, optional). Only the `indicator` column is read.
Rows already holding a severity are skipped by default. Invalid values and private IPs never
reach VirusTotal.

## Severity
Malicious count: 0 Clean, 1-5 Medium, 6-10 High, above 10 Critical. Rule is `severity()` in
`public/index.html`.

## Run locally
`node dev.js` then open http://localhost:3000 (Node 18+, nothing to install).

## Deploy free on Vercel
Push to GitHub, import at vercel.com, deploy. No environment variables needed.
