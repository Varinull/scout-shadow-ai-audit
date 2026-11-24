# VARINULL Local Scout #2: Unofficial AI Usage & Compliance Readiness Check

Inspect local project manifests for AI libraries, `.env` key names, and SSO/OAuth or vendor CSV exports on your own computer.

## Open, Inspectable & Local-First
- **Runs on Your Computer:** Opens directly in any modern browser (`client-assessment.html`) or runs on your localhost (`127.0.0.1:9102`).
- **100% Readable Source Code:** Inspect `client-assessment.html`, `engine.py`, and `customer_server.py` directly. `engine.py` uses **only the Python standard library** with zero outbound HTTP client calls.
- **What Is Read vs. Ignored:** Pattern-based local scanning inspects structural metadata (column/table names, dependency names, `.env` key names before `=`, row/formula counts) while ignoring secret values after `=` and never uploading raw files anywhere.
- **No Login or Email Gate:** All contact fields are optional. Run the check, keep the printable report, and fix everything in-house at your own pace.

## Option A: Instant Browser Mode (Zero Install)
Double-click **`client-assessment.html`** to open the Blank Assessment directly in Chrome, Edge, Firefox, or Safari. You can answer the plain-English checklist or pick local files/folders right in browser memory.

## Option B: Localhost Python Server (Enables Local Folder Path Scanning)
If you have Python 3.10+ installed and want to paste a local directory path on your computer:

### Windows
```powershell
pip install -r requirements.txt
.\start-scout.bat
```

### macOS / Linux
```bash
pip install -r requirements.txt
chmod +x start-scout.sh && ./start-scout.sh
```

Then open **`http://127.0.0.1:9102`**.

## Optional Next Step
If your team resolves everything internally using the checklist, enjoy the tool with our compliments.
If you ever want help remediating what you find in a focused sprint (scoped upfront to realistic 40-hr/week milestones), click **Export Summary File (`.json`)** (contains structural counts and risk flags only, with zero raw records or file contents) and email it to **info@varinull.com** (or attach it at https://varinull.com/contact).

## License
MIT License - see [LICENSE](LICENSE).
