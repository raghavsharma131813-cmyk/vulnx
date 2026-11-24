<h1 align="center">VulnX</h1>

<p align="center">
  <b>Context-aware vulnerability scanner.</b><br>
  Finds what matters, not just what scans.
</p>

<p align="center">
  <a href="https://raghavsharma131813-cmyk.github.io/vulnx/"><b>Live page</b></a> ·
  <a href="#quick-start-docker">Quick start</a> ·
  <a href="#how-it-works">How it works</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue" alt="Python">
  <img src="https://img.shields.io/badge/framework-Flask-black" alt="Flask">
  <img src="https://img.shields.io/badge/docker-ready-2496ED" alt="Docker">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

---

VulnX runs an nmap service scan, correlates detected products against the National Vulnerability Database (NVD), discovers related Metasploit modules, and ranks every finding by the real risk to the asset, not by CVSS alone. It runs as a Flask web app, packaged with Docker so it works on Windows, macOS, or Linux.

> **Authorized use only.** Only scan systems you own or have explicit written permission to test. VulnX performs intelligence and discovery only and never runs exploit modules.

## Why it is different

Most scanners order findings by a generic severity score, which says little about how much a finding matters on a particular asset. VulnX adds environmental context, so the same CVE ranks higher on a critical internet-facing asset than on a throwaway lab box.

## Features

- **Network scanning** — nmap discovery with service and version detection, parsed into structured findings.
- **CVE intelligence** — live NVD correlation with CPE version applicability, so a match is evidence, not a guess.
- **Context-aware risk** — asset criticality, network exposure, and service importance re-rank findings per host.
- **Metasploit intelligence** — discovers candidate modules for matched services. VulnX never runs exploits.
- **Web checks and reporting** — passive web checks, scan history, scan-to-scan comparison, and export to PDF, CSV, JSON, and nmap-format XML (importable into Metasploit).

## How it works

```
Target -> nmap scan -> parse services and CPEs -> NVD CVE correlation ->
context-aware risk engine -> Metasploit module discovery -> report and history
```

## Quick start (Docker)

Docker bundles nmap, Metasploit, and the app in one container. No separate Kali setup needed.

```bash
git clone https://github.com/raghavsharma131813-cmyk/vulnx.git
cd vulnx
docker compose up --build
```

Then open http://localhost:5000. For a safe first test, scan `127.0.0.1` with the Kali SSH password `kali`. The first build installs Metasploit and can take 10 to 20 minutes; later runs are fast.

## Running locally (without Docker)

Requires Python 3.10+, nmap, and Metasploit on your PATH.

```bash
python -m venv .venv
# Windows:      .venv\Scripts\Activate.ps1
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open the URL Flask prints (usually http://127.0.0.1:5000).

## Configuration

Set these environment variables to point VulnX at your scanner, instead of the defaults:

| Variable | Default | Purpose |
|---|---|---|
| `VULNX_SCANNER_HOST` | `192.168.56.101` | IP of the Kali scanner (SSH) |
| `VULNX_SCANNER_USER` | `kali` | Scanner SSH username |
| `VULNX_BIND` | `127.0.0.1` | Web UI bind address |
| `VULNX_PORT` | `5000` | Web UI port |
| `VULNX_DEBUG` | `0` | Set to `1` to enable Flask debug |

Per-host context (criticality, exposure, importance) can be set in `asset_context.json`.

## Project structure

```
vulnx/
├── app.py                 # Flask application and routes
├── scanner/               # nmap running/parsing, Metasploit discovery and mapping
├── vulnerability_engine/  # NVD client, risk scoring, database layer
├── report/                # PDF report and CSV/JSON/XML exporters
├── templates/             # web UI
├── docs/                  # project landing page (served by GitHub Pages)
├── experiments/           # ranking evaluation scripts
├── tests/                 # test scripts
├── Dockerfile
└── docker-compose.yml
```

## Tech stack

Python · Flask · nmap · Metasploit Framework · SQLite · Docker

## Project status

Actively developed. Core scanning, CVE correlation, Metasploit module discovery, context-aware risk scoring, reporting, and scan comparison are complete, and the tool runs via Docker on any OS. VulnX is also the implementation behind a research paper on context-aware, risk-based vulnerability prioritization.

## Author

**Raghav Sharma**
GitHub: [@raghavsharma131813-cmyk](https://github.com/raghavsharma131813-cmyk)

## License

Released under the MIT License. See [LICENSE](LICENSE).
