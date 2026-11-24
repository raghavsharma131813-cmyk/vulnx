# Running VulnX with Docker

VulnX needs Linux tools (nmap, Metasploit, curl, openssl) to scan.
Docker bundles all of them with the app in one container, so you can
run it on **Windows, macOS, or Linux** without setting up Kali.

## 1. Install Docker

- Windows: Docker Desktop — https://www.docker.com/products/docker-desktop/
- macOS: Docker Desktop — https://www.docker.com/products/docker-desktop/
- Linux: Docker Engine — https://docs.docker.com/engine/install/

After installing, make sure Docker is running (open Docker Desktop, or
`sudo systemctl start docker` on Linux).

## 2. Get VulnX

Download or clone the VulnX project folder so you have the `Dockerfile`
and `docker-compose.yml` in it.

## 3. Build and run

From inside the VulnX folder, run one command:

```bash
docker compose up --build
```

The first build is large (it installs Metasploit) and can take 10 to 20
minutes. Later runs are fast.

## 4. Use it

Open **http://localhost:5000** in any browser.

On the scan form:
- **Target**: an IP address the container can reach (for a safe first
  test, use `127.0.0.1`, which scans the container itself).
- **Kali SSH Password**: `kali`  (the container's built-in scanner user)
- Set the environmental context, then start the scan.

## Stopping

Press `Ctrl+C`, or run `docker compose down`.

## Notes

- Only scan systems you own or are explicitly authorized to test.
  Scanning other people's systems is illegal in most countries.
- Scans run from inside the container, so the target must be reachable
  from the container's network.
- The image is self-contained: it runs its own SSH, Metasploit database,
  and web server. No separate Kali VM is required.

## Running without Docker (your own Kali)

If you prefer the original setup (VulnX on your machine, scanning a
separate Kali VM), set these environment variables before starting the
app, instead of the hardcoded defaults:

```bash
export VULNX_SCANNER_HOST=192.168.56.101   # your Kali IP
export VULNX_SCANNER_USER=kali
python app.py
```
