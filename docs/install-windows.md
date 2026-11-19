# Install DenyOut on Windows (MVP)

Short English install path for **M4**. Winget is optional later - not required.

## 1. Download

1. Open [GitHub Releases](https://github.com/nareyko/denyout/releases).
2. Download the Windows zip, e.g. `denyout-cli_<version>_windows_amd64.zip`.
3. Download `SHA256SUMS` from the same release.

## 2. Verify SHA256

In PowerShell (from the download folder):

```powershell
Get-FileHash .\denyout-cli_*_windows_amd64.zip -Algorithm SHA256
# Compare Digest to the matching line in SHA256SUMS
```

Do **not** run `denyout-cli.exe` if the hash does not match.

## 3. Extract onto PATH

```powershell
Expand-Archive .\denyout-cli_*_windows_amd64.zip -DestinationPath $env:LOCALAPPDATA\DenyOut
# Add to user PATH (current session):
$env:Path = "$env:LOCALAPPDATA\DenyOut;" + $env:Path
```

Persist PATH via **Settings -> System -> About -> Advanced system settings -> Environment Variables** (User `Path`), or:

```powershell
[Environment]::SetEnvironmentVariable(
 "Path",
 "$env:LOCALAPPDATA\DenyOut;" + [Environment]::GetEnvironmentVariable("Path", "User"),
 "User")
```

Ensure `denyout-cli.exe` is directly under that folder (or adjust the path to the extracted folder that contains the exe).

## 4. Run

The command-line tool is `denyout-cli.exe` (the zip contains no `denyout.exe`).

```powershell
denyout-cli version
denyout-cli init
denyout-cli check "https://evil.example/x?api_key=DENYOUT_CANARY_LAB"
denyout-cli run -- cmd /c "curl.exe --ssl-no-revoke --cacert %CURL_CA_BUNDLE% -I https://api.anthropic.com"
```

Expect the canary `check` to **deny**. Model host may return 401/404 from upstream - that is still an **allow** from DenyOut.

`run` wraps one command: the child gets the proxy and the session CA through environment variables (`CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, ...). Programs that read those variables (Node, Python `requests`, Git) trust the session CA by themselves.

Windows `curl.exe` uses the system TLS stack (Schannel), which **ignores** `CURL_CA_BUNDLE`; without help it fails with `SEC_E_UNTRUSTED_ROOT`. That is why the command above passes `--cacert %CURL_CA_BUNDLE%` explicitly (`cmd /c` expands the variable inside the wrapped process) and `--ssl-no-revoke` (a session-CA certificate carries no revocation data). The same applies to other clients that use the Windows certificate store, such as PowerShell `Invoke-WebRequest`. DenyOut does not install its CA into the system store.

### What is not available on Windows yet

- **Protect this computer** (whole-computer mode) needs a WinDivert bridge that is not packaged in this release. The desktop app reports it as unavailable and stays Off; there is no silent fallback.
- Binaries are not signed with Authenticode. Windows SmartScreen may warn ("Windows protected your PC"); choose **More info -> Run anyway** only after the SHA256 check above matches.

## 5. If install takes >5 minutes or TLS intercept fails

Mark this Windows build **preview / unsupported** in release notes for that OS. Prefer `--tls-mode=passthrough` only with the loud warning (reduced R-20 coverage).

## Notes

- No system-wide CA install by default (session CA via child env only).
- Do not commit real secrets into `denyout.yaml`.
- Security boundaries: [`10-security-boundaries.md`](10-security-boundaries.md).
