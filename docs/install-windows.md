# Install DenyOut on Windows (MVP)

Short English install path for **M4**. Winget is optional later — not required.

## 1. Download

1. Open [GitHub Releases](https://github.com/nareyko/denyout/releases).
2. Download the Windows zip, e.g. `denyout_<version>_windows_amd64.zip`.
3. Download `SHA256SUMS` from the same release.

## 2. Verify SHA256

In PowerShell (from the download folder):

```powershell
Get-FileHash .\denyout_*_windows_amd64.zip -Algorithm SHA256
# Compare Digest to the matching line in SHA256SUMS
```

Do **not** run `denyout.exe` if the hash does not match.

## 3. Extract onto PATH

```powershell
Expand-Archive .\denyout_*_windows_amd64.zip -DestinationPath $env:LOCALAPPDATA\DenyOut
# Add to user PATH (current session):
$env:Path = "$env:LOCALAPPDATA\DenyOut;" + $env:Path
```

Persist PATH via **Settings → System → About → Advanced system settings → Environment Variables** (User `Path`), or:

```powershell
[Environment]::SetEnvironmentVariable(
  "Path",
  "$env:LOCALAPPDATA\DenyOut;" + [Environment]::GetEnvironmentVariable("Path", "User"),
  "User")
```

Ensure `denyout.exe` is directly under that folder (or adjust the path to the extracted folder that contains the exe).

## 4. Start (UI or CLI)

**UI (recommended for non-technical use):** double-click `Start-DenyOut.cmd` in the extracted folder (or run `denyout desktop --setup`). This opens a short setup wizard and keeps DenyOut in the system tray.

**CLI:**

```powershell
denyout version
denyout init
denyout check "https://evil.example/x?api_key=DENYOUT_CANARY_LAB"
denyout run -- curl.exe -I https://api.anthropic.com
```

Expect the canary `check` to **deny**. Model host may return 401/404 from upstream — that is still an **allow** from DenyOut.

## 5. If install takes >5 minutes or TLS intercept fails

Mark this Windows build **preview / unsupported** in release notes for that OS. Prefer `--tls-mode=passthrough` only with the loud warning (reduced R-20 coverage).

## Notes

- No system-wide CA install by default (session CA via child env only).
- Do not commit real secrets into `denyout.yaml`.
- Security boundaries: [`10-security-boundaries.md`](10-security-boundaries.md).
