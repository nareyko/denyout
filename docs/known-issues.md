# Known issues

Short honest list. Full discussion: [GitHub Issues](https://github.com/nareyko/denyout/issues).

## Current

1. **Windows packaging** for the Dec 1 install bet is still the hard path (WinDivert bridge packaging). Linux/macOS install scripts are ahead.
2. **Optional account sync** uses an interim API; cloud sessions are not a substitute for local Protect. Settings sync needs a signed-in account; Protect does not.
3. **Threat list refresh** can lag offline; Protect keeps the last good cache and stays usable.
4. **Agents only (whole PC)** can break messengers and many sites — intentional confirm in Settings → Advanced; prefer My agents for tools.

## Reporting

Prefer GitHub Issues with OS, DenyOut version (`denyout version`), and whether Protect or wrap was on. Do not paste real secrets or full audit URLs.
