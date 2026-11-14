# Windows Protect this computer (WinDivert)

Transparent divert on Windows requires the **WinDivert** driver beside `denyout.exe`:

- `WinDivert.dll` or `WinDivert64.dll`
- `WinDivert64.sys` (loaded with admin rights)
- `denyout-windivert.exe` companion bridge (ships when packaged. Starts from `denyout hostctl apply`)

Without these files, `denyout desktop` -> Protect this computer must show **Needs setup** / error - never a fake "Protecting" state that only set a system proxy.

CA trust uses `certutil` (Current User or Local Machine Root) during elevated `hostctl apply`.

License: WinDivert is LGPL. Redistribute with attribution in NOTICE when bundling binaries in Releases.
