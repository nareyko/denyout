# Platform seams and macOS / Windows packaging

## Platform seams

Per-OS behaviour sits behind three small interfaces in `internal/platform`:

| Interface | Linux | macOS | Windows | Wrapped code |
|-----------|-------|-------|---------|--------------|
| `Redirector[Spec]` (Apply, Remove, Status) | nft | pf | WinDivert | `internal/hostguard/apply_*.go` via `platform_impl.go` |
| `TrustStore` (Install, Remove, Installed) | `update-ca-certificates` | `security` System keychain | `certutil` Root store | `internal/hostguard/ca_*.go` |
| `Autostart` (Register, Unregister, Registered) | XDG autostart + systemd user | LaunchAgent | registry Run key | `internal/desktop/autostart_*.go` |

`hostguard.Apply/Remove/Teardown` and `desktop.RegisterAutostart/UnregisterAutostart/AutostartRegistered`
keep their signatures and forward to package-level interface values, which tests replace with fakes.
`Redirector.Status` is tracked in-process (last successful Apply/Remove). The root helper stays the
authoritative source of protection state.

`internal/platform/platformtest` holds the table-driven contract suites
(`RedirectorContract`, `TrustStoreContract`, `AutostartContract`) and in-memory fakes. A new
implementation must pass its contract. Real OS commands are never run by these tests.

## CI coverage

- `quality`: gofmt, `go vet` for linux/darwin/windows (compiles every test), staticcheck, race tests (Linux).
- `portable-tests`: `go test` on `macos-15` and `windows-latest` for platform-neutral packages, plus
  `go test -c` (compile only) for all other packages. Privileged or network-mutating tests are not run
  there (`DENYOUT_TEST_NO_ELEVATE=1`). The Linux nft/helper paths stay in the Docker jobs.
- To widen the list, add a package to the `portable-tests` step only after it passes on both OSes
  (avoid Unix paths, `chmod` bit checks, fixed ports, `sh`).

## What macOS / Windows packaging still lacks

Release archives are cosign-signed (keyless) with a signed `SHA256SUMS`, which proves provenance but
is **not** accepted by Gatekeeper or SmartScreen. Missing:

### macOS: Developer ID signing + notarization

Needed (none exist in the repo today. Do not commit them):

1. Apple Developer Program membership (paid, organization or individual).
2. A "Developer ID Application" certificate exported as `.p12` with a password.
3. A notarization credential: an App Store Connect API key (`.p8`, key id, issuer id) or an Apple ID
   with an app-specific password and team id.

Plan:

1. Add repository secrets `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `NOTARY_KEY_P8_BASE64`,
   `NOTARY_KEY_ID`, `NOTARY_ISSUER_ID`.
2. In the release workflow add a `macos-15` job that, only `if` the secrets are present: creates a
   temporary keychain, imports the `.p12`, runs `codesign --force --options runtime --timestamp
   --sign "Developer ID Application: ..."` on the `.app`/binaries (hardened runtime, add an
   entitlements file if Wails needs one).
3. Zip/dmg the app, run `xcrun notarytool submit --wait`, then `xcrun stapler staple`.
4. Re-run `spctl -a -vv` and `codesign --verify --deep --strict` as a release gate.
5. Keep cosign signing of the final archive. Compute `SHA256SUMS` after stapling.
6. The root helper / pf path needs a signed binary too. Confirm the osascript elevation flow after signing.

### Windows: Authenticode + SmartScreen

Needed:

1. A code-signing certificate: EV (instant SmartScreen reputation) or OV (reputation builds over time),
   or Azure Trusted Signing / a cloud HSM service. EV/OV keys cannot be a plain exported file for new
   issuance (hardware or cloud-held).
2. Secrets for the chosen service (for example `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
   `AZURE_CLIENT_SECRET`, signing account and profile names), or a certificate thumbprint plus HSM access
   on a self-hosted runner.
3. The WinDivert driver is already signed by its upstream. Verify it ships unmodified.

Plan:

1. Add the secrets above. The signing step runs only when they are set.
2. In a `windows-latest` release job sign `denyout.exe`, `denyout-cli.exe` and the installer with
   `signtool sign /fd sha256 /tr <timestamp-url> /td sha256` (or the Trusted Signing action).
3. Verify with `signtool verify /pa /v` as a gate.
4. Build an MSI/MSIX or signed installer so users do not run a bare zip.
5. Submit the signed installer to Microsoft for SmartScreen reputation if using OV.
6. Update `docs/install-windows.md` and `install.sh` equivalents once signed artifacts exist.

Until these are done, macOS users must right-click Open (or clear quarantine) and Windows users see a
SmartScreen warning. Both are expected and documented in the install guides.
