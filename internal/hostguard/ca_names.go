package hostguard

// DesktopCANickname is the NSS / Keychain / store nickname for the Protect CA.
const DesktopCANickname = "DenyOut CA"

// LinuxSystemCACert is the Debian/Ubuntu ca-certificates path written by installCA.
const LinuxSystemCACert = "/usr/local/share/ca-certificates/denyout.crt"

// LinuxSystemCAHashLink is the OpenSSL hash symlink; may dangle after crt removal
// until update-ca-certificates runs (or must be removed manually).
const LinuxSystemCAHashLink = "/etc/ssl/certs/denyout.pem"
