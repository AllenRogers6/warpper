set -euo pipefail

pkg="${1:?usage: $0 <pkg.tar.zst>}"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}
ok() { echo "ok: $1"; }

files=$(bsdtar -tf "$pkg")

echo "$files" | grep -qx 'usr/bin/warpperd' ||
  fail "missing /usr/bin/warpperd"
ok "/usr/bin/warpperd"

echo "$files" | grep -qx 'usr/bin/warpperctl' ||
  fail "missing /usr/bin/warpperctl"
ok "/usr/bin/warpperctl"

echo "$files" | grep -qx 'usr/lib/systemd/system/warpperd.service' ||
  fail "missing systemd unit"
ok "systemd unit"

echo "$files" | grep -qx 'etc/warpper/warpper.conf' ||
  fail "missing config file"
ok "config file"

if echo "$files" | grep -qE '\.INSTALL$'; then
  fail "package ships a .INSTALL scriptlet; we ship none by design"
fi
ok "no .INSTALL scriptlet"

# The unit must NOT contain ExecStartPre=/usr/bin/warpperd init (removed)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bsdtar -xf "$pkg" -C "$tmp" 'usr/lib/systemd/system/warpperd.service'
if grep -q 'ExecStartPre' "$tmp/usr/lib/systemd/system/warpperd.service"; then
  fail "unit still has ExecStartPre; daemon should self-initialize"
fi
ok "no ExecStartPre in unit"

# Config must be parseable and non-empty
bsdtar -xf "$pkg" -C "$tmp" 'etc/warpper/warpper.conf'
python - "$tmp/etc/warpper/warpper.conf" <<'PY'
import configparser, sys
c = configparser.ConfigParser()
c.read(sys.argv[1])
assert c.sections(), "config has no sections"
assert c.has_section("general")
assert c.has_section("proxy")
assert c.has_section("firewall")
PY
ok "config parses"

echo
echo "all package checks passed"
