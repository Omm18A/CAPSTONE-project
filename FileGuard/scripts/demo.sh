#!/usr/bin/env bash
# Runs the presentation scenario end-to-end with the CLI in a throw-away data directory.
#   scripts/demo.sh [path/to/fileguard]
# Passwords come from environment variables here purely to automate the demo.
set -u
cd "$(dirname "$0")/.."
FG="${1:-build/fileguard}"
[ -x "$FG" ] || { echo "Binary $FG not found. Run scripts/build.sh first." >&2; exit 1; }
WORK="$(mktemp -d)"; export FILEGUARD_HOME="$WORK/store"; trap 'rm -rf "$WORK"' EXIT
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
as()   { local u="$1" p="$2"; shift 2; FILEGUARD_PASSWORD="$p" "$FG" --user "$u" "$@"; }

step "1. Create users (admin bootstrap, Omm=OWNER, Rahul/Priya=USER)"
FILEGUARD_NEW_PASSWORD=adminpass1 "$FG" user add admin ADMIN
FILEGUARD_NEW_PASSWORD=ommpass123 "$FG" user add Omm OWNER
FILEGUARD_NEW_PASSWORD=rahulpass1 "$FG" user add Rahul USER
FILEGUARD_NEW_PASSWORD=priyapass1 "$FG" user add Priya USER

step "2-4. Omm registers confidential.pdf -> File ID, SHA-256, encrypted package"
printf 'CONFIDENTIAL: Q3 acquisition target is Example Corp.\n' > "$WORK/confidential.pdf"
as Omm ommpass123 register "$WORK/confidential.pdf"

step "5. Omm shares FG-10001 with Rahul (READ) and exports the .fguard"
as Omm ommpass123 share FG-10001 Rahul READ
as Omm ommpass123 export FG-10001 "$WORK/confidential.fguard"
echo "On-disk package starts with: $(head -c 6 "$WORK/confidential.fguard")  (no plaintext inside: $(grep -c 'acquisition' "$WORK/confidential.fguard" || true) matches)"

step "6-8. Rahul logs in and opens it"
as Rahul rahulpass1 open FG-10001

step "Priya (never shared) tries - even holding the .fguard file"
as Priya priyapass1 open "$WORK/confidential.fguard"; echo "exit code: $? (3 = access denied)"

step "9-10. Omm revokes Rahul; Rahul tries again"
as Omm ommpass123 revoke FG-10001 Rahul
as Rahul rahulpass1 open FG-10001; echo "exit code: $? (3 = access denied)"

step "11. Tampered file -> integrity failure"
as Omm ommpass123 share FG-10001 Rahul READ >/dev/null
chmod u+w "$FILEGUARD_HOME/protected_files/FG-10001.fguard"
printf 'X' | dd of="$FILEGUARD_HOME/protected_files/FG-10001.fguard" bs=1 seek=100 conv=notrunc 2>/dev/null
as Rahul rahulpass1 open FG-10001; echo "exit code: $? (4 = integrity failure)"

step "Audit log (Omm)"
as Omm ommpass123 logs 30
step "Security alerts (admin)"
as admin adminpass1 alerts 20

step "12. System info + kernel driver"
"$FG" sysinfo
if "$FG" driver status 2>/dev/null; then as admin adminpass1 driver events; else
  echo "(driver not loaded - run: make -C driver && sudo scripts/install_driver.sh)"; fi
