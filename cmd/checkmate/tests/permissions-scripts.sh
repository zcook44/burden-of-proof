#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
tmp=$(mktemp -d "${TMPDIR:-$HOME}/checkmate-script-test.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
mode() { stat -c %a -- "$1"; }
assert_mode() { [[ $(mode "$1") == "$2" ]] || fail "mode $1 expected $2, got $(mode "$1")"; }
source_dir="$tmp/source archives"
mkdir -p "$source_dir"
# Synthetic DISA-style ZIP: extract the one manual XML, not the other files.
mkdir -p "$tmp/input/U_RHEL_9_V2R10_Manual_STIG"
printf '<Benchmark/>\n' > "$tmp/input/U_RHEL_9_V2R10_Manual_STIG/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml"
printf 'not a benchmark\n' > "$tmp/input/readme.txt"
(cd "$tmp/input" && zip -q -r "$source_dir/U_RHEL_9_V2R10_STIG.zip" .)
mkdir -p "$tmp/lib parent"
bash "$repo/scripts/unpack-stig-library.sh" "$source_dir" "$tmp/lib parent/stig_library"
xml="$tmp/lib parent/stig_library/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml"
[[ -f "$xml" ]] || fail 'missing extracted benchmark'
cmp "$xml" "$tmp/input/U_RHEL_9_V2R10_Manual_STIG/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml" || fail 'content mismatch'
assert_mode "$tmp/lib parent/stig_library" 700
assert_mode "$xml" 600
[[ ! -e "$tmp/lib parent/stig_library/readme.txt" ]] || fail 'extracted unrelated file'
if bash "$repo/scripts/unpack-stig-library.sh" "$source_dir" "$tmp/lib parent/stig_library"; then fail 'overwrote destination'; fi
# Detect duplicate official filenames before promoting any files.
cp "$source_dir/U_RHEL_9_V2R10_STIG.zip" "$source_dir/U_RHEL_9_V2R10_STIG-copy.zip"
if bash "$repo/scripts/unpack-stig-library.sh" "$source_dir" "$tmp/duplicate"; then fail 'accepted duplicate benchmark'; fi
[[ ! -e "$tmp/duplicate" ]] || fail 'created destination on failed preflight'
rm "$source_dir/U_RHEL_9_V2R10_STIG-copy.zip"
# Cisco filenames reflect the manual XCCDF members in the local official ZIP listing:
# IOS/IOS-XE/IOS-XR, ASA, ACI, ISE, NX-OS and SNA have different STIG/version ordering.
cisco_names=(
  U_Cisco_ACI_L2S_V1R2_STIG_Manual-xccdf.xml
  U_Cisco_ACI_NDM_V1R2_STIG_Manual-xccdf.xml
  U_Cisco_ACI_RTR_Manual_V1R2_STIG_Manual-xccdf.xml
  U_Cisco_ASA_Firewall_STIG_V2R1_Manual-xccdf.xml
  U_Cisco_ASA_IPS_STIG_V2R1_Manual-xccdf.xml
  U_Cisco_ASA_NDM_STIG_V2R5_Manual-xccdf.xml
  U_Cisco_ASA_VPN_STIG_V2R2_Manual-xccdf.xml
  U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml
  U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml
  U_Cisco_IOS-XE_Switch_RTR_STIG_V3R4_Manual-xccdf.xml
  U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml
  U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml
  U_Cisco_IOS-XR_Router_NDM_STIG_V3R6_Manual-xccdf.xml
  U_Cisco_IOS-XR_Router_RTR_STIG_V3R3_Manual-xccdf.xml
  U_Cisco_IOS_Router_NDM_STIG_V3R9_Manual-xccdf.xml
  U_Cisco_IOS_Router_RTR_STIG_V3R5_Manual-xccdf.xml
  U_Cisco_IOS_Switch_L2S_STIG_V3R3_Manual-xccdf.xml
  U_Cisco_IOS_Switch_NDM_STIG_V3R9_Manual-xccdf.xml
  U_Cisco_IOS_Switch_RTR_STIG_V3R4_Manual-xccdf.xml
  U_Cisco_ISE_NAC_STIG_V2R4_Manual-xccdf.xml
  U_Cisco_ISE_NDM_STIG_V2R4_Manual-xccdf.xml
  U_Cisco_NX-OS_Switch_L2S_STIG_V3R4_Manual-xccdf.xml
  U_Cisco_NX-OS_Switch_NDM_STIG_V3R6_Manual-xccdf.xml
  U_Cisco_NX-OS_Switch_RTR_STIG_V3R4_Manual-xccdf.xml
  U_Cisco_SNA_STIG_V1R1_Manual-xccdf.xml
)
mkdir -p "$tmp/cisco-input/U_Cisco_IOS_Router_NDM_V3R9_Manual_STIG"
for name in "${cisco_names[@]}"; do
  printf '<Benchmark id="%s"/>\n' "$name" > "$tmp/cisco-input/U_Cisco_IOS_Router_NDM_V3R9_Manual_STIG/$name"
done
printf 'not a manual benchmark\n' > "$tmp/cisco-input/U_Cisco_IOS_Router_NDM_V3R9_Manual_STIG/U_Cisco_IOS_Router_NDM_STIG_V3R9-xccdf.xml"
(cd "$tmp/cisco-input" && zip -q -r "$source_dir/U_Cisco_IOS_Router_Y26M10_STIG.zip" .)
bash "$repo/scripts/unpack-stig-library.sh" "$source_dir" "$tmp/cisco-library"
assert_mode "$tmp/cisco-library" 700
for name in "${cisco_names[@]}"; do
  cmp "$tmp/cisco-input/U_Cisco_IOS_Router_NDM_V3R9_Manual_STIG/$name" "$tmp/cisco-library/$name" || fail "Cisco XML mismatch: $name"
  assert_mode "$tmp/cisco-library/$name" 600
done
[[ ! -e "$tmp/cisco-library/U_Cisco_IOS_Router_NDM_STIG_V3R9-xccdf.xml" ]] || fail 'extracted non-manual Cisco XML'
[[ $(find "$tmp/cisco-library" -mindepth 1 -maxdepth 1 -type f | wc -l) == $((${#cisco_names[@]} + 1)) ]] || fail 'extracted unexpected files'
bash "$repo/scripts/unpack-stig-library.sh" "$source_dir/U_Cisco_IOS_Router_Y26M10_STIG.zip" "$tmp/cisco-only"
[[ $(find "$tmp/cisco-only" -mindepth 1 -maxdepth 1 -type f | wc -l) == ${#cisco_names[@]} ]] || fail 'Cisco-only ZIP extraction incomplete'
[[ ! -e "$tmp/cisco-only/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml" ]] || fail 'Cisco-only ZIP acquired RHEL XML'
# The same flat Cisco name in two archives must fail without publishing a library.
cp "$source_dir/U_Cisco_IOS_Router_Y26M10_STIG.zip" "$source_dir/U_Cisco_IOS_Router_Y26M10_STIG-copy.zip"
if bash "$repo/scripts/unpack-stig-library.sh" "$source_dir" "$tmp/cisco-duplicate"; then fail 'accepted duplicate Cisco benchmark'; fi
[[ ! -e "$tmp/cisco-duplicate" ]] || fail 'published duplicate Cisco library'
rm "$source_dir/U_Cisco_IOS_Router_Y26M10_STIG-copy.zip"
# An allowlisted Cisco basename underneath a traversal component must be rejected.
python3 - "$tmp/cisco-traversal.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'w') as archive:
    archive.writestr('../U_Cisco_IOS_Router_NDM_STIG_V3R9_Manual-xccdf.xml', '<Benchmark/>')
PY
if bash "$repo/scripts/unpack-stig-library.sh" "$tmp/cisco-traversal.zip" "$tmp/cisco-traversal-library"; then fail 'accepted Cisco traversal member'; fi
[[ ! -e "$tmp/cisco-traversal-library" ]] || fail 'published traversal member'
# A ZIP with no matching manual XCCDF must not create output.
(cd "$tmp/input" && zip -q "$source_dir/irrelevant.zip" readme.txt)
if bash "$repo/scripts/unpack-stig-library.sh" "$source_dir/irrelevant.zip" "$tmp/irrelevant"; then fail 'accepted unrelated ZIP'; fi
[[ ! -e "$tmp/irrelevant" ]] || fail 'created destination for irrelevant ZIP'
ln -s "$source_dir/U_RHEL_9_V2R10_STIG.zip" "$tmp/link.zip"
if bash "$repo/scripts/unpack-stig-library.sh" "$tmp/link.zip" "$tmp/linked"; then fail 'accepted symlink archive'; fi
mkdir -m 777 "$tmp/writable parent"
chmod 777 "$tmp/writable parent"
if bash "$repo/scripts/unpack-stig-library.sh" "$source_dir/U_RHEL_9_V2R10_STIG.zip" "$tmp/writable parent/lib"; then fail 'accepted writable destination parent'; fi
[[ ! -e "$tmp/writable parent/lib" ]] || fail 'created library in writable parent'
# Permissions repair: inspect first, then apply; preserve data and ownership.
root="$tmp/scan results"
mkdir -p "$root/host one/subdir"
printf 'xccdf\n' > "$root/host one/scan.results.xml"
printf 'arf\n' > "$root/host one/scan.results.arf.xml"
printf 'evidence\n' > "$root/host one/subdir/report.txt"
chmod 755 "$root" "$root/host one" "$root/host one/subdir"
chmod 644 "$root/host one/scan.results.xml" "$root/host one/scan.results.arf.xml" "$root/host one/subdir/report.txt"
bash "$repo/scripts/fix-oscap-permissions.sh" "$root"
assert_mode "$root" 755
assert_mode "$root/host one/scan.results.xml" 644
bash "$repo/scripts/fix-oscap-permissions.sh" --apply "$root"
assert_mode "$root" 700
assert_mode "$root/host one" 700
assert_mode "$root/host one/subdir" 700
assert_mode "$root/host one/scan.results.xml" 600
assert_mode "$root/host one/scan.results.arf.xml" 600
assert_mode "$root/host one/subdir/report.txt" 600
[[ $(<"$root/host one/scan.results.xml") == xccdf ]] || fail 'modified contents'
# Refuse symlinks before changing anything in the requested tree.
chmod 755 "$root"
ln -s /etc/passwd "$root/host one/surprise"
if bash "$repo/scripts/fix-oscap-permissions.sh" --apply "$root"; then fail 'accepted symlink in results tree'; fi
assert_mode "$root" 755
rm "$root/host one/surprise"
ln "$root/host one/scan.results.xml" "$root/host one/external-hardlink"
if bash "$repo/scripts/fix-oscap-permissions.sh" --apply "$root"; then fail 'accepted multiply-linked result'; fi
assert_mode "$root" 755
rm "$root/host one/external-hardlink"
if bash "$repo/scripts/fix-oscap-permissions.sh" --apply "$tmp/lib parent"; then fail 'accepted tree without OSCAP results'; fi
printf 'PASS: library extraction and results permissions\n'
