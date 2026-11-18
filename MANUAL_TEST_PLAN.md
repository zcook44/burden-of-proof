# Manual Test Plan for Layered Tailoring

This test plan verifies the layered tailoring system works correctly on a disconnected deployment.

## Prerequisites

1. Unpacked docket release archive with `cisco-library/` containing 25 schema v2 Cisco root inventories
2. RHEL 9 benchmark: `U_RHEL_9_STIG_V2R10_Manual-xccdf.xml`
3. Cisco IOS Router RTR benchmark: `U_Cisco_IOS_Router_RTR_STIG_V3R11_Manual-xccdf.xml`
4. One RHEL 9 scan result: `node1.results.xccdf.xml`
5. One Cisco router config: `router1.running-config`

## Test 1: RHEL Batch with Root + Host Override

### Setup

```bash
# Create library root with RHEL 9 benchmark
mkdir -p /tmp/test-library
cp U_RHEL_9_STIG_V2R10_Manual-xccdf.xml /tmp/test-library/
chmod 600 /tmp/test-library/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml

# Compute benchmark SHA-256
RHEL_SHA=$(sha256sum /tmp/test-library/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml | awk '{print $1}')

# Create root tailoring (site-wide policy) - schema v2 with NO comments on auto
cat > /tmp/test-library/RHEL_9_STIG.tailoring.yaml <<EOF
schema_version: 2
benchmark_id: RHEL_9_STIG
benchmark_sha256: $RHEL_SHA
rules:
  - rule_name: sudo_remove_nopasswd
    stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    status: not_a_finding
    comment: "Site requires passwordless sudo for automation"
EOF

chmod 600 /tmp/test-library/RHEL_9_STIG.tailoring.yaml

# Create scan root with one host scan
mkdir -p /tmp/test-scans/node1.example.test
cp node1.results.xccdf.xml /tmp/test-scans/node1.example.test/scan.results.xccdf.xml
chmod 600 /tmp/test-scans/node1.example.test/scan.results.xccdf.xml

# Create host override (this specific host needs password for sudo)
cat > /tmp/test-scans/node1.example.test/RHEL_9_STIG.tailoring.yaml <<EOF
schema_version: 2
benchmark_id: RHEL_9_STIG
benchmark_sha256: $RHEL_SHA
rules:
  - stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    status: auto
    comment: "Host requires password for sudo; revert site override to use scan result"
EOF

chmod 600 /tmp/test-scans/node1.example.test/RHEL_9_STIG.tailoring.yaml
```

### Validation

```bash
# Validate tailoring files
./docket tailoring check --library-root /tmp/test-library --scan-root /tmp/test-scans

# Expected output:
# Checking library root: /tmp/test-library
# OK: RHEL_9_STIG.tailoring.yaml (root layer, /tmp/test-library/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml)
# 
# Checking scan root: /tmp/test-scans
# Checking host override: RHEL_9_STIG.tailoring.yaml (host: node1.example.test)
# OK: /tmp/test-scans/node1.example.test/RHEL_9_STIG.tailoring.yaml (host layer)
# 
# VALIDATION PASSED: no issues, 0 warnings
```

### Dry Run

```bash
./docket batch-cklb --input-root /tmp/test-scans --library-root /tmp/test-library --dry-run

# Expected output includes:
# BENCHMARK RHEL 9: /tmp/test-library/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml (sha256 ...)
# TAILORING ROOT RHEL 9: /tmp/test-library/RHEL_9_STIG.tailoring.yaml (sha256 ...; 1 rules)
# TAILORING HOST node1.example.test: /tmp/test-scans/node1.example.test/RHEL_9_STIG.tailoring.yaml (sha256 ...)
# SCAN /tmp/test-scans/node1.example.test/scan.results.xccdf.xml [...]
# bundles: 1; no files written
```

### Generate Checklist

```bash
./docket batch-cklb --input-root /tmp/test-scans --library-root /tmp/test-library

# Check provenance
cat /tmp/test-scans/node1.example.test/*-ASSESSMENT.cklb.provenance.json | jq '{
  schema_version,
  tailoring_root: .tailoring_root.path,
  tailoring_host: .tailoring_host.path,
  rule_V258106_layer: .tailoring_rule_layer."V-258106"
}'

# Expected output:
# {
#   "schema_version": 2,
#   "tailoring_root": "/tmp/test-library/RHEL_9_STIG.tailoring.yaml",
#   "tailoring_host": "/tmp/test-scans/node1.example.test/RHEL_9_STIG.tailoring.yaml",
#   "rule_V258106_layer": "host"
# }
```

**Verify:**
- Both root and host tailoring files loaded
- V-258106 mapped to "host" layer in provenance
- Generated checklist has V-258106 using scan result (host override applied)

---

## Test 2: Cisco Device with Root + Host Override

### Setup

```bash
# Create library root with Cisco benchmark
mkdir -p /tmp/cisco-library
cp U_Cisco_IOS_Router_RTR_STIG_V3R11_Manual-xccdf.xml /tmp/cisco-library/
chmod 600 /tmp/cisco-library/U_Cisco_IOS_Router_RTR_STIG_V3R11_Manual-xccdf.xml

# Copy schema v2 root inventory from release package
cp cisco-library/Cisco_IOS_Router_RTR_STIG.tailoring.yaml /tmp/cisco-library/
chmod 600 /tmp/cisco-library/Cisco_IOS_Router_RTR_STIG.tailoring.yaml

# Edit root file to add ONE site-wide override (example: V-216555)
# Change line "    status: auto" to "    status: not_applicable" and add comment:
#   - stig_id: V-216555
#     sv_id: SV-216555r1007824_rule
#     status: not_applicable
#     comment: "Site uses external AAA; local accounts not applicable"

# Compute benchmark SHA-256
CISCO_SHA=$(sha256sum /tmp/cisco-library/U_Cisco_IOS_Router_RTR_STIG_V3R11_Manual-xccdf.xml | awk '{print $1}')

# Create device directory with config
mkdir -p /tmp/cisco-devices/router1
cat > /tmp/cisco-devices/router1/scan.running-config <<'EOF'
hostname router1
version 15.7
!
username admin privilege 15 secret 5 $1$...
!
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
!
end
EOF

chmod 600 /tmp/cisco-devices/router1/scan.running-config

# Create host override (this device has local accounts, revert site override)
cat > /tmp/cisco-devices/router1/Cisco_IOS_Router_RTR_STIG.tailoring.yaml <<EOF
schema_version: 2
benchmark_id: Cisco_IOS_Router_RTR_STIG
benchmark_sha256: $CISCO_SHA
rules:
  - stig_id: V-216555
    sv_id: SV-216555r1007824_rule
    status: auto
    comment: "Device has local fallback accounts; revert site override to use config result"
EOF

chmod 600 /tmp/cisco-devices/router1/Cisco_IOS_Router_RTR_STIG.tailoring.yaml
```

### Validation

```bash
./docket tailoring check --library-root /tmp/cisco-library --scan-root /tmp/cisco-devices

# Expected: OK for both root (validates full inventory) and host (partial) files
```

### Dry Run

```bash
./docket cisco-cklb --config /tmp/cisco-devices/router1/scan.running-config \
    --target router1 --library-root /tmp/cisco-library \
    --benchmark-id Cisco_IOS_Router_RTR_STIG --dry-run

# Expected output:
# BENCHMARK Cisco_IOS_Router_RTR_STIG: /tmp/cisco-library/U_Cisco_IOS_Router_RTR_STIG_V3R11_Manual-xccdf.xml (sha256 ...)
# TAILORING ROOT /tmp/cisco-library/Cisco_IOS_Router_RTR_STIG.tailoring.yaml (sha256 ...; <N> rules)
# TAILORING HOST /tmp/cisco-devices/router1/Cisco_IOS_Router_RTR_STIG.tailoring.yaml (sha256 ...)
# CONFIG /tmp/cisco-devices/router1/scan.running-config (sha256 ...); <N> controls; open=... not_a_finding=... not_applicable=... not_reviewed=...; no files written
```

### Generate Checklist

```bash
./docket cisco-cklb --config /tmp/cisco-devices/router1/scan.running-config \
    --target router1 --library-root /tmp/cisco-library \
    --benchmark-id Cisco_IOS_Router_RTR_STIG

# Check provenance
cat /tmp/cisco-devices/router1/*-ASSESSMENT.cklb.provenance.json | jq '{
  schema_version,
  tailoring_root: .tailoring_root.path,
  tailoring_host: .tailoring_host.path,
  rule_V216555_layer: .tailoring_rule_layer."V-216555"
}'

# Expected output:
# {
#   "schema_version": 4,
#   "tailoring_root": "/tmp/cisco-library/Cisco_IOS_Router_RTR_STIG.tailoring.yaml",
#   "tailoring_host": "/tmp/cisco-devices/router1/Cisco_IOS_Router_RTR_STIG.tailoring.yaml",
#   "rule_V216555_layer": "host"
# }
```

**Verify:**
- Schema version 4 (Cisco layered provenance)
- Both root and host files recorded
- V-216555 mapped to "host" layer
- Generated checklist has V-216555 using config result (host override applied)

---

## Test 3: Generate Cisco Root Inventory from Scratch

```bash
# Use the included generator to create a new full-inventory root file
./scripts/generate-cisco-tailoring.py --library-root /tmp/cisco-library --dry-run

# Expected: Shows count of benchmarks and rules that would be generated

# Generate (creates .tailoring.yaml for each benchmark not already present)
./scripts/generate-cisco-tailoring.py --library-root /tmp/cisco-library

# Verify generated file is schema v2
head -10 /tmp/cisco-library/Cisco_IOS_Switch_RTR_STIG.tailoring.yaml

# Expected:
# # Cisco STIG root-layer tailoring (full inventory)
# # Generated by generate-cisco-tailoring.py - schema version 2
# # status: auto keeps the config-scored result
# # Override with open/not_a_finding/not_applicable/not_reviewed + comment
# schema_version: 2
# benchmark_id: Cisco_IOS_Switch_RTR_STIG
# benchmark_sha256: <hex>
# rules:
#   - stig_id: V-...
```

---

## Test 4: Validate Preflight Script

```bash
# Run offline preflight (includes tailoring validation)
./scripts/preflight-offline.sh --converter ./docket \
    --input-root /tmp/test-scans --library-root /tmp/test-library

# Expected:
# - TREE OK for both directories
# - TAILORING VALIDATION: validates root and host files
# - CONVERTER DRY RUN: shows loaded tailoring files
# - Preflight complete message

# Try with Cisco
./scripts/preflight-offline.sh --converter ./docket \
    --input-root /tmp/cisco-devices --library-root /tmp/cisco-library
```

---

## Common Issues to Test

### Invalid: Schema v2 root with comment on auto

```bash
cat > /tmp/test-library/RHEL_9_STIG.tailoring.yaml <<EOF
schema_version: 2
benchmark_id: RHEL_9_STIG
benchmark_sha256: $RHEL_SHA
rules:
  - stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    status: auto
    comment: "This should be rejected in schema v2"
EOF

./docket tailoring check --library-root /tmp/test-library

# Expected: ERROR about auto entries must not have comments (schema v2)
```

### Invalid: Host file without comment on auto

```bash
cat > /tmp/test-scans/node1.example.test/RHEL_9_STIG.tailoring.yaml <<EOF
schema_version: 2
benchmark_id: RHEL_9_STIG
benchmark_sha256: $RHEL_SHA
rules:
  - stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    status: auto
EOF

./docket tailoring check --scan-root /tmp/test-scans

# Expected: ERROR about comment required for all host overrides (including auto reverts)
```

### Invalid: Stale benchmark hash

```bash
cat > /tmp/test-scans/node1.example.test/RHEL_9_STIG.tailoring.yaml <<EOF
schema_version: 2
benchmark_id: RHEL_9_STIG
benchmark_sha256: 0000000000000000000000000000000000000000000000000000000000000000
rules:
  - stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    status: auto
    comment: "Stale hash test"
EOF

./docket tailoring check --scan-root /tmp/test-scans

# Expected: ERROR about benchmark_sha256 mismatch
```

---

## Success Criteria

✓ All validation commands pass for valid files
✓ Invalid files (wrong schema, missing comments, stale hashes) are rejected with clear errors
✓ Dry runs show both root and host files loaded
✓ Generated checklists have correct provenance (schema v2 for RHEL, v4 for Cisco)
✓ Per-rule layer tracking correctly shows "root" vs "host" origin
✓ Preflight script validates tailoring files before conversion
✓ Generator creates schema v2 files
✓ Disconnected package includes Cisco root inventories and generator
