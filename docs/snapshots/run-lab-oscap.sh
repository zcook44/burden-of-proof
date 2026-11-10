#!/usr/bin/env bash
# Boot inventory-listed libvirt guests, scan each, then request graceful shutdown.
set -euo pipefail

usage() {
  printf 'Usage: %s [--dry-run] [--limit INVENTORY_HOST]\n' "$0" >&2
  exit 2
}
dry_run=false
limit=''
while (($#)); do
  case $1 in
    --dry-run) dry_run=true; shift ;;
    --limit) (($# >= 2)) && [[ -n $2 && -z $limit ]] || usage; limit=$2; shift 2 ;;
    *) usage ;;
  esac
done

lab=/scratch/ansible
cd "$lab"
uri=qemu:///system
for tool in virsh ansible-inventory ansible ansible-playbook python3; do
  command -v "$tool" >/dev/null || { printf 'Missing %s\n' "$tool" >&2; exit 1; }
done
[[ -f inventory.yml && -f inventory-rhel7.yml && -f playbooks/oscap_scan.yml && -x ansible-ee ]] || {
  printf 'Missing inventory, scan playbook, or RHEL 7 EE wrapper\n' >&2; exit 1;
}
# Inventory is authoritative. Hostnames must also be exact libvirt domain names.
read_inventory() {
  local inventory=$1
  ansible-inventory -i "$inventory" --list | python3 -c '
import json, re, sys
hosts = sorted(json.load(sys.stdin)["_meta"]["hostvars"])
if not hosts or any(not re.fullmatch(r"rhel(7|8|9|10)-[a-z0-9-]+", h) for h in hosts):
    sys.exit("Inventory contains no hosts or an unsafe/unexpected domain name")
print("\n".join(hosts))'
}
modern=$(read_inventory inventory.yml)
legacy=$(read_inventory inventory-rhel7.yml)
mapfile -t modern_hosts <<< "$modern"
mapfile -t legacy_hosts <<< "$legacy"
all_hosts=("${modern_hosts[@]}" "${legacy_hosts[@]}")
declare -A unique=()
for host in "${all_hosts[@]}"; do
  [[ ! ${unique[$host]+yes} ]] || { printf 'Duplicate host: %s\n' "$host" >&2; exit 1; }
  unique[$host]=1
done
hosts=("${all_hosts[@]}")
if [[ -n $limit ]]; then
  [[ ${unique[$limit]+yes} ]] || { printf 'Host not in inventory: %s\n' "$limit" >&2; exit 2; }
  hosts=("$limit")
fi
declare -A initial_state=()
for host in "${hosts[@]}"; do
  virsh -c "$uri" dominfo "$host" >/dev/null || { printf 'Missing domain: %s\n' "$host" >&2; exit 1; }
  initial_state[$host]=$(virsh -c "$uri" domstate "$host")
  case ${initial_state[$host]} in
    running|'shut off') ;;
    *) printf 'Refusing scan of %s in state %s\n' "$host" "${initial_state[$host]}" >&2; exit 1 ;;
  esac
done
# Fail before touching guests if the selected RHEL 7 runtime is unavailable.
if [[ $dry_run == false ]]; then
  for host in "${hosts[@]}"; do
    if [[ $host == rhel7-* ]]; then
      command -v docker >/dev/null || { printf 'Docker is required for RHEL 7\n' >&2; exit 1; }
      docker image inspect local/ansible-rhel7:core-2.16.20 >/dev/null || { printf 'Missing local RHEL 7 EE image\n' >&2; exit 1; }
      break
    fi
  done
fi
printf 'Libvirt: %s; %d selected inventory domain(s)\n' "$uri" "${#hosts[@]}"
for host in "${hosts[@]}"; do
  printf '%-20s %s\n' "$host" "${initial_state[$host]}"
done
if [[ $dry_run == true ]]; then
  printf 'Dry run: would scan selected domains, boot only shut-off guests, and preserve the initial running state of each domain.\n'
  exit 0
fi

shutdown_one() {
  local host=$1 state tries
  state=$(virsh -c "$uri" domstate "$host") || return 1
  if [[ $state != 'shut off' ]]; then
    virsh -c "$uri" shutdown "$host" || return 1
  fi
  for ((tries=0; tries<60; tries++)); do
    state=$(virsh -c "$uri" domstate "$host") || return 1
    [[ $state == 'shut off' ]] && return 0
    sleep 3
  done
  printf 'Still running: %s (no forced power-off)\n' "$host" >&2
  return 1
}
shutdown_started() {
  local original=$? failed=0 host
  trap - EXIT INT TERM
  for host in "${hosts[@]}"; do
    [[ ${started[$host]+yes} ]] || continue
    printf 'Checking graceful shutdown for wrapper-started %s...\n' "$host" >&2
    shutdown_one "$host" || failed=1
  done
  (( original != 0 )) && exit "$original"
  (( failed == 0 )) || exit 1
}
declare -A started=()
trap shutdown_started EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
status=0
for host in "${hosts[@]}"; do
  if [[ ${initial_state[$host]} == 'shut off' ]]; then
    printf 'Starting %s\n' "$host"
    started[$host]=1
    virsh -c "$uri" start "$host"
  elif [[ $(virsh -c "$uri" domstate "$host") != running ]]; then
    printf 'Initially running domain changed state before scan: %s\n' "$host" >&2
    status=1
    continue
  fi
  if [[ $host == rhel7-* ]]; then
    inventory=inventory-rhel7.yml
    ansible_cmd=(./ansible-ee ansible)
    playbook_cmd=(./ansible-ee ansible-playbook)
  else
    inventory=inventory.yml
    ansible_cmd=(ansible)
    playbook_cmd=(ansible-playbook)
  fi
  printf '\nWaiting for %s...\n' "$host"
  if ! "${ansible_cmd[@]}" -i "$inventory" "$host" -m ansible.builtin.wait_for_connection -a 'timeout=300 connect_timeout=8 sleep=5'; then
    printf 'Skipping scan: %s did not become reachable\n' "$host" >&2
    status=1
  elif ! "${playbook_cmd[@]}" -i "$inventory" playbooks/oscap_scan.yml --limit "$host"; then
    printf 'Scan failed: %s\n' "$host" >&2
    status=1
  fi
  if [[ ${started[$host]+yes} ]]; then
    printf 'Shutting down wrapper-started %s\n' "$host"
    if shutdown_one "$host"; then
      unset 'started[$host]'
    else
      status=1
    fi
  else
    printf 'Leaving initially running %s powered on\n' "$host"
  fi
done
exit "$status"
