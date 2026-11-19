# Bash completion for docket.
# Flags, subcommands, and — when a library or scan root is configured —
# benchmark IDs and host directory names. Private file contents are not read
# beyond benchmark id attributes and directory names.
_docket_cfg() {
  local key=$1 file line
  file=${DOCKET_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/docket/config.yaml}
  [[ -f $file && ! -L $file ]] || return 0
  line=$(sed -n "s/^${key}:[[:space:]]*//p" "$file" | head -n 1)
  line=${line%%#*}
  line=${line#"${line%%[![:space:]]*}"}
  line=${line%"${line##*[![:space:]]}"}
  line=${line#\"}; line=${line%\"}
  line=${line#\'}; line=${line%\'}
  printf '%s' "$line"
}

_docket_library() {
  if [[ -n ${DOCKET_LIBRARY_ROOT:-} ]]; then
    printf '%s' "$DOCKET_LIBRARY_ROOT"
    return
  fi
  _docket_cfg library_root
}

_docket_benchmark_ids() {
  local lib=$(_docket_library) id
  [[ -d $lib && ! -L $lib ]] || return 0
  while IFS= read -r id; do
    [[ -n $id ]] && printf '%s\n' "$id"
  done < <(
    find -P "$lib" -type f -name '*.tailoring.yaml' -printf '%f\n' 2>/dev/null | sed -n 's/^\(.*_STIG\)\.tailoring\.yaml$/\1/p'
    find -P "$lib" -type f -name 'U_RHEL_*_Manual-xccdf.xml' -printf '%f\n' 2>/dev/null | sed -n 's/^U_\(RHEL_[0-9]*_STIG\)_V[0-9]*R[0-9]*_Manual-xccdf\.xml$/\1/p'
    find -P "$lib" -type f -name 'U_*Manual-xccdf.xml' -print0 2>/dev/null | while IFS= read -r -d '' f; do
      grep -o -m 1 'id="[A-Za-z0-9_-]*_STIG"' "$f" 2>/dev/null | head -n 1 | sed 's/^id="//; s/"$//'
    done
  ) | sort -u
}

_docket_host_dirs() {
  local key root name
  for key in input_root evidence_root; do
    root=${DOCKET_INPUT_ROOT:-}
    [[ $key == evidence_root ]] && root=${DOCKET_EVIDENCE_ROOT:-$root}
    if [[ $key == input_root && -z ${DOCKET_INPUT_ROOT:-} ]]; then
      root=$(_docket_cfg input_root)
    fi
    if [[ $key == evidence_root && -z ${DOCKET_EVIDENCE_ROOT:-} ]]; then
      root=$(_docket_cfg evidence_root)
    fi
    [[ -d $root && ! -L $root ]] || continue
    find -P "$root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null
  done | sort -u
}

_docket_complete() {
  local cur prev cmd sub
  COMPREPLY=()
  cur=${COMP_WORDS[COMP_CWORD]}
  prev=${COMP_WORDS[COMP_CWORD-1]}
  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=($(compgen -W "asset-check reconcile draft-cklb batch-cklb cisco-cklb cisco-batch cisco-xccdf xccdf-cklb tailoring quarter" -- "$cur"))
    return
  fi
  cmd=${COMP_WORDS[1]}
  if [[ $cmd == tailoring && ${COMP_CWORD} -eq 2 ]]; then
    COMPREPLY=($(compgen -W "check rehash migrate" -- "$cur"))
    return
  fi
  sub=""
  [[ $cmd == tailoring && ${COMP_CWORD} -ge 2 ]] && sub=${COMP_WORDS[2]}
  local flags=""
  case $cmd in
    asset-check) flags="--asset --pre --host" ;;
    reconcile) flags="--scan --benchmark --out" ;;
    draft-cklb) flags="--scan --benchmark --out --html-report --arf --assessment-view --operator-approved" ;;
    batch-cklb) flags="--input-root --library-root --benchmark --dry-run" ;;
    cisco-cklb) flags="--config --target --benchmark --library-root --benchmark-id --port-roles --dry-run" ;;
    cisco-batch) flags="--manifest --evidence-root --library-root --output-root --dry-run" ;;
    cisco-xccdf) flags="--config --target --fqdn --ip --mac --role --target-type --technology --benchmark --library-root --benchmark-id --port-roles --out" ;;
    xccdf-cklb) flags="--results --benchmark --library-root --out" ;;
    quarter) flags="--library-root --input-root --evidence-root --manifest --output-root --dry-run" ;;
    tailoring)
      case $sub in
        check) flags="--library-root --scan-root --benchmark --scan-dir" ;;
        rehash) flags="--library-root --dry-run" ;;
        migrate) flags="--library-root --scan-root --dry-run" ;;
      esac
      ;;
    *) return ;;
  esac
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    return
  fi
  case $prev in
    --benchmark-id)
      COMPREPLY=($(compgen -W "$(_docket_benchmark_ids | tr '\n' ' ')" -- "$cur"))
      return
      ;;
    --target|--scan-dir)
      COMPREPLY=($(compgen -W "$(_docket_host_dirs | tr '\n' ' ')" -- "$cur"))
      return
      ;;
    --dry-run|--assessment-view|--operator-approved) return ;;
    *) COMPREPLY=($(compgen -f -- "$cur")) ;;
  esac
}
complete -F _docket_complete docket
