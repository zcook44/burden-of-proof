# Bash completion for docket. Subcommands and flags only.
# Completing benchmark IDs or hostnames would mean reading private trees from the shell.
# Source this file, or let bash-completion load it from a completions directory.
_docket_complete() {
  local cur prev cmd
  COMPREPLY=()
  cur=${COMP_WORDS[COMP_CWORD]}
  prev=${COMP_WORDS[COMP_CWORD-1]}
  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=($(compgen -W "asset-check reconcile draft-cklb batch-cklb cisco-cklb cisco-batch cisco-xccdf xccdf-cklb" -- "$cur"))
    return
  fi
  cmd=${COMP_WORDS[1]}
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
    *) return ;;
  esac
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    return
  fi
  case $prev in
    --dry-run|--assessment-view|--operator-approved) return ;;
    *) COMPREPLY=($(compgen -f -- "$cur")) ;;
  esac
}
complete -F _docket_complete docket
