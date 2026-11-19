# Bash completion for checkmate. Flags only.
# Completing checklist directories would mean the shell walking private evidence.
_checkmate_complete() {
  local cur prev
  COMPREPLY=()
  cur=${COMP_WORDS[COMP_CWORD]}
  prev=${COMP_WORDS[COMP_CWORD-1]}
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "--root --benchmark --list --validate --schema --export-tailoring" -- "$cur"))
    return
  fi
  case $prev in
    --root|--schema|--export-tailoring) COMPREPLY=($(compgen -f -- "$cur")) ;;
  esac
}
complete -F _checkmate_complete checkmate
