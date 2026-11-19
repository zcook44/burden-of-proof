# Bash completion for checkmate.
# Benchmark IDs come from the same docket library config as docket itself.
_checkmate_cfg() {
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

_checkmate_benchmark_ids() {
  local lib=${DOCKET_LIBRARY_ROOT:-$(_checkmate_cfg library_root)}
  [[ -d $lib && ! -L $lib ]] || return 0
  find -P "$lib" -type f -name '*.tailoring.yaml' -printf '%f\n' 2>/dev/null | sed -n 's/^\(.*_STIG\)\.tailoring\.yaml$/\1/p' | sort -u
}

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
    --benchmark)
      COMPREPLY=($(compgen -W "$(_checkmate_benchmark_ids | tr '\n' ' ')" -- "$cur"))
      ;;
    --root|--schema|--export-tailoring)
      local root=${DOCKET_CHECKLIST_ROOT:-$(_checkmate_cfg checklist_root)}
      if [[ -n $root && -d $root ]]; then
        COMPREPLY=($(compgen -W "$(find -P "$root" -mindepth 1 -maxdepth 1 -type d -printf '%p\n' 2>/dev/null | tr '\n' ' ')" -- "$cur"))
      fi
      if [[ ${#COMPREPLY[@]} -eq 0 ]]; then
        COMPREPLY=($(compgen -f -- "$cur"))
      fi
      ;;
  esac
}
complete -F _checkmate_complete checkmate
