#!/usr/bin/env bash
# Documentation gate: required files exist and relative markdown links resolve.
set -uo pipefail
cd "$(dirname "$0")/.."
required=(plan.md RULES.md docs/plans/M0.md SECURITY.md CONTRIBUTING.md CODEOWNERS
  docs/adr/0001-record-architecture-decisions.md docs/security/risk-register.md)
fail=0
for f in "${required[@]}"; do [[ -f $f ]] || { echo "MISSING: $f"; fail=1; }; done
while IFS=: read -r file link; do
  target=${link%%#*}
  [[ -z $target ]] && continue
  [[ -e "$(dirname "$file")/$target" ]] || { echo "BROKEN LINK: $file -> $link"; fail=1; }
done < <(grep -rEo --include='*.md' '\]\([^)]+\)' . | grep -vE '\]\((https?:|mailto:|#)' \
         | sed -E 's/^\.\///; s/:\]\(/:/; s/\)$//')
[[ $fail -eq 0 ]] && echo "check-docs: OK"
exit $fail
