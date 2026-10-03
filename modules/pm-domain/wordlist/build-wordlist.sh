#!/bin/sh
# Rebuilds src/main/resources/pm/domain/generate/wordlist.txt (ADR 0012 §3).
# Input: macOS /usr/share/dict/web2 (SHA-256 be41ad97963bf8dabedd5871d5d691596175269d540956b0f9965a885c2bbab9).
# Keeps distinct all-lowercase 4-5 letter words, drops every word in excluded.txt (slurs,
# obscenities, sexual terms), then takes 8192 evenly spaced words so the list is exactly 13 bits/word.
set -eu
here=$(dirname "$0")
dict=${1:-/usr/share/dict/web2}
grep -E '^[a-z]{4,5}$' "$dict" | LC_ALL=C sort -u \
  | grep -vxF -f "$here/excluded.txt" \
  | awk '{w[NR-1]=$0} END{n=NR; for(i=0;i<8192;i++){print w[int(i*n/8192)]}}'
