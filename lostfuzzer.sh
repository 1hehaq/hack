#!/bin/bash

RED='\033[91m'
GREEN='\033[92m'
RESET='\033[0m'

echo -e "${RED}"
cat << "EOF"
 ______            _____________
___  /______________  /___  __/___  _________________________
__  /_  __ \_  ___/  __/_  /_ _  / / /__  /__  /_  _ \_  ___/
_  / / /_/ /(__  )/ /_ _  __/ / /_/ /__  /__  /_/  __/  /
_/  \____//____/ \__/ /_/    \__,_/ _____/____/\___//_/

                                       by ~/.coffinxp@lostsec
EOF
echo -e "${RESET}"

REQUIRED_TOOLS=("gau" "uro" "httpx" "nuclei")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[ERROR] $tool is not installed. Please install it and try again.${RESET}"
        exit 1
    fi
done

read -p "Enter the target domain or subdomains list file: " INPUT
if [ -z "$INPUT" ]; then
    echo -e "${RED}[ERROR] Input cannot be empty.${RESET}"
    exit 1
fi

if [ -f "$INPUT" ]; then
    TARGETS=$(cat "$INPUT")
else
    TARGETS="$INPUT"
fi

TARGETS=$(echo "$TARGETS" | sed 's|https\?://||g')

GAU_FILE=$(mktemp)
FILTERED_URLS_FILE="filtered_urls.txt"
NUCLEI_RESULTS="nuclei_results.txt"

echo -e "${GREEN}[INFO] Fetching URLs using gau in parallel...${RESET}"
echo "$TARGETS" | xargs -P10 -I{} sh -c 'gau "{}" >> "$1"' _ "$GAU_FILE"

echo -e "${GREEN}[INFO] Filtering URLs with query parameters...${RESET}"
grep -E '\?[^=]+=.+$' "$GAU_FILE" | uro | sort -u > "$FILTERED_URLS_FILE"

echo -e "${GREEN}[INFO] Checking for live URLs using httpx-toolkit...${RESET}"
httpx -silent -t 300 -rl 200 < "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp"
mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"

echo -e "${GREEN}[INFO] Running nuclei for DAST scanning...${RESET}"
nuclei -dast -retries 2 -silent -o "$NUCLEI_RESULTS" < "$FILTERED_URLS_FILE"

echo -e "${GREEN}[INFO] Nuclei results saved to $NUCLEI_RESULTS${RESET}"
echo -e "${GREEN}[INFO] Filtered URLs saved to $FILTERED_URLS_FILE for manual testing.${RESET}"
echo -e "${GREEN}[INFO] Automation completed successfully!${RESET}"

if [ ! -s "$NUCLEI_RESULTS" ]; then
    echo -e "${GREEN}[INFO] No vulnerable URLs found.${RESET}"
else
    echo -e "${GREEN}[INFO] Vulnerabilities were detected. Check $NUCLEI_RESULTS for details.${RESET}"
fi
