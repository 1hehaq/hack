#!/bin/bash

# subfinder, httpx, katana, gau, arjun, curl, wpscan, dirsearch, ffuf, subzy, corsy, nuclei, naabu, nmap, masscan, assetfinder, httprobe

DOMAIN="$1"
OUTPUT_DIR="./recon/$DOMAIN"
WORDLIST_DIR="$2"

mkdir -p $OUTPUT_DIR/{subdomains,urls,params,vulns,scans,reports}

check_tools() {
    required_tools=("subfinder" "httpx" "katana" "gau" "arjun" "curl" "wpscan" "dirsearch" "ffuf" "subzy" "python3" "nuclei" "naabu" "nmap" "masscan" "assetfinder" "httprobe")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo "[-] Error: $tool not found. Please install it first."
            exit 1
        fi
    done
}

run_subdomain_enum() {
    echo "[+] Starting subdomain enumeration..."
    subfinder -d $DOMAIN -all -recursive -o $OUTPUT_DIR/subdomains/subdomains.txt
    
    echo "[+] Filtering live subdomains..."
    cat $OUTPUT_DIR/subdomains/subdomains.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 -o $OUTPUT_DIR/subdomains/live_subdomains.txt
}

fetch_urls() {
    echo "[+] Gathering URLs..."
    katana -u $OUTPUT_DIR/subdomains/live_subdomains.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o $OUTPUT_DIR/urls/all_urls.txt
    
    echo "[+] Finding sensitive files..."
    grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5" $OUTPUT_DIR/urls/all_urls.txt > $OUTPUT_DIR/urls/sensitive_files.txt
}

parameter_discovery() {
    echo "[+] Parameter discovery..."
    katana -u $OUTPUT_DIR/subdomains/live_subdomains.txt -d 5 | grep '=' | urldedupe | anew $OUTPUT_DIR/params/parameters.txt
    cat $OUTPUT_DIR/params/parameters.txt | sed 's/=.*/=/' > $OUTPUT_DIR/params/clean_parameters.txt
    
    gau --mc 200 $DOMAIN | urldedupe > $OUTPUT_DIR/urls/gau_urls.txt
    grep -E ".php|.asp|.aspx|.jspx|.jsp" $OUTPUT_DIR/urls/gau_urls.txt | grep '=' | sort > $OUTPUT_DIR/params/dynamic_urls.txt
}

cors_checks() {
    echo "[+] Checking for CORS vulnerabilities..."
    while read url; do
        curl -H "Origin: http://evil.com" -I $url 2>/dev/null | grep -i "access-control-allow-origin" >> $OUTPUT_DIR/vulns/cors_issues.txt
    done < $OUTPUT_DIR/urls/all_urls.txt
}

wordpress_scan() {
    echo "[+] WordPress scanning..."
    wpscan --url https://$DOMAIN --disable-tls-checks --api-token YOUR_API_TOKEN -e at,ap,u --plugins-detection aggressive --force -o $OUTPUT_DIR/scans/wpscan.txt
}

lfi_checks() {
    echo "[+] LFI testing..."
    cat $OUTPUT_DIR/urls/all_urls.txt | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w $WORDLIST_DIR/Fuzzing/LFI/LFI-Jhaddix.txt -c -mr "root:" -o $OUTPUT_DIR/vulns/lfi_results.txt
}

directory_bruteforce() {
    echo "[+] Directory brute-forcing..."
    dirsearch -u https://$DOMAIN -e php,html,js,txt,bak,zip,json,xml -t 50 --random-agent -R 3 -t 20 --exclude-status=404 -o $OUTPUT_DIR/scans/dirsearch.txt
    
    ffuf -w $WORDLIST_DIR/Discovery/Web-Content/directory-list-2.3-big.txt -u https://$DOMAIN/FUZZ -fc 400-403,404,5XX -recursion -e .php,.html,.js -ac -c -t 100 -o $OUTPUT_DIR/scans/ffuf_results.json
}

js_analysis() {
    echo "[+] JavaScript file analysis..."
    katana -u $OUTPUT_DIR/subdomains/live_subdomains.txt -d 5 | grep -E "\.js$" | nuclei -t ~/nuclei-templates/http/exposures/ -c 30 -o $OUTPUT_DIR/vulns/js_exposures.txt
}

subdomain_takeover() {
    echo "[+] Checking for subdomain takeovers..."
    subzy run --targets $OUTPUT_DIR/subdomains/live_subdomains.txt --concurrency 100 --hide_fails --verify_ssl -o $OUTPUT_DIR/vulns/subtakeover.txt
}

xss_checks() {
    echo "[+] XSS testing..."
    cat $OUTPUT_DIR/params/clean_parameters.txt | Gxss | kxss | tee $OUTPUT_DIR/vulns/xss_candidates.txt
    ffuf -request xss -request-proto https -w $WORDLIST_DIR/Fuzzing/XSS/XSS-Test.txt -c -mr "<script>alert(1)</script>" -o $OUTPUT_DIR/vulns/xss_results.txt
}

content_type_checks() {
    echo "[+] Content-type verification..."
    httpx -l $OUTPUT_DIR/urls/all_urls.txt -status-code -content-type -o $OUTPUT_DIR/reports/content_types.txt
}

nmap_scan() {
    echo "[+] Port scanning..."
    naabu -host $DOMAIN -c 50 -nmap-cli 'nmap -sV -sC -oA $OUTPUT_DIR/scans/full_scan' 
    masscan -p0-65535 $DOMAIN --rate 100000 -oG $OUTPUT_DIR/scans/masscan.txt
}

generate_report() {
    echo "[+] Generating final report..."
    echo "=== Recon Report for $DOMAIN ===" > $OUTPUT_DIR/report.txt
    echo "Subdomains found: $(wc -l $OUTPUT_DIR/subdomains/live_subdomains.txt)" >> $OUTPUT_DIR/report.txt
    echo "Vulnerabilities found:" >> $OUTPUT_DIR/report.txt
    grep -R -i "vulnerable" $OUTPUT_DIR/vulns/ >> $OUTPUT_DIR/report.txt
    echo "Full results available in: $OUTPUT_DIR" >> $OUTPUT_DIR/report.txt
}

main() {
    check_tools
    run_subdomain_enum
    fetch_urls
    parameter_discovery
    cors_checks
    wordpress_scan
    lfi_checks
    directory_bruteforce
    js_analysis
    subdomain_takeover
    xss_checks
    content_type_checks
    nmap_scan
    generate_report
    echo "[+] Scan complete! Results saved to $OUTPUT_DIR"
}

if [ -z "$1" ]; then
    echo "Usage: $0 example.com"
    exit 1
fi

main
