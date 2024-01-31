# Fingerprinting

* [ ] **Use `[wafw00f](<https://github.com/EnableSecurity/wafw00f>)` WAF detect \[ `Wafw00f <URL HERE>`]**
* [ ] **Use `[Wappalyzer`]\(**[**https://github.com/wappalyzer/wappalyzer**](https://github.com/wappalyzer/wappalyzer)**) \[ `python3 [main.py](<http://main.py/>) analyze -u <URL HERE>` ]**
* [ ] **Use `[nuclei](<https://github.com/projectdiscovery/nuclei>)` technology template \[ `nuclei --list targets.txt -it nuclei-templates/technologies` ]**
* [ ] **Use `[CMSmap](<https://github.com/dionach/CMSmap>)` for CMS Detecting and penetration testing**
* [ ] **port scanning `naabu -list subdomain-list.txt -p - -exclude-ports 80,443,8080,22,25 -o result.txt`**
* [ ] [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner) | `s3scanner --endpoint-url <https://sfo2.digitaloceanspaces.com> scan --bucket my-bucket`
* [ ] **AEM Hacking** [**0ang3el/aem-hacker (github.com)**](https://github.com/0ang3el/aem-hacker)
* [ ] **Zone-Transfer-Checker →**[https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/)

```bash
Port Scanning 
# <https://github.com/robertdavidgraham/masscan>
# <https://github.com/x90skysn3k/brutespray>
#!/bin/bash
strip=$(echo $1|sed 's/https\\?:\\/\\///')
echo ""
echo "##################################################"
host $strip
echo "##################################################"
echo ""
masscan -p1-65535 $(dig +short $strip|grep -oE "\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b"|head -1) --max-rate 1000 |& tee $strip_scan
------------------------------------------------------------
# Credential bruteforce
Masscan -> Nmap service scan-og -> Brutespray credential bruteforce
1. Use Masscan with the -oG option to get an output in Nmap format
2. Re-scan the output with Nmap version scanning
3. Pass the output to Brutespray which will bruteforce any remote administration protocol found with default & common passwords, and anonymous logins
python brutespray.py --file nmap.gnmap -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt --threads 5 --hosts 5
python Eyewitness.py --prepend-https -f ../domain/tesla.com.lst --all-protocols --headless
--------------------------------------------------------------------
automation ? masscan + nmap
<https://github.com/nullt3r/jfscan>
cat ../../davosalestax.txt | jfscan -p 0-65535 --nmap --nmap-options="-sV"
```
