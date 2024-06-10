---
description: https://www.youtube.com/watch?v=vFk0XtHfuSg
---

# Attacking Organizations with big scopes

### Subdomain Enumeration

* Use BBOT it is the best [https://github.com/blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot)
* ```
  bbot -t ebay.com -f subdomain-enum
  ```

<figure><img src="../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

### Reverse Whois

* [https://www.whoxy.com/](https://www.whoxy.com/)

### Virtual Hosts Identification

* Using Burp Intruder

<figure><img src="../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

* Using FFUF

```bash
ffuf -w namelist.txt -u http://10.129.184.109 -H "HOST: FUZZ.inlanefreight.htb".
```

* Gobuster

```bash
gobuster vhost -u http://10.129.118.153 -w namelist.txt -p pattern --exclude-length 301 -t 10
```

### ASN Mapping

* [https://bgp.he.net/](https://bgp.he.net/)

```bash
cat iplist | cut -fi 
for i in $(cat iplist | cut -fi); do prips $i >> ips;done
cat fbsubs  
```

### Brute force IPs & Subdomains

```bash
for i in $(cat ips);do ffuf -w subs -u https://$i -H 'Host: FUZZ' -of csv -o $1.csv ; done
```

### Web Fuzzing&#x20;

> Create Custom Wordlist of the target

* Grap All URLs using (gau,katana)

```bash
cat "$RESULTS_DIR/subs.txt" | gau | sort -u >> "$RESULTS_DIR/urls"
cat domains | httpx | katana | sort -u >> "$RESULTS_DIR/urls"
```

* LinkFinder on all urls

```bash
cat urls | rush -j10 "python3 LinkFinder/linkfinder.py -o cli -i {} | sort -u >> ouput"
```

* Sorting

```bash
cat urls output | tr "/" "\n" | sort -u | more 
```

* DORKING\
  The asterisks (\*) are wildcards that match any character(s). In this case, the dork will match any domain or subdomain that contains the word "example".

```bash
site:*<example>* 
site:atlassian>*
site:*<atlassian.*>* 
site:*<*yahoo.*>*
site:*yahoo.*
```

* Bing Dorking
  * Remember the IP list we got from ASN?&#x20;
  * Use bing to find valid hosts on the server

```bash
Dork: “ip:127.0.0.1”
inbody:example
instreamset:(title url):example
```

