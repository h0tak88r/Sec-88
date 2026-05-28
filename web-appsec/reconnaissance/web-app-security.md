---
description: Deep Subdomain Enumeration Notes
---

# Subdomain Enumeration

### What's the need?

* A good subdomain enumeration will help you find those hidden/untouched subdomains, resulting lesser people finding bugs on that particular domain. Hence, fewer **duplicates**.
* Finding applications running on hidden, forgotten (by the organization) sub-domains may lead to uncovering critical vulnerabilities.
* For large organizations, to find what services they have exposed to the internet while performing an internal pentest.
* The methodology of collecting subdomains from tools like `amass`, `subfinder`, `findomain` and directly sending them to httpx/httprobe is **absolutely wrong**. Instead, you should first DNS resolve them using tools like [puredns](https://github.com/d3mondev/puredns) or [shuffledns](https://github.com/projectdiscovery/shuffledns).

💡 There are many tools that you may think are better than the ones mentioned in some techniques, In this methodology I focus on the techniquess part You can go ahead and try your preferred Tools

**From this image, you can get the idea of horizontal/vertical domain correlation:**

![image](https://github.com/h0tak88r/h0tak88r.github.io/assets/108616378/66dae1c9-af03-48e9-8bab-df516c70cb21)

## **Horizontal Enumeration**

> These enumeration methods can go out of scope and backfire you. Do it with caution!

#### Discovering the IP space

1. First We need to get the **ASN** from websites like [https://bgp.he.net/](https://bgp.he.net/) or you can use any other tool that gets the job done

> **ASN**(Autonomous System Number) is a unique identifier for a set of IP-ranges an organizations owns. Very large organizations such as Apple, GitHub, Tesla have their own significant IP space.

2. find out the IP ranges that reside inside that ASN. For this, we will use a tool called **whois.**

```bash
 apt-get install whois
 whois -h whois.radb.net  -- '-i origin AS8983' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq -u > ip_ranges.txt
```

#### PTR records (Reverse DNS)

Since we already know the IP space of an organization we can, we can **reverse query** the IP addresses and find the valid domains

**DNS PTR records (pointer record)** helps us to achieve this. We can query a **PTR record** of an IP address and find the associated **hostname/domain name**.

1.  Chain the tools [**Mapcidr**](https://github.com/projectdiscovery/mapcidr) **-** [**Dnsx**](https://github.com/projectdiscovery/dnsx) together in one liner

    ```bash
    cat ip_anges.txt | mapcidr -silent | dnsx -ptr -resp-only -o ptr_recrds.txt
    ```

> When an IP range is given to `mapcidr` through stdin(standard input), it performs **expansion of the CIDR range**, spitting out each **IP address** from the range onto a new line. Now when **`dnsx`** receives each IP address from stdin, it performs **reverse DNS** and checks for **PTR record**. If, found it gives us back the **hostname/domain name**.

#### **Favicon Search**

> **What is a favicon?** The image/icon shown on the left-hand side of a tab is called as **favicon.ico**

![image](https://github.com/h0tak88r/h0tak88r.github.io/assets/108616378/47062d80-9cb4-4a37-a556-623af8c722c6)

1. View source of the website page
2. Search for favicon.ico
3. download it from the link you got from source code
4.  Calculate the hash using python3

    ```python
    import hashlib

    def calculate_favicon_hash(file_path):
        with open(file_path, 'rb') as file:
            favicon_data = file.read()
            favicon_hash = hashlib.md5(favicon_data).hexdigest()
        return favicon_hash

    favicon_path = '/path/to/favicon.ico'
    favicon_hash = calculate_favicon_hash(favicon_path)
    print(favicon_hash)
    ```
5. Shodan Search `http.favicon.hash:[Favicon hash here]`

> **Hint**: Generally the favicon hash of any spring boot application is `116323821`**.** So we can use this shodan filter \*\*\*\*`http.favicon.hash:116323821`, You can use different favicon hashes for different services.

#### Automation ?

Use https://github.com/devanshbatham/FavFreak

```bash
cat urls.txt | python3 favfreak.py -o output
http.favicon.hash:-<hash>
```

#### Finding related domains/acquisitions

* Ask **CHATGPT**
* Search on Google ,wikibedia ro any other sources
* Visit https://tools.whoisxmlapi.com/reverse-whois-search

## **Vertical Enumeration**

### Passive Enum

> Here you have a lot of tools that do the job, but it is not about the tools; it is about the technique or the way you do it. You must use the tool with all of the APIs you can get.

Personally I prefer `subfinder`

**Subfinder** \[ `subfinder -d test.com -o passive2.txt -all` ]

Here is a list of free-api websites

1. censys
2. bevigil
3. binaryedge
4. cerspotter
5. whoisxmlapi
6. fofa
7. shodan
8. github
9. virustotal
10. zoomeye

* There are in total around [**90 passive DNS sources/services**](https://gist.github.com/sidxparab/22c54fd0b64492b6ae3224db8c706228) that provide such datasets to query them
* You can use another tool that use free services and apis to do subdomain enumeration [https://github.com/sl4x0/subfree](https://github.com/sl4x0/subfree)
* [https://dnsdumpster.com/](https://dnsdumpster.com/) → FREE domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process.
* https://chaos.projectdiscovery.io/#/→ it is like database or something here u can get all subdomains for public bug bounty programs , Yeah it is useless when you work in a private ones

#### Another Ways (I don’t use )

* **Internet Archive →** [district →](https://github.com/lc/gau) [waybackurls](https://github.com/tomnomnom/waybackurls)
* **Github Scraping →** [github-subdomains](https://github.com/gwen001/github-subdomains)
* **GitLab Scraping →** [gitlab-subdomains](https://github.com/gwen001/gitlab-subdomains)

#### **Recursive Enumeration**

* In easy words, we again run tools like Amass, Subfinder, Assetfinder again each of the subdomains that were found.
* If you have set up API keys, this technique may consume your entire querying quota
* This technique is only useful when your target has a large number of multi-level subdomains\*(not effective for small & medium scope targets).\*
* It is a huge use of resources and power and takes time to return the final results so be careful and make this technique the last step of you process if you can :)))
* Do it exclusively on a validated list of subdomains that you have collected through other **Passive + Active** techniques.

**Workflow:**

1. Read the list of subdomains from the file "subdomains.txt".
2. Process the subdomains in two steps: **a)** Find the Top-10 most frequent occuring **Second-Level Domain** names with the help of tools like `cut`, `sort`, `rev`, `uniq` **b)** Find the Top-10 most frequent occuring **Third-Level domains**.
3. Now run passive subdomain enumeration on these 10 Second-level domain names and 10 Third-level domain names using tools like **amass, subfinder, assetfinder, findomain.**
4. Keep appending the results to `passive_recursive.txt` file.
5. Now after finding out the a list of domain names, run puredns to DNS resolve them and find the alive subdomains

#### Automation

```bash
#!/bin/bash

go install -v github.com/tomnomnom/anew@latest
subdomain_list="subdomains.txt"

for sub in $( ( cat $subdomain_list | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
    subfinder -d $sub -silent -max-time 2 | anew -q passive_recursive.txt
    assetfinder --subs-only $sub | anew -q passive_recursive.txt
    amass enum -timeout 2 -passive -d $sub | anew -q passive_recursive.txt
    findomain --quiet -t $sub | anew -q passive_recursive.txt
done
```

### Active Enum

#### **DNS Brute Forcing**

**What is DNS bruteforcing?**

* We try to identify all possible subdomains using a very large word list.
* By applying brute force to the domain or hostname, we get a very big list of subdomains that contains all possible subdomains from the wordlist + subdomain.
* We pass this list to a tool that does DNS resolution and save the valid subdomains.

**Tool**

* [**Puredns**](https://github.com/d3mondev/puredns) outperforms the work of DNS bruteforcing & resolving millions of domains at once. There exists various open-source tools, but puredns is the best in terms of speed & accuracy of the results produced.

**Workflow**

1. Sanitize the input wordlist
2. Mass resolve using the public resolvers
3. Wildcard detection
4.  Validating results with trusted resolvers

    > The DNS resolution process uses "[**Trusted DNS resolvers**](https://raw.githubusercontent.com/six2dez/resolvers\_reconftw/main/resolvers\_trusted.txt)" inorder to verify the results for the final time. This double resolution process helps in discarding those false-positive results. The main advantage of using Trusted DNS resolvers like Google DNS (`8.8.8.8` , `8.8.4.4`), Cloudflare(`1.1.1.1`) is to avoid DNS poisoned responses or other discrepancies that normal resolvers cause.

```bash
#Prerequisites
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo make install

#Installing the tool
go install github.com/d3mondev/puredns/v2@latest

# Download Resolvers List
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt

# You even can make yours
git clone https://github.com/vortexau/dnsvalidator.git
cd dnsvalidator/
pip3 install -r requirements.txt
pip3  install setuptools==58.2.0
python3 setup.py install
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt

# Download dns wordlist  
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt 

# Brute Forcing
puredns bruteforce best-dns-wordlist.txt example.com -r resolvers.txt -w dns_bf.txt
```

#### **Permutations**

**Workflow:**

* First, we need to make a combined list of all the subdomains(valid/invalid) we collected from all the above steps whose permutations we will create.
* To generate combinations you need to provide a small wordlist that contains common domain names like admin, demo, backup, api, ftp, email, etc.
* [This](https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw) is a good wordlist of 1K permutation words that we will need.

1. generate various combinations or permutations of a root domain
2. DNS resolve them and check if we get any valid subdomains

```python
# Permutation words Wordlist
wget https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw
# Run 
gotator -sub subdomains.txt -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt
# DNS resolve them and check for valid ones.
puredns resolve permutations.txt -r resolvers.txt > resolved_perms
# Hint: Collect subdomains that is not valid and make compinations then resolve them u may git valid unique subdomains that is hard to find 
gotator -sub not_vali_subs.txt -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt
```

#### **Google analytics**

We can perform a reverse search and find all the subdomains having the same Google Analytic ID. Hence, it helps us find acquisitions and unique domains.

> Most organizations use [Google Analytics](https://analytics.google.com/analytics/web/) to track website visitors and for more statistics. Generally, they have the same Google Analytics ID across all subdomains of a root domain

```bash
 git clone https://github.com/Josue87/AnalyticsRelationships.git
 cd AnalyticsRelationships/Python
 sudo pip3 install -r requirements.txt
 python3 analyticsrelationships.py -u https://www.example.com
```

* [ ] **TLS, CSP, CNAME Probing**
* [ ] In order to use HTTPS, the website owner needs to issue an SSL(Secure Socket Layer) certificate.
*   [ ] CSP headers sometimes contain **domains/subdomains** from where the content is usually imported

    ```bash
    go install github.com/glebarez/cero@latest
    #tls
    cero in.search.yahoo.com | sed 's/^*.//' | grep -e "\." | sort -u
    #cls
    cat subdomains.txt | httpx -csp-probe -status-code -retries 2 -no-color | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew -q csp_subdomains.txt
    # cname
    dnsx -retry 3 -cname -l subdomains.txt
    ```

#### **Scraping(JS/Source code)**

**Workflow**

1.  Web probing subdomains

    ```bash
    cat subdomains.txt | httpx -random-agent -retries 2 -no-color -o probed_tmp_scrap.txt
    ```
2.  Now, that we have web probed URLs, we can send them for crawling to gospider

    ```bash
    gospider -S probed_tmp_scrap.txt --js -t 50 -d 3 --sitemap --robots -w -r > gospider.txt
    ```
3.  Cleaning the output

    ```bash
    sed -i '/^.\{2048\}./d' gospider.txt
    or 
    cat gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".example.com$" | sort -u scrap_subs.txt
    ```
4.  Resolving our target subdomains

    ```bash
    puredns resolve scrap_subs.txt -w scrap_subs_resolved.txt -r resolvers.txt
    ```

### Finish Work

```bash
cd subs/
cat horizontal/ptr_records.txt | sort -u > horizontal.txt
cat Vertical/Active/* | sort -u > active.txt
cat Vertical/Pssive/* | sort -u > passive.txt
cat * | sort -u > all_subs.txt
cat all_subs.txt | httpx -random-agent -retries 2 -no-color -o filtered_subs.txt
```
