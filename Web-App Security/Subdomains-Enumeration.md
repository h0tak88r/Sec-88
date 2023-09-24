# Horizontal Enumeration

1. **Discovering the IP space**

```
# get the ASN from websites likehttps://bgp.he.net/# find out the IP ranges that reside inside that ASNapt-get install whoiswhois -h whois.radb.net  -- '-i origin AS8983' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq -u > ip_ranges.txt
```

1. **PTR records (Reverse DNS)**

```
cat ip_anges.txt | mapcidr -silent | dnsx -ptr -resp-only -o ptr_recrds.txt
```

1. **Favicon Search**

```
cat urls.txt | python3 favfreak.py -o outputhttp.favicon.hash:-<hash>
```

1. **Finding related domains/acquisitions**

- use **CHATGPT,** Google, wikipedia,
- [https://tools.whoisxmlapi.com/reverse-whois-search](https://tools.whoisxmlapi.com/reverse-whois-search)

# Vertical Enumeration

### Passive Enum

1. **Subfinder** [ `subfinder -d test.com -o subs/subfinder.txt -all` ] (it is important to add apis to get better results go to the detailed blog if u diddn`t git it
    - **Internet Archive →** [district →](https://github.com/lc/gau) [waybackurls](https://github.com/tomnomnom/waybackurls)
    - **Github Scraping →** [github-subdomains](https://github.com/gwen001/github-subdomains)
    - **GitLab Scraping →** [gitlab-subdomains](https://github.com/gwen001/gitlab-subdomains)
    - **Shodan Dorking**
2. [https://github.com/sl4x0/subfree](https://github.com/sl4x0/subfree) | `bash subfree.sh domain.com`
3. [https://chaos.projectdiscovery.io/#/](https://chaos.projectdiscovery.io/#/) → it is like database or something here u can get all subdomains for public bug bounty programs, yeah it is useless when you work in a private one.
4. [https://dnsdumpster.com/](https://dnsdumpster.com/) → FREE domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process.
5. [https://otx.alienvault.com/indicator/domain/<target.com>](https://otx.alienvault.com/indicator/domain/%3Ctarget.com%3E) → domain_Analysis that provide subdomains

### Active Enum

1. **DNS Brute Forcing [ using puredns]**
    
    ```
    \#Prerequisitesgit clone https://github.com/blechschmidt/massdns.gitcd massdnsmakesudo make install\#Installing the toolgo install github.com/d3mondev/puredns/v2@latest# Download Resolvers Listwget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt# You even can make yoursgit clone https://github.com/vortexau/dnsvalidator.gitcd dnsvalidator/pip3 install -r requirements.txtpip3  install setuptools==58.2.0python3 setup.py installdnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt --silent# Download dns wordlistwget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt# Brute Forcingpuredns bruteforce Wordlists/dns/dns_9m.txt davosalestax.com -r Wordlists/dns/valid_resolvers.txt -w subs/dns_bf.txt
    ```
    
2. **Permutations**
    
    ```
    # Permutation words Wordlistwget https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw# Rungotator -sub subs/inscope.txt -perm Wordlists/dns/dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt# DNS resolve them and check for valid ones.puredns resolve perms.txt -r Wordlists/dns/valid_resolvers.txt -w subs/resolved_perms.txt# Hint: Collect subdomains that is not valid and make compinations then resolve them u may git valid unique subdomains that is hard to findgotator -sub not_vali_subs.txt -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt
    ```
    
3. **Google Analytics**
    
    ```
     git clone https://github.com/Josue87/AnalyticsRelationships.git cd AnalyticsRelationships/Python sudo pip3 install -r requirements.txtpython3 AnalyticsRelationships/Python/analyticsrelationships.py -u iagcargo.com
    ```
    
4. **TLS, CSP, CNAME Probing**
    
    ```
    go install github.com/glebarez/cero@latest
    #tls
    cero in.search.yahoo.com | sed 's/^*.//' | grep -e "\." | sort -u\#clscat subdomains.txt | httpx -csp-probe -status-code -retries 2 -no-color | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew -q csp_subdomains.txt# cnamednsx -retry 3 -cname -l subdomains.txt
    # tls from asn numbers
     echo ASNUM | asmap -silent | tlsx -san -cn -silent -resp-only | sort -u 
    
    ```
    
5. **Scraping(JS/Source code)**
    
    ```
    # Web probing subdomainscat subdomains.txt | httpx -random-agent -retries 2 -no-color -o probed_tmp_scrap.txt# Now, that we have web probed URLs, we can send them for crawling to gospidergospider -S probed_tmp_scrap.txt --js -t 50 -d 3 --sitemap --robots -w -r > gospider.txt\#Cleaning the outputsed -i '/^.\{2048\}./d' gospider.txtcat gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".$domain$" | sort -u scrap_subs.txt# Resolving our target subdomains puredns resolve scrap_subs.txt -w scrap_subs_resolved.txt -r resolvers.txt
    ```
    

## Recursive Enumeration

```
#!/bin/bashgo install -v github.com/tomnomnom/anew@latestsubdomain_list="subdomains.txt"for sub in $( ( cat $subdomain_list | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do     subfinder -d $sub -silent -max-time 2 | anew -q passive_recursive.txt    assetfinder --subs-only $sub | anew -q passive_recursive.txt    amass enum -timeout 2 -passive -d $sub | anew -q passive_recursive.txt    findomain --quiet -t $sub | anew -q passive_recursive.txtdone
```

## Finish Work

```
cd subs/cat horizontal/ptr_records.txt | sort -u > horizontal.txtcat Vertical/Active/* | sort -u > active.txtcat Vertical/Pssive/* | sort -u > passive.txtcat * | sort -u > all_subs.txtcat all_subs.txt | httpx -random-agent -retries 2 -no-color -o filtered_hosts.txtcat filtered_subs.txt | gf interestingsubs > valid_interestingsubs.txthttpx -l filtered_hosts.txt -srd subsScreens -ss
```

# AutoSubRecon

```
#!/bin/bash# Define directories and filessubs_dir="subs/"wordlists_dir="Wordlists/"# Make directories if they don't existmkdir -p "$subs_dir"mkdir -p "$wordlists_dir/dns"# Define colorsRED='\033[0;31m'GREEN='\033[0;32m'YELLOW='\033[0;33m'BLUE='\033[0;34m'NC='\033[0m' # No Colorascii_art='''  /\   _|_ _ (~   |_ |~) _  _ _  _ /~~\|_|| (_)_)|_||_)|~\(/_(_(_)| |                                        by @h0tak88r'''echo -e "${RED}$ascii_art${NC}"# Set the target domaintarget_domain="$1"# Check if target_domain is providedif [ -z "$target_domain" ]; then  echo "Please provide the target domain as an argument."  exit 1fi# Passive subdomain enumerationecho -e "${RED}[+] Let's start with passive subdomain enumeration${NC}"# URLs to fetch subdomains from various sourcesurls=(    "https://rapiddns.io/subdomain/$target_domain?full=1\#result"    "http://web.archive.org/cdx/search/cdx?url=*.$target_domain/*&output=text&fl=original&collapse=urlkey"    "https://crt.sh/?q=%.$target_domain"    "https://crt.sh/?q=%.%.$target_domain"    "https://crt.sh/?q=%.%.%.$target_domain"    "https://crt.sh/?q=%.%.%.%.$target_domain"    "https://otx.alienvault.com/api/v1/indicators/domain/$target_domain/passive_dns"    "https://api.hackertarget.com/hostsearch/?q=$target_domain"    "https://urlscan.io/api/v1/search/?q=$target_domain"    "https://jldc.me/anubis/subdomains/$target_domain"    "https://www.google.com/search?q=site%3A$target_domain&num=100"    "https://www.bing.com/search?q=site%3A$target_domain&count=50")# Fetch subdomains from various sources concurrentlyecho -e "${YELLOW}[+] Getting $target_domain subdomains using [crt.sh+rapiddns+alienvault+hackertarget+urlscan+jldc+google+bing]${NC}"for url in "${urls[@]}"; do    curl -s "$url" | grep -o -E '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.'"$target_domain"'' >> "$subs_dir/passive.txt" &donewaitecho -e "${BLUE}[+] Removing duplicates from passive subdomains${NC}"cat "$subs_dir/passive.txt" | sort -u > "$subs_dir/quick_passive.txt"rm "$subs_dir/passive.txt"echo -e "${BLUE}[+] Saving to quick_passive.txt${NC}"echo "$target_domain" >> "$subs_dir/quick_passive.txt"echo -e "${BLUE}[+] That's it, we are done for $target_domain!${NC}"# Active subdomain enumerationecho -e "${RED}[+] Start active subdomain enumeration!${NC}"# 1. DNS Brute Forcing using purednsecho -e "${GREEN}[+] DNS Brute Forcing using puredns${NC}"puredns bruteforce "$wordlists_dir/dns/dns_9m.txt" "$target_domain" -r "$wordlists_dir/dns/valid_resolvers.txt" -w "$subs_dir/dns_bf.txt"# 2. Permutations using gotatorecho -e "${GREEN}[+] Permutations using gotator${NC}"gotator -sub "$target_domain" -perm "$wordlists_dir/dns/dns_permutations_list.txt" -depth 1 -numbers 10 -mindup -adv -md | sort -u > "$subs_dir/perms.txt"# Resolving permutations using purednsecho -e "${GREEN}[+] Resolving permutations using puredns${NC}"puredns resolve "$subs_dir/perms.txt" -r "$wordlists_dir/dns/valid_resolvers.txt" -w "$subs_dir/resolved_perms.txt"# 3. TLS probing using ceroecho -e "${GREEN}[+] TLS probing using cero${NC}"cero "$target_domain" | sed 's/^*.//' | grep -e "\." | sort -u > "$subs_dir/tls_probing.txt"# 4. Scraping (JS/Source code)echo -e "${GREEN}[+] Scraping (JS/Source code)${NC}"cat "$subs_dir/"* | sort -u > "$subs_dir/filtered_subs.txt"cat "$subs_dir/filtered_subs.txt" | httpx -random-agent -retries 2 -o "$subs_dir/filtered_hosts.txt"# Crawling using gospiderecho -e "${GREEN}[+] Crawling for js files using gospider${NC}"gospider -S "$subs_dir/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "$subs_dir/gospider.txt"# Cleaning the outputecho -e "${GREEN}[+] Cleaning the output${NC}"sed -i '/^.\{2048\}./d' "$subs_dir/gospider.txt"cat "$subs_dir/gospider.txt" | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep -Eo '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.[^.]{2,}' | sort -u > "$subs_dir/scrap_subs.txt"# Resolving target subdomainsecho -e "${GREEN}[+] Resolving target subdomains${NC}"puredns resolve "$subs_dir/scrap_subs.txt" -r "$wordlists_dir/dns/valid_resolvers.txt" -w "$subs_dir/scrap_subs_resolved.txt"# Done with active subdomain enumerationecho -e "${RED}[+] Done with Active subdomain enumeration!${NC}"# Finishing our subdomain enumerationecho -e "${BLUE}[+] Finishing our work and filtering out the subdomains${NC}"cat "$subs_dir/"* | sort -u > "$subs_dir/filtered_subs.txt"cat "$subs_dir/filtered_subs.txt" | httpx -random-agent -retries 2 -o "$subs_dir/filtered_hosts.txt"cat "$subs_dir/filtered_hosts.txt" | sort -u > "$subs_dir/filtered_hosts.txt"echo -e "${RED}[+] That's it, we are done with subdomain enumeration!${NC}"
```