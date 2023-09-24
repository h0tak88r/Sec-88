  

- It’s a first step of a penetration testing process , on it we collect information as much as we can of our target .

- Passive information gathering
    
    - IP addresses & Dns information
    - domain name & domain ownership information
    - email addresses & social media profiles
    - web technologies used
    - subdomains
    
- Active information gathering
    
    - open ports on target
    - internal infrastructure of target network/organization
    - enumerating information
    
      
    
      
    
      
    

  

### website recon & footprinting (Passive)

- we can use host command to see the ip addresses of the website ⇒ ==$ host google.com==
- now we want to collect some name email .. etc ⇒ so we can explore the website and see what it have , name , emails , YouTube channels , twitter … etc

  

- so first step see the ==robots.txt== file , it’s a dir every website have it , on it we tell the browser or search engin to allow or disallow some sensitive directory , so on it we can disallow the browser to index the admin panal as a example .

  

- the seconde file u should review is the ==sitemap.xml== or ==sitemaps.xml ,== so on it we provide the browser with a organized way to organize the index’s .

  

- Technologies footprinting
    
    - builtwith adds on ⇒ it’s tell u what running in website what the CMS ..etc
    - weblayzer adds on ⇒ it’s like the builtwith
    - whatweb command ⇒ it’s like the other but on the command line
    - Httrack ⇒ it’s a tool to download all the website files image files and the source code on your local pc , just open it (GUI) and provided the url to download all website .
    
      
    

  

- whois ⇒ it’s a website and command use to enum ips names emails …etc and alot of information , the owner & more .

  

- footprinting using netcraft ⇒ third party tool used alot of info like ssl cert and alot more ⇒ once u open it ⇒ select services ⇒ internet data mining ⇒ in bottom u find box , like what that site running.

  

- Dns Recon
    
    - dnsrecon ⇒ it’s a command line tool to scan your target domain ⇒ dnscan -d <domain> so it back with alot info about dns , the mail server (MX), A recored , AAA ,AAAA ..etc
    - ==**[dnsdumpster](https://dnsdumpster.com/)**== ⇒ one of the best , it’s a GUI tool , used to enum the dns , it’s back with the mail server , name server , AAA … etc
    

  

- Waf detection using waf00f ⇒ it’s on of the best to detect the wep application firwall and the proxy that the target using ⇒ **==waf00f <domain> -a==**

  

- enum Subdomains using ==**sublist3er**== ⇒ so here it’s not subdomain bruteforceing so it’s not active recon ⇒ **==sublist3r -d <domain>==**

  

- Google dorking ([==_GHDB_==](https://www.exploit-db.com/google-hacking-database))
    
    - **==dorking for google ⇒==** [https://dorks.faisalahmed.me/](https://dorks.faisalahmed.me/)
    - ==**dorking of all ⇒**== [https://mr-koanti.github.io/github.html](https://mr-koanti.github.io/github.html)
    - **==Shodan-Dork ⇒==** [https://mr-koanti.github.io/shodan](https://mr-koanti.github.io/shodan)
    - to limit to target ⇒ site:<domain>
    - to search for specific word in url like admin-panal ⇒ site:<domin> inurl:admin
    - to dork about subdomain ⇒ site:*.<domin>
    - to dork about title in entire page ⇒ site:*.<domin> intitle:admin
    - to dork about file ⇒ site:*.<domin> filetype:pdf
    - to dork about word like employees ⇒ site:*.<domin> employees
    - to dork about ==directory listing== ⇒ site:*<domin> intitle:index of
    - to dork what the website look on the in previous times ⇒ cache:<domin> OR use ==[webcache](https://cachedview.com/)==
    - ==**_waybackmachine_**== ⇒ my best site .
    - to dork about if the website save the password on dir listing ⇒ ==inurl:auth_user_file.txt , password.txt , .txt …etc==
    - Best resources of this dork is (google hacking database) ⇒ _**==[exploit.db](https://www.exploit-db.com/google-hacking-database)==**_
    

  

- Search for emails
    
    - theHarvester ⇒ it’s a command line tool , it’s powerfull tool ,the tool gathering ( username , ip , email ,subdomains,urls) ⇒ ==_**theHarvester -d <domain> -b <search engin if u want >**_==
    
      
    
      
    

  

- Leaked Password Databases
    
    - ==[have i been pwned](https://haveibeenpwned.com/)== ⇒ it’s popular tool , u just give it a email or phone
    
      
    

  

  

# Active information gathering

  

- _**==Dns Zone Transfers==**_ ⇒
    
- ==Dns interrogation== : is the process of enumerating dns records for a specific domain .

> ==_Zone transfer_== ⇒ is the procces like the admin want to copy or transfer zone files from one dns server to another .

> a DNS Zone Transfer can provide us with a holistic view of an organization’s network layout . internal network address may be found on an organization’s DNS Servers

- For tool u can use here
    
    - **_==dnsrecon -d <website.com>==_** ⇒ this tool will give u more info about the dns recored that the website have .
    - **_==dnsenum <websit.com>==_** ⇒ this tool like the other but here it automatice print a zone transfer and a auto bruteforce , u will see a lot of info like a recorde subdomain …etc
    - **_==dig axfr @<domain-server-name>==_** <website.com> ⇒ that will return with a info about a zone transfer of the provided domain-server-name
    
    > If the Domain-server protcted by cloudflire as a example u will see the ns in tolls return with cloudeflire not the actual name-server . and if that happen u will see that the scan for zonetransfer will be not allowed .
    
      
    
      
    

  

  

- Host discovery with Nmap (network mapper)

> First we need to figer out what the devices are running in this host

1. **_==nmap -sn <ip>==_** ⇒ that will list all ip of the devices that running on the target network

  

- Port scanning with Nmap

> if u scan the ip like this 10.4.19.218 , u will see that nmap return with error because this is a windows ip so the windows blocking the ping probes so , try -Pn

1. **_==nmap <ip> || nmap -Pn <ip if windows >==_** ⇒ that will scan for all ports open on the target network

> now as always u can see that nmap show alot of filtered port that because maybe the target have a firwall that filter the traffic

> the default scan of nmap is Tcp , use -sU if we want to scan UDP:

1. **_==nmap -sU < ip target>==_** ⇒ To Scan UDP

> u can use -v to print the output found at the same time it found it .

> now if we want to know more info about the the open ports we will use -sV

1. **_==nmap -sV <ip target>==_** ⇒ that will scan for the open ports ad what the services Version that running on this port

> -O to scan what the operating system the services have

> -sC to provide the scan by a lot of scripts that will return more info about target

1. **_==nmap -A <ip target>==_** ⇒ _this is a agrasive mode so it compine the -sV -O -sC and do the scan in one time_

> -T<0-5> to speed the scan up || slow down the scan ⇒ select this by the target infrastructure .

> To save the output in file ⇒ _-oN test.txt_ ( print it like the terminal format ) && -oX test.xml ( on xml format useful in Metasploit)