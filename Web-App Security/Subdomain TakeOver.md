- [ ] **Using** [`**Subjack**`](https://github.com/haccer/subjack) [](https://github.com/haccer/subjack)**[** `**subjack -w <Subdomain List> -o results.txt -ssl -c fingerprints.json**` **]**
- [ ] **The next step is to see where this domain is pointing to so we can try to take it over.****`dig <Domain Here>`**
- [ ] [https://0xpatrik.com/takeover-proofs/](https://0xpatrik.com/takeover-proofs/) | [https://github.com/EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
#  1. Method by [@Virdoex_hunter](https://twitter.com/Virdoex_hunter)
Easy Subdomain Takeover Method
```
Step:

1:Grab all subdomains of target. i.e, subfinder -d flaws.cloud | tee -a domains.txt
			
2:Run this one liner
			
3:cat domains.txt | while read domain;do dig  $domain;done | tee -a digs.txt
			
4::Grab all the CNAME Entries i.e, cat digs.txt | grep CNAME
			
5:Find a domain that is pointed to third party domain like sub.exampple.com CNAME x.aws.com
			
6:Check wheather the main subdomain is down
			
7:Go to host provider where the domain is pointed to and register that domain if you registered congrats you have takeover the subdomain.
			
```

# 2. Method by [@WhoIs1nVok3r](https://twitter.com/WhoIs1nVok3r)
```
Step-1:- First of all collect all subdomain of the target using assetfinder,subfinder,chaos(needs API key).

Step-2:- Next sort out duplicate URLs using -- cat unresolved | sort -u | tee -a resolved

Step-3:- Pass it to subzy,subjack or other subdomain-takeover tool -- using subzy tool  --  subzy -targets resolved , or use subjack

Step-4:- We can also use nuclei templates but we need to first use httpx -- cat resolved | httpx | tee -a hosts

Step-5:- Next use nuclei-templates -- cat hosts | nuclei -t nuclei-templates/vulnerabilites -o nuclei.txt -v 

Tools Used:-

https://github.com/projectdiscovery/nuclei
https://github.com/projectdiscovery/subfinder
https://github.com/projectdiscovery/httpx
https://github.com/projectdiscovery/nuclei-templates
https://github.com/projectdiscovery/chaos-client
https://github.com/haccer/subjack
https://github.com/LukaSikic/subzy
```


- ==**Subdomain Takeover Write_ups**==
    
    - [How I bought my way to subdomain takeover on tokopedia](https://medium.com/bugbountywriteup/how-i-bought-my-way-to-subdomain-takeover-on-tokopedia-8c6697c85b4d)
    - [Subdomain Takeover via pantheon](https://smaranchand.com.np/2019/12/subdomain-takeover-via-pantheon/)
    - [Subdomain takeover : a unique way](https://www.mohamedharon.com/2019/11/subdomain-takeover-via.html)
    - [Subdomain takeover awarded 200](https://medium.com/@friendly_/subdomain-takeover-awarded-200-8296f4abe1b0)
    - [Subdomain takeover via Hubspot](https://www.mohamedharon.com/2019/02/subdomain-takeover-via-hubspot.html)
    - [Souq.com subdomain takeover](https://www.mohamedharon.com/2019/02/souqcom-subdomain-takeover-via.html)
    - [Subdomain takeover : new level](https://medium.com/bugbountywriteup/subdomain-takeover-new-level-43f88b55e0b2)
    - [Subdomain takeover due to misconfigured project settings for custom domain](https://medium.com/@prial261/subdomain-takeover-dew-to-missconfigured-project-settings-for-custom-domain-46e90e702969)
    - [Subdomain takeover via unsecured s3 bucket](https://blog.securitybreached.org/2018/09/24/subdomain-takeover-via-unsecured-s3-bucket/)
    - [Subdomain takeover worth 200](https://medium.com/@alirazzaq/subdomain-takeover-worth-200-ed73f0a58ffe)
    - [How to do 55000 subdomain takeover in a blink of an eye](https://medium.com/@thebuckhacker/how-to-do-55-000-subdomain-takeover-in-a-blink-of-an-eye-a94954c3fc75)
    - [Subdomain takeover Starbucks (Part 2)](https://0xpatrik.com/subdomain-takeover-starbucks-ii/)
    - [Subdomain takeover Starbucks](https://0xpatrik.com/subdomain-takeover-starbucks/)
    - [Uber wildcard subdomain takeover](https://blog.securitybreached.org/2017/11/20/uber-wildcard-subdomain-takeover)
    - [Bugcrowd domain subdomain takeover vulnerability](https://blog.securitybreached.org/2017/10/10/bugcrowds-domain-subdomain-takeover-vulnerability)
    - [Subdomain takeover vulnerability (Lamborghini Hacked)](https://blog.securitybreached.org/2017/10/10/subdomain-takeover-lamborghini-hacked/)
    - [Authentication bypass on uber's SSO via subdomain takeover](https://www.arneswinnen.net/2017/06/authentication-bypass-on-ubers-sso-via-subdomain-takeover/)
    - [Authentication bypass on SSO ubnt.com via Subdomain takeover of ping.ubnt.com](https://www.arneswinnen.net/2016/11/authentication-bypass-on-sso-ubnt-com-via-subdomain-takeover-of-ping-ubnt-com/)
    
- ==**Top Subdomain Takeover reports from HackerOne:**==
    
    1. [Subdomain Takeover to Authentication bypass](https://hackerone.com/reports/335330) to Roblox - 718 upvotes, $2500
    2. [Subdomain takeover of datacafe-cert.starbucks.com](https://hackerone.com/reports/665398) to Starbucks - 302 upvotes, $2000
    3. [Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com](https://hackerone.com/reports/219205) to Uber - 165 upvotes, $5000
    4. [Subdomain takeover of storybook.lystit.com](https://hackerone.com/reports/779442) to Lyst - 155 upvotes, $1000
    5. [Hacker.One Subdomain Takeover](https://hackerone.com/reports/159156) to HackerOne - 152 upvotes, $1000
    6. [Subdomain takeover at info.hacker.one](https://hackerone.com/reports/202767) to HackerOne - 130 upvotes, $1000
    7. [Multiple Subdomain Takeovers: fly.staging.shipt.com, fly.us-west-2.staging.shipt.com, fly.us-east-1.staging.shipt.com](https://hackerone.com/reports/576857) to Shipt - 126 upvotes, $900
    8. [Subdomain takeover of mydailydev.starbucks.com](https://hackerone.com/reports/570651) to Starbucks - 120 upvotes, $2000
    9. [Subdomain takeover of d02-1-ag.productioncontroller.starbucks.com](https://hackerone.com/reports/661751) to Starbucks - 119 upvotes, $2000
    10. [Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com](https://hackerone.com/reports/352869) to Grab - 116 upvotes, $1000
    11. [Subdomain takeover on](https://hackerone.com/reports/154425) [http://fastly.sc-cdn.net/](http://fastly.sc-cdn.net/) to Snapchat - 108 upvotes, $3000
    12. [Subdomain takeover on svcgatewayus.starbucks.com](https://hackerone.com/reports/325336) to Starbucks - 105 upvotes, $2000
    13. [Subdomain takeover on happymondays.starbucks.com due to non-used AWS S3 DNS record](https://hackerone.com/reports/186766) to Starbucks - 103 upvotes, $2000
    14. [Subdomain takeover on usclsapipma.cv.ford.com](https://hackerone.com/reports/484420) to Ford - 97 upvotes, $0
    15. [Subdomain takeover of resources.hackerone.com](https://hackerone.com/reports/863551) to HackerOne - 94 upvotes, $500
    16. [Subdomain takeover of fr1.vpn.zomans.com](https://hackerone.com/reports/1182864) to Zomato - 89 upvotes, $350
    17. [Subdomain takeover on wfmnarptpc.starbucks.com](https://hackerone.com/reports/388622) to Starbucks - 86 upvotes, $2000
    18. [Subdomain takeover of v.zego.com](https://hackerone.com/reports/1180697) to Zego - 83 upvotes, $0
    19. [Subdomain Takeover at creatorforum.roblox.com](https://hackerone.com/reports/264494) to Roblox - 81 upvotes, $1000