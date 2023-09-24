- **==\#Github-Dorking==**
    
    ```
    # Methodology “site.com” :here you add your program you wanna search ((you can put “site.com”)) ((“sub.site.com”)) ((“site” only))but site name like these ((site-site.com))and have these ((-)) the dork without ((“ “ ))# Keywords # password — passwd — pwd — secret — private — LdapJenkinsOTPoauthauthoriztionpasswordpwdftpdotfilesJDBCkey-keyssend_key-keyssend,key-keystokenuserlogin-singinpasskey-passkeyspasssecretSecretAccessKeyapp_AWS_SECRET_ACCESS_KEY AWS_SECRET_ACCESS_KEYcredentialsconfigsecurity_credentialsconnectionstringssh2_auth_passwordDB_PASSWORD# good Dorks https://github.com/techgaun/github-dorks/blob/master/github-dorks.txt# NOT: **capital**like www.bugcrowd.com is repeated ?? -> use “bugcrowd.com” NOT www.bugcrowd ((but in NOT dont add .com))example: “paypal” language:python password NOT sandbox.paypal NOT api.paypal NOT www.paypal NOT gmail.com NOT yahoo.com NOT hotmail.com NOT test# user ? # see if he work for this company orwa atyat bugcrowd linkedinuser:orwagodfather linkedin user:orwagodfather full nameuser:orwagodfather https://user:orwagodfather Ldap# if you wanna know about some internal links in org you can do like theseorg:bugcrowd https://org:bugcrowd host:
    ```
    
- **==\#Google-Dorking==**
    
    ```
    #!/bin/bash# Google dorks helper\#https://dorks.faisalahmed.me/# Check that a domain has been providedif [ -z "$1" ]; then  echo "Usage: $0 <domain>"  exit 1fi# Check that ggldorks.txt existsif [ ! -f "ggldorks.txt" ]; then  echo "Error: ggldorks.txt not found"  exit 1fi# Loop through each line in ggldorks.txtwhile read dork; do  # Search for the dork on Google  results=$(curl -s "https://www.google.com/search?q=site%3A$1+${dork// /+}")  # Check if there were any results  if [[ $results =~ "did not match any documents" ]]; then    echo "No results for \"$dork\""  else    # Save the URL and dork to results.txt    echo "$dork: $1" >> results.txt  fidone < ggldorks.txt
    ```
    
- ==**\#Shodan-Dorking**==
    
    ```
    ssl:"<ssl_for_target>"ssl.cert.subject.CN:"<specific_hos_name_>"# go to <more> option and see the filters like http.titlessl.cert.subject.CN:"<specific_hos_name_>" http.title:"<title>"   # exclude -http.title:"Invalid URL"ssl.cert.subject.CN:"<specific_hos_name_>" -http.title:"Invalid URL" 401
    ```
    
    - [ ] Big IP shodan Search:—> `http.title:"BIG-IP&reg;-Redirect" org:Org`
    - [ ] CVE 2020-3452 → `http.html_hash:-628873716 “set-cookie: webvpn;”`
    - [ ] CVE CVE-2019-11510 → `http.html:/dana-na/`
    - [ ] CVE-2020–5902→ `inurl:/tmui/login.jsp`
    - [ ] **Databases**
    - [ ] **Exposed ports**
    

- [ ] **`GET /admin`** **→ blocked |** **`TRACE /admin`** **→ 200**
- [ ] **chick for** **`phpinfo.php`**
- [ ] **check for** **`/.git`**
- [ ] **check for** **`back-up-files`**
- [ ] **`cat iplist| httpx -silent -path /xmlrpc.php -title -match-string "XML-RPC”`** **→** **[hackerone.com/reports/1890719](http://hackerone.com/reports/1890719)**
- [ ] **`/sitemap.xml?offset=1;SELECT IF((8303>8302),SLEEP(9),2356)#`**
- [ ] **Have you ever heard about `wc-db` file disclosure?! ->** `**https://target[.]com/.svn/wc.db**`
- [ ] **Easy p1 —>** [https://otx.alienvault.com/indicator/domain/<target.com>](https://otx.alienvault.com/indicator/domain/%3ctarget.com%3e)
- [ ] **change** **`POST`** **request for sensitive data to** **`GET`** **request may be u get** **`missing authorization policy`** **bug .**
- [ ] `[https://target](https://target/)``[.]com/wp-content/debug.log`

```
f you happen to find Symfony Web Framework that has Symfony profiler debug mode enabled, fuzz the following endpoints:- /app_dev.php- /app_dev.php/_profiler/phpinfo- /app_dev.php/_profiler- Look for "profiler token" in phpinfo()
```

- [ ] $500 for authentication bypass and reading internal files.  
    Tip: fuzz for special and unicode characters.  
    `/admin/files` --> `302 /authFailure`  
    `/adminFUZZ/files` --> `200`  
    `/admin/FUZZ/files` --> `200`
- [ ] Found a Google Map API Key? Follow these steps with me!  
    Google Map API Key starts with "AIzxxxxxxxxxxxxxx"  
    Download this tool for making a clear PoC:
- [ ] Apache Karaf Web Console Default Credentials! → `karaf:karaf`
- [ ] I found client id & client secret for Microsoft tenant in js file in website → **POC**