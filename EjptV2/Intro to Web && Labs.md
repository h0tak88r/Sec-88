  

### ==_**Intro to Web**_==

  

> ==What is website== ⇒ is Files and codes on a server , ( Html, CSS , JavaScript ) , when u reach out with your browser , u’r going to pull these files using HTTP/HTTPS

  

- Website AND HTTP Contents
    
    - _==Headers==_ ⇒ Headers hold information about what you’re requesting files from a server
    - _==Request==_ ⇒ when u call functions or click on thing on website the browser sent request to server to perform these thing or what u want to do .
    - ==_Response_== ⇒ when the browser sent request to the server to perform your request , server send response to browser to see what the result of this request
    - ==_Browser_== ⇒ it’s software application used to locate, retrieve, and display content on the World Wide Web , including webpages, images, videos, and other files .
    - ==_Sessions_== ⇒ way to store user data between HTTP requests , when u want to login multi times on short time , u want something to let u login easily without entering username and password every time , so the server will provide u with session like ( cookies , session token ..etc).
    - ==_Directors_== ⇒ it’s the endpoint that store the some part of the entire system , when u want to navigate as example login page ,we will call /login ⇒ this page called Directory .
    - _==User-agent==_ ⇒ it’s header sent with request to tell the server what browser and OS we used .
    - ==_Host_== ⇒ header sent with request tell the server what host u are call
    - ==_Status code_== ⇒ header return on response tell us a code , there are many code type every code expresses states of server response .
    - ==_Content Type_== ⇒ header return on response used to indicate the original media type of the resource
    

  

- _==Request Methods==_ ⇒ GET , HEAD , POST , PUT , DELETE , CONNECT , OPTIONS , TRACE , PATCH .
- HTTPS ⇒ ==it’s HTTP protocol with TLS certification , so the difference between HTTP and HTTPS ⇒ instead of used SSL we use TLS so the network traffic if u intercept it it will be Encrypted==
- `dirb <url>` ⇒ to scan for open directories on website

  

### ==_**Labs**_==

  

- ==Web and HTTP Protocol==
    
    - `nmap -sV -sS -O <target ip >` ⇒ to scan open ports on target and identifying what services that running on target to exploit it .
    - if we identify http protocol open ⇒ `enter the ip on browser`
    - first we should check some interesting thing ⇒ `the source code` && `robots.txt end point`
    - `dirb http://<target ip>` ⇒ to brute force some directories
    - `curl -I <target ip + end point u want to explore >` ⇒ that will return with the response headers
    - `curl -X <http method > <target ip > -v` ⇒ to modify the http method when u send a request
    - `curl -X <http method > <target ip > -d "parameter-name=value&parameter2-name=value"` ⇒ to send data with the request
    - explore all application functionality && see all directories
    - If we found a dir provide us with ability to upload file ⇒ `curl <target ip>/dir - -upload-file <file we want to upload>`
    - `open burb suits and :)`
    
      
    

  

- ==Directory Enumeration with Gobuster==
    
    > Gobuster ⇒ it’s like dirb and dirsearch …etc , it’s command line tool used to bruteforce the directories `goLang` ,faster than dirb
    
    - `gobuster dir -u http://<target ip> -w /usr/share/wordlist/dirb/common.txt` ⇒ that will bruteforce the directories using gobuster with dirb wordlist
    - `-b 404,403` ⇒ to Exclude some status codes
    - `-x .php,.txt,.xml` ⇒ to included a file extensions
    - u can do a bruteforce for sub directories ⇒ `just add the directory to the scanned url`
    

  

- ==Directory Enumeration with BurpSuite==
    
    - Send the request to intruder
    - highlight the parameter u want to bruteforce it
    - on scope tab select spider attack
    - now from the payload options select upload from file , and select the dirb file
    - start attack
    

  

- ==Scanning Web Application with ZAProxy==
    
    > ZAProxy ⇒ tool like brupsuite used to scan web application
    
    - On Linux search bar ⇒ `type Owasp zap`
    - `Click on Manual Explore` && `enter the target url`
    - `Open on browser` will give u a browser with all zap tools
    - explore it on youtube
    - `on sitemap , right click && select active scan and start scan`
    - on alert tap we can see what happen here and what vuln founded on application
    
      
    

  

- ==Scanning Web Application with Nikto==
    
    - `nikto -h <target url>` ⇒ that will scan the target URL from common vuln , and will return with some interesting thing u n. eed to check
    - `nikto -h <target url -Tuning <number> -Display v` ⇒ that will scan for exact vuln based on Tuning number ==< check help page >==
    - `nikto -h <target url -Tuning <number> -Display v -o nikto.html -Format html` ⇒ same command but here the output will be on html format
    

  

- ==Passive Crawling with Burp Suite==
    
    - open target url && start burpsuite
    - intercept on && on firefox browser download foxyproxy extension and config it to intercept all request on 127.0.0.1
    - Back to Burpsuite and start intercepting all request that u made on target website
    

  

- ==SQL Injection with SQLMap==
    
    - ==First with burpsuite we should identify a input filed to test for SQL==
    - `sqlmap -u <target url></endpoint with the target parameter > --cookie <cookie value if u need it > -p <target parameter` ⇒ That will start sqlmap on the target system and here with -p we will target parameter
    - `sqlmap -u <target url></endpoint with the target parameter > --cookie <cookie value if u need it > -p <target parameter> --dbs` ⇒ that will try to do a sql injection and return with the databases
    - `sqlmap -u <target url></endpoint with the target parameter > --cookie <cookie value if u need it > -p <target parameter> -D <database name> --tables` ⇒ that will try to do a sql injection and connect with the database and return with the tables on this databases
    - `sqlmap -u <target url></endpoint with the target parameter > --cookie <cookie value if u need it > -p <target parameter> -D <database name> -T <table name> --columns` ⇒ to identify the column on this table
    - `sqlmap -u <target url></endpoint with the target parameter > --cookie <cookie value if u need it > -p <target parameter> -D <database name> -T <table name> -C <column name> --dump` ⇒ that will dump all data on this column
    
      
    

  

- ==XSS Attack with XSSer==
    
    - ==First with burpsuite we should identify a input filed to test for XSS==
    - `xsser --url “<target url>” -p “<target parameter=`==`XSS`==`>` ⇒ to test for xss where ⇒ XSS on parameter is the value will replace with payload
    - `xsser --url “<target url>” -p “<target parameter=``==XSS==`==`> --auto`== ⇒
    

  

- ==Attacking HTTP Login Form with Hydra==
    
    - `hydra -L <username wordlist> -P <password wordlist> <target ip> http-post-form “/<endpoint>:<open the source code and see the form and if the first parameter called Login and the we will put the value as a <username wordlist> we should put all form parameter>:<regexs> to match it` ⇒ so here if we have a form that have a 3 types of parameter login & password & security_level ⇒ Login=^<wordlist-username>^&password=^<wordlist-password>^& security_level=<0,1>&form=submit
    
      
    
      
    

  

- ==Attacking Basic Auth with Burp Suite==
    
    - here we will see that the web page auth using a basic auth header “Authorization: Basic <value in base64> “
    - so when we see that intercept the request and sent it to intruder , make a highlight to this value after u decode it
    - now do a brute force but make sure to make a payload Processing ⇒ (add prefix ⇒ admin:) && (encoding ⇒ base64) to encoded the value to base64 before sent the request
    - start attack
    

  

- ==Attacking HTTP Login Form with ZAProxy==
    
    - enter the url and open the zap browser
    - enter any crad then on zap proxy , we will see the request appear on the lift list enter on it , then click on request tab
    - right click and click fuzz , then highlight the username and click add and paste what u want , do same to password
    - `start fuzzer`