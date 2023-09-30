# API Reconnaissance
[https://target-name.com/api/v1](https://target-name.com/api/v1) 
[https://api.target-name.com/v1](https://api.target-name.com/v1) 
[https://target-name.com/docs](https://target-name.com/v1)
[https://dev.target-name.com/rest](https://target-name.com/v1)
Look for API indicators within directory names like:  
```go
/api, /api/v1, /v1, /v2, /v3, /rest, /swagger, /swagger.json, /doc, /docs, /graphql, /graphiql, /altair, /playground
```

Also, subdomains can also be indicators of web APIs:
```go
api.target-name.com
uat.target-name.com
dev.target-name.com
developer.target-name.com
test.target-name.com
```

_Also, watch for HTTP Responses that include statements like:  
```go
{"message": "Missing Authorization token"}
```
One of the most obvious indicators of an API would be through information gathered using third-Party Sources like Github and API directories.
Gitub: [https://github.com/](https://github.com/) 
Postman Explore: [https://www.postman.com/explore/apis](https://www.postman.com/explore/apis)
ProgrammableWeb API Directory: [https://www.programmableweb.com/apis/directory](https://www.programmableweb.com/apis/directory) 
APIs Guru: [https://apis.guru/](https://apis.guru/) 
Public APIs Github Project: [https://github.com/public-apis/public-apis](https://github.com/public-apis/public-apis) 
RapidAPI Hub: [https://rapidapi.com/search/](https://rapidapi.com/search/)
## **Passive Reconnaissance**
### **Google Dorking**
|   |   |
|---|---|
|**Google Dorking Query**|**Expected results**|
|inurl:"/wp-json/wp/v2/users"|Finds all publicly available WordPress API user directories.|
|intitle:"index.of" intext:"api.txt"|Finds publicly available API key files.|
|inurl:"/api/v1" intext:"index of /"|Finds potentially interesting API directories.|
|ext:php inurl:"api.php?action="|Finds all sites with a XenAPI SQL injection vulnerability. (This query was posted in 2016; four years later, there are currently 141,000 results.)|
|intitle:"index of" api_key OR "api key" OR apiKey -pool|This is one of my favorite queries. It lists potentially exposed API keys.|

### **GitDorking**
```go
filename:swagger.json
extension: .json
# use Truffelhog
sudo docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=target-name
```
## **Shodan**
|   |   |
|---|---|
|**Shodan Queries**|**Purpose**|
|hostname:"targetname.com"|Using hostname will perform a basic Shodan search for your target’s domain name. This should be combined with the following queries to get results specific to your target.|
|"content-type: application/json"|APIs should have their content-type set to JSON or XML. This query will filter results that respond with JSON.|
|"content-type: application/xml"|This query will filter results that respond with XML.|
|"200 OK"|You can add "200 OK" to your search queries to get results that have had successful requests. However, if an API does not accept the format of Shodan’s request, it will likely issue a 300 or 400 response.|
|"wp-json"|This will search for web applications using the WordPress API.|

### **The Wayback Machine**
The Wayback Machine is an archive of various web pages over time. This is great for passive API reconnaissance because this allows you to check out historical changes to your target. If, for example, the target once advertised a partner API on their landing page, but now hides it behind an authenticated portal, then you might be able to spot that change using the Wayback Machine. Another use case would be to see changes to existing API documentation. If the API has not been managed well over time, then there is a chance that you could find retired endpoints that still exist even though the API provider believes them to be retired. These are known as Zombie APIs. Zombie APIs fall under the Improper Assets Management vulnerability on the OWASP API Security Top 10 list. Finding and comparing historical snapshots of API documentation can simplify testing for Improper Assets Management.

##  Active API Reconnaissance
**Nmap**
```bash 
nmap -sC -sV [target address or network range] -oA nameofoutput
nmap -p- [target address] -oA allportscan
nmap -sV --script=http-enum <target> -p 80,443,8000,8080
```
**OWASP Amass**
```bash
amass enum -list
#Next, we will need to create a config file to add our API keys to.
sudo curl https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini >~/.config/amass/config.ini
amass enum -active -d target-name.com |grep api
```
### **Directory Brute-force with Gobuster**
```bash
gobuster dir -u://targetaddress/ -w /usr/share/wordlists/api_list/common_apis_160 -x 200,202,301 -b 302
```
### **Kiterunner**
Kiterunner is an excellent tool that was developed and released by Assetnote. Kiterunner is currently the best tool available for discovering API endpoints and resources.
`kr scan HTTP://127.0.0.1 -w ~/api/wordlists/data/kiterunner/routes-large.kite`
`kr brute <target> -w ~/api/wordlists/data/automated/nameofwordlist.txt`