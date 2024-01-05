# API Recon

## Summary of API Security - Reconnaissance

### API Reconnaissance

#### Directory and Subdomain Analysis

* Look for API indicators in directory names like `/api`, `/api/v1`, `/v1`, `/v2`, `/v3`, `/rest`, `/swagger`, `/swagger.json`, `/doc`, `/docs`, `/graphql`, `/graphiql`, `/altair`, `/playground`.
* Subdomains like `api.target-name.com`, `uat.target-name.com`, `dev.target-name.com`, `developer.target-name.com`, `test.target-name.com` can indicate web APIs.
* Monitor HTTP Responses for statements like `{"message": "Missing Authorization token"}`.

#### Third-Party Sources

* Leverage third-party sources like GitHub, Postman Explore, ProgrammableWeb API Directory, APIs Guru, Public APIs GitHub Project, and RapidAPI Hub for information on APIs.

### Passive Reconnaissance

#### Google Dorking

* Utilize Google Dorking with queries such as inurl:"/wp-json/wp/v2/users" and intitle:"index.of" intext:"api.txt" to find publicly available API directories and key files.

#### GitDorking

* Search for files like `swagger.json` using GitDorking, and employ tools like Trufflehog for additional security checks.

#### Shodan

* Use Shodan queries like `hostname:"targetname.com"` and `"content-type: application/json"` to identify APIs based on domain and content type.

#### The Wayback Machine

* Employ The Wayback Machine to explore historical changes in API documentation, uncovering potential Zombie APIs and aiding in testing for Improper Assets Management.

### Active Reconnaissance

#### Nmap

* Use Nmap for active API reconnaissance with commands like `nmap -sC -sV [target address or network range] -oA nameofoutput`.

#### OWASP Amass

* Employ OWASP Amass for active enumeration of APIs, creating a configuration file for API keys, and using commands like `amass enum -active -d target-name.com | grep api`.

#### Directory Brute-force with Gobuster

* Use Gobuster for directory brute-force with a command like `gobuster dir -u://targetaddress/ -w /usr/share/wordlists/api_list/common_apis_160 -x 200,202,301 -b 302`.

#### Kiterunner

* Utilize Kiterunner for discovering API endpoints and resources with commands like `kr scan HTTP://127.0.0.1 -w ~/api/wordlists/data/kiterunner/routes-large.kite` and `kr brute <target> -w ~/api/wordlists/data/automated/nameofwordlist.txt`.
