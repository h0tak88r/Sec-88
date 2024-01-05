---
description: >-
  CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
  Dorking.....Fuzzing
---

# Information Disclosure

## **Google Dorking**

[Bug Bounty Helper (faisalahmed.me)](https://dorks.faisalahmed.me/) |\*\* [Google Dorks List and Updated Database in 2023 - Box Piper](https://www.boxpiper.com/posts/google-dork-list) https://www.uedbox.com/shdb/type/files-containing-juicy-info/

**Vulnerable web servers**

```python
inurl:/proc/self/cwd
inurl:/proc/self/environ # environment variables on a website
```

**SQL**

```pytohn
"index of" "database.sql.zip" | filetype:sql intext:password
ext:sql | ext:dbf | ext:mdb
intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
site:target.com intitle:”index of” db_backup.sql | db.sql | database.sql | sql | .sql.gz | .sql.bz2
```

**WordPress**

```python
intitle:"Index of" wp-admin
```

**cgi-bin**

```python
inurl:/cgi-bin/
inurl:/cgi-bin/ + intext:”User ID” + intext:”Password”
inurl:/cgi-bin/login.cgi
```

**Juicy files/Pages**

```python
intext:"budget approved") inurl:confidential
#### Apache2 
intitle:"Apache2 Ubuntu Default Page: It works"
#### Zoom Videos
inurl:zoom.us/j AND intext:"scheduled for"
#### SSH private keys
intitle:index.of id_rsa -id_rsa.pub
intitle:"Index of /" ".ssh"
#### email list
filetype:xls inurl:"email.xls"
#### ENV files
inurl:.env | filetype:.env | ext:env
filetype:env intext:DB_USERNAME
intitle:"index of"
inurl:"/private"
intitle:"index of" "local.json"
Fwd: intitle:"Index of /" intext:"resource/"
filetype:xls + password + inurl:.com
site:gov.* intitle:"index of" *.pptx
docs.google.com/spreadsheets
"microsoft internet information services" ext:log
inurl:src/viewcvs.cgi/log/.c?=
intitle:"welcome.to.squeezebox"
intitle:"index of" "mysql.properties"
inurl: /wp-content/uploads/ inurl:"robots.txt" "Disallow:" filetype:txt
inurl:"/horde/test.php"
filetype:gitattributes intext:CHANGELOG.md -site:github.com
ext:txt | ext:log | ext:cfg | ext:yml "administrator:500:"
intitle: index of "*db.tar.gz"
inurl:admin filetype:xlsx site:gov.*
Index of" intext:"source_code.zip
inurl:"htaccess|passwd|shadow|htusers"
“config.yml” | intitle:”index of” “config.yml”
intitle:"index of" "config.txt"
inurl:/wp-content/uploads/wpo_wcpdf
intext:"ArcGIS REST Services Directory" intitle:"Folder: /"
allintitle:"macOS Server" site:.edu
inurl:wp-content/uploads/sites
intitle:"index of" "private.properties"
intitle:"SCM Manager" intext:1.60
intitle:"index of" "profiler"
intitle:"index of" "main.yml"
intitle:"Index of" inurl:/backup/ "admin.zip"
intitle:"index of" google-maps-api
intitle:"index of" github-api
inurl:uploadimage.php
intitle: "index of" "/backup.sql"
intitle:"Sharing API Info"
inurl:user intitle:"Drupal" intext:"Log in" -"powered by"
inurl: /libraries/joomla/database/
"web.config" | inurl:/conf/ | "error_log"
intitle:"Index of /" + ".htaccess"
intitle:"index of /.git" "paren directory"
inurl:Makefile.toml
#### Govermment documentss
allintitle: restricted filetype:doc site:gov
#### pdf files
intitle: index of pdf | ext:pdf | inurl:.pdf
filetype:pdf “Confidential” | “Secret” | “Classified”

```

**Endpoints**

```python
ext:php | ext:asp | ext:aspx | ext:jsp | ext:asp | ext:pl | ext:cfm | ext:py | ext:rb
ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:yaml | ext:yml | ext:rdp | ext:ora | ext:bak | ext:log | ext:config
(ext:doc | ext:pdf | ext:xls | ext:txt | ext:ps | ext:rtf | ext:odt | ext:sxw | ext:psw | ext:ppt | ext:pps | ext:xml) intext:confidential salary 
```

**Panels/Dashboards**

```python
inurl:/admin/login.php
inurl:_cpanel/forgotpwd
#### Jira/Kabana
inurl:Dashboard.jspa intext:"Atlassian Jira Project Management Software"
inurl:app/kibana intext:Loading Kibana
intext:("Sign in" | "Sign in to" | "Log in" | "Log in to")
intitle:login
"inurl:admin.asp"  
"inurl:login/admin.asp"  
"inurl:admin/login.asp"  
"inurl:adminlogin.asp"  
"inurl:adminhome.asp"  
"inurl:admin_login.asp"  
"inurl:administratorlogin.asp"  
"inurl:login/administrator.asp"  
"inurl:administrator_login.asp  
"inurl:admin.php"  
"inurl:login/admin.php"  
"inurl:admin/login.php"  
"inurl:adminlogin.php"  
"inurl:adminhome.php"  
"inurl:admin_login.php"  
"inurl:administratorlogin.php"  
"inurl:login/administrator.php"  
"inurl:administrator_login.php  
admin1.php  
admin1.html  
admin2.php  
admin2.html  
yonetim.php  
yonetim.html  
yonetici.php  
yonetici.html  
adm/  
admin/  
admin/account.php  
admin/account.html  
admin/index.php  
admin/index.html  
admin/login.php  
admin/login.html  
admin/home.php  
admin/controlpanel.html  
admin/controlpanel.php  
admin.php  
admin.html  
admin/cp.php  
admin/cp.html  
cp.php  
cp.html  
administrator/  
administrator/index.html  
administrator/index.php  
administrator/login.html  
administrator/login.php  
administrator/account.html  
administrator/account.php  
administrator.php  
administrator.html  
login.php  
login.html  
modelsearch/login.php  
moderator.php  
moderator.html  
moderator/login.php  
moderator/login.html  
moderator/admin.php  
moderator/admin.html  
moderator/  
account.php  
account.html  
controlpanel/  
controlpanel.php  
controlpanel.html  
admincontrol.php  
admincontrol.html  
adminpanel.php  
adminpanel.html  
admin1.asp  
admin2.asp  
yonetim.asp  
yonetici.asp  
admin/account.asp  
admin/index.asp  
admin/login.asp  
admin/home.asp  
admin/controlpanel.asp  
admin.asp  
admin/cp.asp  
cp.asp  
administrator/index.asp  
administrator/login.asp  
administrator/account.asp  
administrator.asp  
login.asp  
modelsearch/login.asp  
moderator.asp  
moderator/login.asp  
moderator/admin.asp  
account.asp  
controlpanel.asp  
admincontrol.asp  
adminpanel.asp  
fileadmin/  
fileadmin.php  
fileadmin.asp  
fileadmin.html  
administration/  
administration.php  
administration.html  
sysadmin.php  
sysadmin.html  
phpmyadmin/  
myadmin/  
sysadmin.asp  
sysadmin/  
ur-admin.asp  
ur-admin.php  
ur-admin.html  
ur-admin/  
Server.php  
Server.html  
Server.asp  
Server/  
wp-admin/  
administr8.php  
administr8.html  
administr8/  
administr8.asp  
webadmin/  
webadmin.php  
webadmin.asp  
webadmin.html  
administratie/  
admins/  
admins.php  
admins.asp  
admins.html  
administrivia/  
Database_Administration/  
WebAdmin/  
useradmin/  
sysadmins/  
admin1/  
system-administration/  
administrators/  
pgadmin/  
directadmin/  
staradmin/  
ServerAdministrator/  
SysAdmin/  
administer/  
LiveUser_Admin/  
sys-admin/  
typo3/  
panel/  
cpanel/  
cPanel/  
cpanel_file/  
platz_login/  
rcLogin/  
blogindex/  
formslogin/  
autologin/  
support_login/  
meta_login/  
manuallogin/  
simpleLogin/  
loginflat/  
utility_login/  
showlogin/  
memlogin/  
members/  
login-redirect/  
sub-login/  
wp-login/  
login1/  
dir-login/  
login_db/  
xlogin/  
smblogin/  
customer_login/  
UserLogin/  
login-us/  
acct_login/  
admin_area/  
bigadmin/  
project-admins/  
phppgadmin/  
pureadmin/  
sql-admin/  
radmind/  
openvpnadmin/  
wizmysqladmin/  
vadmind/  
ezsqliteadmin/  
hpwebjetadmin/  
newsadmin/  
adminpro/  
Lotus_Domino_Admin/  
bbadmin/  
vmailadmin/  
Indy_admin/  
ccp14admin/  
irc-macadmin/  
banneradmin/  
sshadmin/  
phpldapadmin/  
macadmin/  
administratoraccounts/  
admin4_account/  
admin4_colon/  
radmind-1/  
Super-Admin/  
AdminTools/  
cmsadmin/  
SysAdmin2/  
globes_admin/  
cadmins/  
phpSQLiteAdmin/  
navSiteAdmin/  
server_admin_small/  
logo_sysadmin/  
server/  
database_administration/  
power_user/  
system_administration/  
ss_vms_admin_sm/
```

**PHPINFO | PHPMYADMIN**

```python
intitle:”phpinfo()” | inurl:/phpmyadmin/ | inurl:server-status
intext:”Powered by” AND intext:”PHP Version”
ext:php intitle:phpinfo "published by the PHP Group"
"Index of" inurl:phpmyadmin | inurl:phpmyadmin | intitle:phpmyadmin
```

#### **Dorks For Bug Bounty Programs**

```python
inurl /bug bounty
inurl : / security
inurl:security.txt
inurl:security "reward"
inurl : /responsible disclosure
inurl : /responsible-disclosure/ reward
inurl : / responsible-disclosure/ swag
inurl : / responsible-disclosure/ bounty
inurl:'/responsible disclosure' hoodie
responsible disclosure swag r=h:com
responsible disclosure hall of fame
responsible disclosure europe
responsible disclosure white hat
white hat program
insite:"responsible disclosure" -inurl:nl
intext responsible disclosure
site eu responsible disclosure
site .nl responsible disclosure
site responsible disclosure
responsible disclosure:sites
responsible disclosure r=h:nl
responsible disclosure r=h:uk
responsible disclosure r=h:eu
responsible disclosure bounty r=h:nl
responsible disclosure bounty r=h:uk
responsible disclosure bounty r=h:eu
responsible disclosure swag r=h:nl
responsible disclosure swag r=h:uk
responsible disclosure swag r=h:eu
responsible disclosure reward r=h:nl
responsible disclosure reward r=h:uk
responsible disclosure reward r=h:eu
"powered by bugcrowd" -site:bugcrowd.com
"submit vulnerability report"
site:*.gov.* "responsible disclosure"
intext:"we take security very seriously"
site:responsibledisclosure.com
inurl:'vulnerability-disclosure-policy' reward
intext:Vulnerability Disclosure site:nl
intext:Vulnerability Disclosure site:eu
site:*.*.nl intext:security report reward
site:*.*.nl intext:responsible disclosure reward
"security vulnerability" "report"
inurl"security report"
"responsible disclosure" university
inurl:/responsible-disclosure/ university
buy bitcoins "bug bounty"
inurl:/security ext:txt "contact"
"powered by synack"
intext:responsible disclosure bounty
inurl: private bugbountyprogram
inurl:/.well-known/security ext:txt
inurl:/.well-known/security ext:txt intext:hackerone
inurl:/.well-known/security ext:txt -hackerone -bugcrowd -synack -openbugbounty
inurl:reporting-security-issues
inurl:security-policy.txt ext:txt
site:*.*.* inurl:bug inurl:bounty
site:help.*.* inurl:bounty
site:support.*.* intext:security report reward
intext:security report monetary inurl:security 
intext:security report reward inurl:report
site:security.*.* inurl: bounty
site:*.*.de inurl:bug inurl:bounty
site:*.*.uk intext:security report reward
site:*.*.cn intext:security report reward
"vulnerability reporting policy"
"van de melding met een minimum van een" -site:responsibledisclosure.nl
inurl:/security ext:txt "contact"
inurl:responsible-disclosure-policy
"If you believe you've found a security vulnerability"
intext:"BugBounty" and intext:"BTC" and intext:"reward"
intext:bounty inurl:/security
inurl:"bug bounty" and intext:"€" and inurl:/security
inurl:"bug bounty" and intext:"$" and inurl:/security
inurl:"bug bounty" and intext:"INR" and inurl:/security
inurl:/security.txt "mailto*" -github.com  -wikipedia.org -portswigger.net -magento
/trust/report-a-vulnerability
site:*.edu intext:security report vulnerability
"cms" bug bounty
"If you find a security issue"  "reward"
"responsible disclosure" intext:"you may be eligible for monetary compensation"
inurl: "responsible disclosure", "bug bounty", "bugbounty"
responsible disclosure inurl:in
site:*.br responsible disclosure
site:*.at responsible disclosure
site:*.be responsible disclosure
site:*.au responsible disclosure
```

## **GitHub Dorking** [**gitdork-Helper**](https://vsec7.github.io/)

```python
# Keywords
pass
pwd 
secret
key
private
credentials
dbpassword
token
-------------------------------------
org:
“paypal” language:python password NOT sandbox.paypal NOT api.paypal NOT www.paypal NOT gmail.com NOT yahoo.com NOT hotmail.com NOT test 
--------------------------------------------------
user:
bugcrowd linkedin user:orwagodfather linkedin user:orwagodfather full name user:orwagodfather https:// user:orwagodfather Ldap
---------------------------------------------------------------
# internal links
 org:bugcrowd https:// 
 org:bugcrowd host:
# Some Dorks
org:lemonade-hq  ( token: OR pass: OR secret: OR api_key: OR acess_token: )
```

## **Shodan Dorking**

```python
# Basic 
ssl:"<ssl_for_target>"
ssl.cert.subject.CN:"<specific_hos_name_>"
ssl.cert.subject.CN:"<specific_hos_name_>" -http.title:"<title>" 
tesla.com.cn
# Exposed Ports
"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"
port:"11211" product:"Memcached"
port:"25" product:"exim"
port:"23"
openssh port:22
"220" "230 Login successful." port:21
proftpd port:21
# Databases
MongoDB Server Information" port:27017 -authentication
Set-Cookie: mongo-express=" "200 OK"
mysql port:"3306"
port:"9200" all:"elastic indices"
port:5432 PostgreSQL
Port:5985,6984 
Port:9042,9160
port:8291 os:"MikroTik RouterOS 6.45.9"
port:5006,5007 product:mitsubishi
org:"xx" 200 http.favicon.hash:1428702434 # IDRAC servers try this credentials Username: root Password: calvin
```
