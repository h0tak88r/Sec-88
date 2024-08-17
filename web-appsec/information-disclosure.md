---
description: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor'
---

# Dorking

## **Resources**

{% embed url="https://github.com/spekulatius/infosec-dorks/blob/master/README.md" %}

{% embed url="https://www.boxpiper.com/posts/google-dork-list" %}

{% embed url="https://www.uedbox.com/shdb/type/files-containing-juicy-info/" %}

{% embed url="https://www.lopseg.com.br/google-dork" %}

{% embed url="https://dorks.faisalahmed.me/" %}

## **Google Dorking**

* Config Files:

{% code overflow="wrap" %}
```
site:[TARGET] ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:inisite:[TARGET] ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini
```
{% endcode %}

* Database files

{% code overflow="wrap" %}
```
site:[TARGET] ext:sql | ext:db | ext:dbf | ext:mdb | ext:sql.gz | ext:sql.gz | ext:db.gz | ext:db.gz
```
{% endcode %}

* Backup files

```
site:[TARGET] ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
```

* .git folder

```
inurl:"/.git" [TARGET] -site:github.com
```

* Exposed Document

{% code overflow="wrap" %}
```
site:[TARGET] ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv
```
{% endcode %}

* SQL Errors

{% code overflow="wrap" %}
```
site:[TARGET] AND (intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()")
```
{% endcode %}

* PHP errors

```
site:[TARGET] AND ("PHP Parse error" | "PHP Warning" | "PHP Error")
site:[TARGET] "Index of" inurl:phpmyadmin
```

* Login pages

```
site:[TARGET] AND (inurl:signup | inurl:login | inurl:register | intitle:Signup)
```

* Open Redirects

{% code overflow="wrap" %}
```
site:[TARGET] AND (inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:location | inurl:next | inurl:dest | inurl:src=http | inurl:r=http)
```
{% endcode %}

* Apache Struts RCE

```
site:[TARGET] AND (ext:action | ext:struts | ext:do)
```

**Wordpress files**

```
site:[TARGET] AND (inurl:wp-content | inurl:wp-includes)
site:[TARGET] inurl:wp-config.php intext:DB_PASSWORD
site:[TARGET] intitle:"Index of" wp-admin
```

**Other Files**

{% code overflow="wrap" %}
```
site:[TARGET] AND (intitle:index.of | ext:log | ext:php intitle:phpinfo "published by the PHP Group" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:"/phpinfo.php" | inurl:".htaccess" | ext:swf)
--------------------------------------------------------------------------------
site:[TARGET] AND (ext:env | ext:log | ext:sql | ext:yml | ext:pem | ext:ini | ext:logs | ext:ibd | ext:txt | ext:php.txt | ext:old | ext:key | ext:frm | ext:bak | ext:zip | ext:swp | ext:conf | ext:db | ext:config | ext:ovpn | ext:svn | ext:git | ext:cfg | ext:exs | ext:dbf | ext:mdb | ext:pem | ext:pub | ext:yaml | ext:zip | ext:asc | ext:xls | ext:xlsx")
```
{% endcode %}

**Credentials in Trello**

```
inurl:trello.com AND intext:[TARGET]
```

**Zoom**

```
inurl:http://zoom.us/j  [TARGET]
inurl:http://zoom.us/j intext:password [TARGET]
inurl:http://zoom.us/j intext:id# [TARGET]
```

**Ciphermail Login**

```
site:*.target.com intext:"CipherMail Email Encryption Gateway login"
```

**Various Service**s

```
site:sharepoint.com [TARGET]
site:box.com/s [TARGET]
site:dropbox.com/s [TARGET]
site:onedrive.live.com [TARGET]
site:docs.google.com inurl:"/d/" [TARGET]
site:[TARGET] inurl:Dashboard.jspa intext:"Atlassian Jira Project Management Software"
```

**Linkedin employees**

```
site:linkedin.com employees [TARGET]
```

**AWS S3 Buckets**

```
intext:[TARGET] AND (site:"s3-external-1.amazonaws.com" | site:"s3.amazonaws.com")
---------------------------------

intext:[TARGET] AND (site:s3.af-south-1.amazonaws.com | site:s3.ap-east-1.amazonaws.com | site:s3.ap-northeast-1.amazonaws.com | site:s3.ap-northeast-2.amazonaws.com | site:s3.ap-northeast-3.amazonaws.com | site:s3.ap-south-1.amazonaws.com | site:s3.ap-south-2.amazonaws.com | site:s3.ap-southeast-1.amazonaws.com | site:s3.ap-southeast-2.amazonaws.com | site:s3.ap-southeast-3.amazonaws.com | site:s3.ap-southeast-4.amazonaws.com | site:s3.ca-central-1.amazonaws.com | site:s3.eu-central-1.amazonaws.com | site:s3.eu-central-2.amazonaws.com | site:s3.eu-north-1.amazonaws.com | site:s3.eu-south-1.amazonaws.com | site:s3.eu-south-2.amazonaws.com | site:s3.eu-west-1.amazonaws.com | site:s3.eu-west-2.amazonaws.com | site:s3.eu-west-3.amazonaws.com | site:s3.me-central-1.amazonaws.com | site:s3.me-south-1.amazonaws.com | site:s3.sa-east-1.amazonaws.com | site:s3.us-east-1.amazonaws.com | site:s3.us-east-2.amazonaws.com | site:s3.us-gov-east-1.amazonaws.com | site:s3.us-gov-west-1.amazonaws.com | site:s3.us-west-1.amazonaws.com | site:s3.us-west-2.amazonaws.com)
-------------------------------------------------------------------------------------

intext:[TARGET] AND (site:s3.dualstack.af-south-1.amazonaws.com | site:s3.dualstack.ap-east-1.amazonaws.com | site:s3.dualstack.ap-northeast-1.amazonaws.com | site:s3.dualstack.ap-northeast-2.amazonaws.com | site:s3.dualstack.ap-northeast-3.amazonaws.com | site:s3.dualstack.ap-south-1.amazonaws.com | site:s3.dualstack.ap-south-2.amazonaws.com | site:s3.dualstack.ap-southeast-1.amazonaws.com | site:s3.dualstack.ap-southeast-2.amazonaws.com | site:s3.dualstack.ap-southeast-3.amazonaws.com | site:s3.dualstack.ap-southeast-4.amazonaws.com | site:s3.dualstack.ca-central-1.amazonaws.com | site:s3.dualstack.eu-central-1.amazonaws.com | site:s3.dualstack.eu-central-2.amazonaws.com | site:s3.dualstack.eu-north-1.amazonaws.com | site:s3.dualstack.eu-south-1.amazonaws.com | site:s3.dualstack.eu-south-2.amazonaws.com | site:s3.dualstack.eu-west-1.amazonaws.com | site:s3.dualstack.eu-west-2.amazonaws.com | site:s3.dualstack.eu-west-3.amazonaws.com | site:s3.dualstack.me-central-1.amazonaws.com | site:s3.dualstack.me-south-1.amazonaws.com | site:s3.dualstack.sa-east-1.amazonaws.com | site:s3.dualstack.us-east-1.amazonaws.com | site:s3.dualstack.us-east-2.amazonaws.com | site:s3.dualstack.us-gov-east-1.amazonaws.com | site:s3.dualstack.us-gov-west-1.amazonaws.com | site:s3.dualstack.us-west-1.amazonaws.com | site:s3.dualstack.us-west-2.amazonaws.com)
```

**Azure**

* `site:"blob.core.windows.net" AND intext:[TARGET]`

#### Google Cloud

* `site:"storage.googleapis.com" AND intext:[TARGET]`

#### Digitalocean Spaces

* `site:"digitaloceanspaces.com" [TARGET]`

#### Git Providers

* `site:github.com | site:gitlab.com | site:bitbucket.org [TARGET]`

#### Secrets in Microsoft Devops

* `site:"dev.azure.com" AND intext:secret`
* `site:"dev.azure.com" AND intext:password`
* `site:"dev.azure.com" AND intext:apikey`

**Various Services**

* `site:stackoverflow.com AND intext:"[TARGET]"`
* `site:jfrog.io AND intext:"[TARGET]"`
* `[TARGET]`
* `intitle:traefik inurl:8080/dashboard [TARGET]`
* `intitle:"Dashboard [Jenkins]" [TARGET]`
* `(site:bitpaste.app | site:codebeautify.org | site:codepad.co | site:codepad.co |site:ideone.com | site:codepad.org | site:codepen.io | site:codeshare.io | site:coggle.it | site:controlc.com | site:dotnetfiddle.net | site:dpaste.com | site:dpaste.org | site:gitter.im | site:hastebin.com | site:heypasteit.com | site:ide.geeksforgeeks.org | site:ideone.com | site:jsdelivr.com | site:jsdelivr.net | site:jsfiddle.net) AND "[TARGET]"`
* `(site:justpaste.it | site:libraries.io | site:npmjs.com | site:npm.runit.com | site:npm.runkit.com | site:papaly.com | site:paste2.org | site:pastebin.com | site:paste.debian.net | site:pastehtml.com | site:paste.org | site:phpfiddle.org | site:prezi.com | site:productforums.google.com | site:repl.it | site:replt.it | site:scribd.com | site:sharecode.io | site:snipplr.com | site:trello.com | site:ycombinator.com) AND "[TARGET]"`

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

* Single Dorks

```
site:[TARGET] inurl:_cpanel/forgotpwd
site:[TARGET] inurl:/proc/self/cwd
site:[TARGET] inurl:/etc/
site:[TARGET] filename:constants
site:[TARGET] filename:settings
site:[TARGET] filename:database
site:[TARGET] filename:config
site:[TARGET] filename:environment
site:[TARGET] filename:spec
site:[TARGET] filename:zhrc
site:[TARGET] filename:bash
site:[TARGET] filename:npmrc
site:[TARGET] filename:dockercfg
site:[TARGET] filename:pass
site:[TARGET] filename:global
site:[TARGET] filename:credentials
site:[TARGET] filename:connections
site:[TARGET] filename:s3cfg
site:[TARGET] filename:wp-config
site:[TARGET] filename:htpasswd
site:[TARGET] filename:git-credentials
site:[TARGET] filename:id_dsa
site:[TARGET] filename:id_rsa
site:[TARGET] extension:env
site:[TARGET] extension:cfg
site:[TARGET] extension:ini
site:[TARGET] language:yaml -filename:travis
site:[TARGET] extension:properties
site:[TARGET] extension:bat
site:[TARGET] extension:sh
site:[TARGET] extension:zsh
site:[TARGET] extension:pem
site:[TARGET] extension:ppk
site:[TARGET] extension:sql
site:[TARGET] extension:json
site:[TARGET] extension:xml
site:[TARGET] filename:bash_history
site:[TARGET] filename:bash_profile
site:[TARGET] filename:bashrc
site:[TARGET] filename:cshrc
site:[TARGET] filename:history
site:[TARGET] filename:netrc
site:[TARGET] filename:pgpass
site:[TARGET] filename:tugboat
site:[TARGET] filename:dhcpd.conf
site:[TARGET] filename:express.conf
site:[TARGET] filename:filezilla.xml
site:[TARGET] filename:idea14.key
site:[TARGET] filename:makefile
site:[TARGET] filename:gitconfig
site:[TARGET] filename:prod.exs
site:[TARGET] filename:prod.secret.exs
site:[TARGET] filename:proftpdpasswd
site:[TARGET] filename:recentservers.xml
site:[TARGET] filename:robomongo.json
site:[TARGET] filename:server.cfg
site:[TARGET] filename:shadow
site:[TARGET] filename:sshd_config
site:[TARGET] filename:known_hosts
site:[TARGET] filename:wp-config.php
site:[TARGET] filename:.env
site:[TARGET] filename:hub
site:[TARGET] filename:.netrc
site:[TARGET] filename:_netrc
site:[TARGET] filename:ventrilo_srv.ini
site:[TARGET] filename:dbeaver-data-sources.xml
site:[TARGET] filename:sftp-config.json
site:[TARGET] filename:.esmtprc password
site:[TARGET] filename:.remote-sync.json
site:[TARGET] filename:WebServers.xml
site:[TARGET] staging
site:[TARGET] stg
site:[TARGET] prod
site:[TARGET] preprod
site:[TARGET] swagger
site:[TARGET] internal
site:[TARGET] dotfiles
site:[TARGET] dot-files
site:[TARGET] mydotfiles
site:[TARGET] config
site:[TARGET] dbpasswd
site:[TARGET] db_password
site:[TARGET] db_username
site:[TARGET] dbuser
site:[TARGET] testuser
site:[TARGET] dbpassword
site:[TARGET] keyPassword
site:[TARGET] storePassword
site:[TARGET] passwords
site:[TARGET] password
site:[TARGET] secret.password
site:[TARGET] database_password
site:[TARGET] sql_password
site:[TARGET] passwd
site:[TARGET] pass
site:[TARGET] pwd
site:[TARGET] pwds
site:[TARGET] root_password
site:[TARGET] credentials
site:[TARGET] security_credentials
site:[TARGET] connectionstring
site:[TARGET] private -language:java
site:[TARGET] private_key
site:[TARGET] master_key
site:[TARGET] token
site:[TARGET] access_token
site:[TARGET] auth_token
site:[TARGET] oauth_token
site:[TARGET] authorizationToken
site:[TARGET] secret
site:[TARGET] secrets
site:[TARGET] secret_key
site:[TARGET] secret_token
site:[TARGET] api_secret
site:[TARGET] app_secret
site:[TARGET] appsecret
site:[TARGET] client_secret
site:[TARGET] key
site:[TARGET] send_keys
site:[TARGET] send.keys
site:[TARGET] sendkeys
site:[TARGET] apikey
site:[TARGET] api_key
site:[TARGET] app_key
site:[TARGET] application_key
site:[TARGET] appkey
site:[TARGET] appkeysecret
site:[TARGET] access_key
site:[TARGET] apiSecret
site:[TARGET] x-api-key
site:[TARGET] apidocs
site:[TARGET] secret_access_key
site:[TARGET] encryption_key
site:[TARGET] consumer_key
site:[TARGET] auth
site:[TARGET] secure
site:[TARGET] login
site:[TARGET] conn.login
site:[TARGET] sshpass
site:[TARGET] ssh2_auth_password
site:[TARGET] irc_pass
site:[TARGET] fb_secret
site:[TARGET] sf_username
site:[TARGET] node_env
site:[TARGET] aws_key
site:[TARGET] aws_token
site:[TARGET] aws_secret
site:[TARGET] aws_access
site:[TARGET] AWSSecretKey
site:[TARGET] github_key
site:[TARGET] github_token
site:[TARGET] gh_token
site:[TARGET] slack_api
site:[TARGET] slack_token
site:[TARGET] bucket_password
site:[TARGET] redis_password
site:[TARGET] ldap_username
site:[TARGET] ldap_password
site:[TARGET] gmail_username
site:[TARGET] gmail_password
site:[TARGET] codecov_token
site:[TARGET] fabricApiSecret
site:[TARGET] mailgun
site:[TARGET] mailchimp
site:[TARGET] appspot
site:[TARGET] firebase
site:[TARGET] gitlab
site:[TARGET] stripe
site:[TARGET] herokuapp
site:[TARGET] cloudfront
site:[TARGET] amazonaws
site:[TARGET] npmrc _auth
site:[TARGET] pem private
site:[TARGET] aws_access_key_id
site:[TARGET] bashrc password
site:[TARGET] xoxp OR xoxb OR xoxa
site:[TARGET] FTP
site:[TARGET] s3.yml
site:[TARGET] .exs
site:[TARGET] beanstalkd.yml
site:[TARGET] deploy.rake
site:[TARGET] mysql
site:[TARGET] .bash_history
site:[TARGET] .sls
site:[TARGET] composer.jsonfilename:.npmrc _auth
site:[TARGET] filename:.dockercfg auth
site:[TARGET] extension:pem private
site:[TARGET] extension:ppk private
site:[TARGET] filename:id_rsa or filename:id_dsa
site:[TARGET] extension:sql mysql dump
site:[TARGET] extension:sql mysql dump password
site:[TARGET] filename:credentials aws_access_key_id
site:[TARGET] filename:.s3cfg
site:[TARGET] filename:.htpasswd
site:[TARGET] filename:.env DB_USERNAME NOT homestead
site:[TARGET] filename:.env MAIL_HOST=smtp.gmail.com
site:[TARGET] filename:.git-credentials
site:[TARGET] PT_TOKEN language:bash
site:[TARGET] filename:.bashrc password
site:[TARGET] filename:.bashrc mailchimp
site:[TARGET] filename:.bash_profile aws
site:[TARGET] rds.amazonaws.com password
site:[TARGET] extension:json api.forecast.io
site:[TARGET] extension:json mongolab.com
site:[TARGET] extension:yaml mongolab.com
site:[TARGET] jsforce extension:js conn.login
site:[TARGET] SF_USERNAME salesforce
site:[TARGET] filename:.tugboat NOT _tugboat
site:[TARGET] HEROKU_API_KEY language:shell
site:[TARGET] HEROKU_API_KEY language:json
site:[TARGET] filename:.netrc password
site:[TARGET] filename:_netrc password
site:[TARGET] filename:hub oauth_token
site:[TARGET] filename:filezilla.xml Pass
site:[TARGET] filename:recentservers.xml Pass
site:[TARGET] filename:config.json auths
site:[TARGET] filename:config irc_pass
site:[TARGET] filename:connections.xml
site:[TARGET] filename:express.conf path:.openshift
site:[TARGET] filename:.pgpass
site:[TARGET] [WFClient] Password= extension:ica
site:[TARGET] filename:server.cfg rcon password
site:[TARGET] JEKYLL_GITHUB_TOKEN
site:[TARGET] filename:.bash_history
site:[TARGET] filename:.cshrc
site:[TARGET] filename:.history
site:[TARGET] filename:.sh_history
site:[TARGET] filename:prod.exs NOT prod.secret.exs
site:[TARGET] filename:configuration.php JConfig password
site:[TARGET] filename:config.php dbpasswd
site:[TARGET] filename:config.php pass
site:[TARGET] path:sites databases password
site:[TARGET] shodan_api_key language:python
site:[TARGET] shodan_api_key language:shell
site:[TARGET] shodan_api_key language:json
site:[TARGET] shodan_api_key language:ruby
site:[TARGET] filename:shadow path:etc
site:[TARGET] filename:passwd path:etc
site:[TARGET] extension:avastlic "support.avast.com"
site:[TARGET] extension:json googleusercontent client_secret
site:[TARGET] HOMEBREW_GITHUB_API_TOKEN language:shell
site:[TARGET] xoxp OR xoxb
site:[TARGET] .mlab.com password
site:[TARGET] filename:logins.json
site:[TARGET] filename:CCCam.cfg
site:[TARGET] msg nickserv identify filename:config
site:[TARGET] filename:settings.py SECRET_KEY
site:[TARGET] filename:secrets.yml password
site:[TARGET] filename:master.key path:config
site:[TARGET] filename:deployment-config.json
site:[TARGET] filename:.ftpconfig
site:[TARGET] filename:sftp.json path:.vscode
site:[TARGET] filename:jupyter_notebook_config.json
site:[TARGET] "api_hash" "api_id"
site:[TARGET] "https://hooks.slack.com/services/"
site:[TARGET] filename:github-recovery-codes.txt
site:[TARGET] filename:gitlab-recovery-codes.txt
site:[TARGET] filename:discord_backup_codes.txt
site:[TARGET] extension:yaml cloud.redislabs.com
site:[TARGET] extension:json cloud.redislabs.com
site:[TARGET] stage
site:[TARGET] _key
site:[TARGET] _token
site:[TARGET] _secret
site:[TARGET] TODO
site:[TARGET] signup
site:[TARGET] register
site:[TARGET] admin
site:[TARGET] administrator
site:[TARGET] testing
site:[TARGET] extension:exs
site:[TARGET] extension:sls
site:[TARGET] filename:beanstalkd.yml
site:[TARGET] filename:deploy.rake
site:[TARGET] filename:composer.json
site:[TARGET] filename:composer.lock
site:[TARGET] ftp
site:[TARGET] ssh

```

## **GitHub Dorking**&#x20;

{% embed url="https://vsec7.github.io/" %}

{% embed url="https://www.lopseg.com.br/dork-helper" fullWidth="false" %}

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

{% embed url="https://mr-koanti.github.io/shodan" %}

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

### Others

* [ ] Exposed User's PII through IMGs

{% embed url="https://x.com/GodfatherOrwa/status/1803430519582937170" %}
