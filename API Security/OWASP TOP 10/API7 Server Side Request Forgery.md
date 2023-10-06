## Intro

API7:2023 Server Side Request Forgery is a vulnerability that takes place when a user is able to control the remote resources retrieved by an application.  An attacker can use an API to supply their own input, in the form of a URL, to control the remote resources that are retrieved by the targeted server. 

An attacker could supply URLs that expose private data, scan the target's internal network, or compromise the target through remote code execution. SSRF is also number 10 on the 2021 OWASP Top 10 list and is a growing threat to APIs.

## [OWASP Attack Vector Description](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

_Exploitation requires the attacker to find an API endpoint that accesses a URI that’s provided by the client. In general, basic SSRF (when the response is returned to the attacker), is easier to exploit than Blind SSRF in which the attacker has no feedback on whether or not the attack was successful._

## [OWASP Security Weakness Description](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

_Modern concepts in application development encourage developers to access URIs provided by the client. Lack of or improper validation of such URIs are common issues. Regular API requests and response analysis will be required to detect the issue. When the response is not returned (Blind SSRF) detecting the vulnerability requires more effort and creativity._

## [OWASP Impacts Description](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

_Successful exploitation might lead to internal services enumeration (e.g. port scanning), information disclosure, bypassing firewalls, or other security mechanisms. In some cases, it can lead to DoS or the server being used as a proxy to hide malicious activities._

## Summary

Server Side Request Forgery (SSRF) is a vulnerability that takes place when an application retrieves remote resources without validating user input. When an attacker has control over the resources a server requests then they can gain access to sensitive data, or worse, completely compromise a vulnerable host.  

The impact of this vulnerability is that an attacker would be able to leverage the target server to perform and process requests that they supply. Note that bug bounties payouts for SSRF are driven based on the impact that can be demonstrated with a proof of concept. The higher the demonstrated impact, the higher the bounty.

There are two general types of SSRF that are worth noting: In-Band SSRF and Out-of-Band (Blind) SSRF. In-Band SSRF means that the server responds with the resources specified by the end user. If the attacker specifies the payload as [http://google.com](http://google.com/) to a server with an In-Band SSRF vulnerability the server would make the request and respond to the attacker with information served from google.com. Blind SSRF takes place when the attacker supplies a URL and the server makes the request but does not send information from the specified URL back to the attacker. In the case of Blind SSRF, an attacker would need control over a web server that will capture the request from the target to prove that they were able to force the server to make the request.

**Intercepted Request:**

```http
POST api/v1/store/products_

headers…

{

_"inventory":"http://store.com/api/v3/inventory/item/12345"_

}
```
**Attack:**

```http
POST api/v1/store/products
headers…

{

"inventory":"_**_§_****_http://localhost/secrets_****_§"_**

}
```

**Response:**
```http
HTTP/1.1 200 OK  
headers...  
{

**"secret_token":"SecretAdminToken123"**

}
```


# Out-of-Band SSRF Example

Out-of-Band (or Blind) SSRF takes place when a vulnerable server performs a request from user input but does not send a response back to the attacker indicating a successful attack. In other words, the victim server makes the request to the URL specified by the attacker, but the attacker does not receive a direct message back from the victim server. In this case, to know if the request was made an attacker will need to have some control over the web server that is specified in the attack.

**Intercepted Request:**
```http
POST api/v1/store/products

headers…

{

"inventory":"http://store.com/api/v3/inventory/item/12345"

}
```


**Attack**:
```http
POST api/v1/store/products

headers…

{

"inventory:"http://localhost/secrets"

} 
```


**Response:**
```http
HTTP/1.1 200 OK  
headers...  
{}
```

In this case, the response is returned and we do not have any indication that the server is vulnerable. Instead of [http://localhost/secrets](http://localhost/secrets), an attacker can leverage the URL to a web server that will let them see if a request is actually made. Burp Suite Pro has a great tool called Burp Suite Collaborator. Collaborator can be leveraged to set up a web server that will provide us with the details of any requests that are made to our random URL. 

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/UHz28Z8BT8i3ZOFGS1xg_ssrf2.PNG)

By navigating to webhook.site a random URL will be created. The randomized URL can be used as a payload and track to see if any requests are made to the site from the vulnerable API. An out-of-band SSRF attack would look more like this.

**Attack**:
```http
POST api/v1/store/products

headers…

{

"inventory":"[https://webhook.site/306b30f8-2c9e-4e5d-934d-48426d03f5c0](https://webhook.site/306b30f8-2c9e-4e5d-934d-48426d03f5c0)§"`

}
```


Once the request is sent the third party site can be checked for any new requests.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/ZJM875zQSICtbtxnT6W1_ssrf3.PNG)

This demonstration of SSRF was done using a third-party site that captures the IP address of the server that sent the request. This process will demonstrate that an API is in fact vulnerable to out-of-band SSRF.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

- _Isolate the resource fetching mechanism in your network: usually, these features are aimed to retrieve remote resources and not internal ones._
- _Whenever possible, use allow lists of_
    - _Remote origins users are expected to download resources from (e.g. Google Drive, Gravatar, etc.)_
    - _URL schemes and ports_
    - _Accepted media types for a given functionality_
- _Disable HTTP redirections._
- _Use a well-tested and maintained URL parser to avoid issues caused by URL parsing inconsistencies._
- _Validate and sanitize all client-supplied input data._
- _Do not send raw responses to clients._

## Additional Resources

- [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [URL confusion vulnerabilities in the wild: Exploring parser inconsistencies, Snyk](https://snyk.io/blog/url-confusion-vulnerabilities/)
- [Web Security Academy: SSRF](https://portswigger.net/web-security/ssrf)