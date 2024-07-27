# Hacking Web Sockets

### WebSocket Protocol Over View

**Origin-Based Security Model**

* **Browser Clients**: Operate based on the origin-based security model to mitigate security risks.
* **No Built-in Authentication**: WebSocket protocol does not provide authentication mechanisms natively. Developers must implement their own authentication solutions.

**Client-to-Server Masking**

* **Masking Requirement**: Clients must mask data sent to the server. This involves using a 32-bit masking key included in the frame.
  * **Masking Mechanism**: `MASKED = MASK ^ DATA (XOR operation)`
  * **Security Purpose**: Protects against cache poisoning and HTTP request smuggling attacks.

### WebSocket Protocol Support

* **Major Web Browsers**: Supported by all leading browsers, ensuring wide compatibility.
* **Web Servers and Proxies**: Widely supported by web servers and proxies including:
  * **Servers**: Apache HTTPD, Nginx, IIS
  * **Proxies**: HAProxy, Traefik, Varnish, Envoy
* **Cloud Providers**: Offer WebSocket API gateways and proxying via load balancers.

### WebSocket handshake

* Request

<figure><img src="../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

* Response

<figure><img src="../.gitbook/assets/image (1) (2).png" alt=""><figcaption></figcaption></figure>

### WebSocket data transfer - masking

* Masking key is 32-bit long passed inside frame&#x20;
* Client must send masked data &#x20;
* `MASKED = MASK ^ DATA (^ - XOR)`&#x20;
* Mechanism protects against **cache poisoning** and **smuggling** attacks

### Discovering WebSocket APIs

* **Monitor Upgrade Requests**: Analyze network traffic to identify WebSocket upgrade requests.
* **Analyze JavaScript Files**: Examine code for WebSocket usage and endpoints.
* **Establish Connections**: Attempt WebSocket connections to various URLs to discover active endpoints.

### Cross-Site WebSocket Hijacking (CSWSH)

* **Same-Origin Policy (SOP)**: Does not apply to WebSockets in browsers.
  * **Read/Write Across Origins**: Possible to read from and write to WebSockets across different origins.
* **Origin Header Check**: Should be enforced during the handshake step to prevent hijacking. However, this is often poorly implemented.
* **Cookies**: Typically used to authenticate upgrade requests, but lack of proper Origin header checks can lead to vulnerabilities.

{% embed url="https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking" %}

### CORS

* **Origin Header Manipulations**: Various bypass techniques exist, including:
  * **Origin: null**
  * **Pre-domain and Post-domain Wildcards**
  * **Other Bypasses**: Developers must be vigilant against sophisticated manipulation techniques.

{% embed url="https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties" %}

### Authentication & IDOR issues

* WebSocket protocol doesn’t offer authentication&#x20;
* Developers have to roll out their own AuthN&#x20;
* It’s secure to check AuthN only during handshake&#x20;
* Common secure implementations&#x20;
  * Session cookies&#x20;
  * Tokens

***

* [ ] &#x20;Some ID / GUID is required in Upgrade request
  * [ ] Guess ID&#x20;
  * [ ] Leak GUID (minor IDOR, …)
* [ ] No authentication during handshake step&#x20;
* [ ] Some ID / GUID required in API messages&#x20;
  * [ ] Guess ID&#x20;
  * [ ] Leak GUID (minor IDOR, …)
* [ ] Exposing **GraphQL** **subscriptions** w/o **AuthN ->** Path `/subscriptions`

**Lack of Authentication**: WebSocket endpoints for GraphQL subscriptions (/subscriptions) often lack proper authentication, leading to potential exposure.

{% embed url="https://github.com/righettod/poc-graphql#subscriptions-websocket-endpoint-default-enabling" %}

### Smuggling through WebSocket

Smuggling through WebSocket connection

<figure><img src="../.gitbook/assets/image (2) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (3) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

#### Summary

WebSocket protocol offers robust support across browsers, servers, proxies, and cloud providers, but also presents several security challenges. Proper masking, Origin header checks, and authentication mechanisms are crucial to secure WebSocket implementations. Developers must be aware of potential vulnerabilities such as CSWSH, CORS bypasses, IDOR issues, and smuggling attacks to safeguard their applications.
