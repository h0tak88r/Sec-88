# WAF Bypassing Techniques

Web Application Firewalls (WAFs) are designed to detect and block malicious requests, but there are several techniques to bypass them depending on how the WAF is configured. Here are a few examples of WAF bypass techniques:

1. **Encoding and Obfuscation**:\
   Attackers can use URL encoding, base64 encoding, or double URL encoding to disguise payloads. For example, encoding a typical SQL injection string like `UNION SELECT` could be obfuscated to `%55%4E%49%4F%4E%20%53%45%4C%45%43%54`.
2. **Case Alteration**:\
   Some WAFs do not perform case-insensitive filtering, so simple case changes in payloads might bypass filters. For instance, using `UnIoN` instead of `UNION`.
3. **Parameter Pollution**:\
   WAFs might struggle with analyzing multiple occurrences of the same parameter. For example, injecting `?id=1&id=2` may confuse the WAF and allow the second parameter to bypass the filter.
4. **Null Byte Injection**:\
   Adding null bytes (`%00`) in the payload can trick the WAF into thinking the string is terminated. However, some back-end systems might ignore the null byte and process the rest of the payload.
5. **JSON and Alternative Content Types**:\
   WAFs typically expect HTTP parameters in the traditional form (key-value pairs). Sending payloads as JSON data or using less common content types (like `text/plain` instead of `application/json`) can sometimes bypass filters.
6. **Overlong UTF-8 Encoding**:\
   In some cases, encoding characters in overlong UTF-8 format (e.g., representing `/' as %C0%AF`) can evade WAF filtering mechanisms.

Each of these methods targets potential weaknesses in how a WAF processes and inspects HTTP traffic. Bypassing WAFs requires analyzing the specific setup, understanding its rules, and trying different techniques to see what gets through.

## How would you completely avoid a WAF?

Completely avoiding a WAF depends on the application’s architecture and the type of WAF in place (network-based, cloud-based, or host-based). Here are some techniques that could help circumvent a WAF entirely:

1. **Target Direct IP or Alternate Endpoints**:\
   Some applications may still have direct access to their web server’s IP address or alternate endpoints not behind the WAF. If DNS resolution or scanning reveals the origin server's IP address, targeting it directly can bypass the WAF altogether. Tools like `host` or `dig` can help uncover this information.
2. **Leverage Unprotected Subdomains**:\
   If the target has multiple subdomains or services, not all may be behind the WAF. Testing various subdomains or endpoints might lead to a server without WAF protection. This can be identified using subdomain enumeration tools like `Sublist3r` or `Amass`.
3. **Use HTTP Smuggling**:\
   HTTP request smuggling manipulates how intermediate systems like proxies or load balancers parse requests. By crafting requests that are parsed differently by the WAF and the origin server, you can potentially bypass the WAF. This technique requires careful inspection of the network setup but can be very effective.
4. **Look for Misconfigured WAF Rules**:\
   Some WAFs might be misconfigured and protect only specific routes or certain types of requests. For example, it might block SQLi on the `/login` endpoint but leave other endpoints unprotected. Analyzing and testing for inconsistencies in rule application can allow you to evade the WAF.
5. **Exploiting Outbound Filters**:\
   In some cases, WAFs might not properly inspect outbound traffic. If the application makes outbound calls (such as fetching URLs or triggering webhooks), it might allow payloads to be passed through to other services or vulnerable areas without WAF inspection.
6. **Brute Force Parameter Tuning**:\
   Some WAFs operate on rate-limiting thresholds or specific triggers (like inspecting only GET or POST requests). Gradually adjusting payload parameters, changing request methods, or splitting payloads across multiple requests might allow you to slip under the WAF’s radar.

Ultimately, WAFs add a layer of security, but they can often be bypassed with patience, understanding of the application’s architecture, and a combination of subtle techniques.
