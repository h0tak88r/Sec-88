# #**What is CRLF injection?**

_CRLF injection_ is a vulnerability that lets a malicious hacker inject carriage return (CR) and linefeed (LF) characters to change the way a web application works or to confuse its administrator. There are two main malicious uses for CRLF injections: _log poisoning_ (also called _log injection, log splitting,_ or _log forging)_ and _HTTP response splitting_.

# #**What is log poisoning?**

In a log poisoning attack based on CRLF injection, a malicious hacker injects CRLF characters into web server log files to confuse both automatic log analysis systems and system administrators browsing the logs manually.

# CRLF_Injection

- [ ] `http://www.example.com/example.php?id=` – starting a valid request to a page with a CRLF injection vulnerability.
- [ ] `%0d%0aContent-Length:%200` – a fake HTTP response header of `Content-Length: 0`. This causes the web browser to treat this response as terminated and start parsing the next response.
- [ ] `%0d%0a%0d%0aHTTP/1.1%20200%20OK` – the injected new response begins here with a double CRLF sequence followed by `HTTP/1.1 200 OK`.
- [ ] `%0d%0aContent-Type:%20text/html` – another fake HTTP response header: `Content-Type: text/html`. This is required for the browser to treat this data as HTML content.
- [ ] `%0d%0aContent-Length:%2025` – yet another fake HTTP response header: `Content-Length: 25`. This instructs the browser to parse only the next 25 bytes and discard any remaining data as junk, causing it to ignore the legitimate HTTP content sent by the web server.
- [ ] `%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E` – a double CRLF sequence signals that the headers are over and the response body starts. The injected page content is `<script>alert(1)</script>`, which causes the user’s browser to display an alert instead of the actual _example.php_ page.