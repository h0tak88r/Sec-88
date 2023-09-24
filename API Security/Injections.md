## Intro

Injection vulnerabilities have plagued web applications for over two decades. They take place when an attacker is able to send commands that are executed by the systems that support the web application. The most common forms of injection attacks are SQL injection, Cross-site scripting (XSS), and operating system command injection. APIs are yet another attack vector for these critical attacks to be communicated from an attacker to the supporting databases and systems.

## [OWASP 2019 Attack Vector Description](https://owasp.org/API-Security/editions/2019/en/0xa8-injection/)

"Attackers will feed the API with malicious data through whatever injection vectors are available (e.g., direct input, parameters, integrated services, etc.), expecting it to be sent to an interpreter."

## [OWASP 2019 Security Weakness Description](https://owasp.org/API-Security/editions/2019/en/0xa8-injection/)

"Injection flaws are very common and are often found in SQL, LDAP, or NoSQL queries, OS commands, XML parsers, and ORM. These flaws are easy to discover when reviewing the source code. Attackers can use scanners and fuzzers."

## [OWASP 2019 Impacts Description](https://owasp.org/API-Security/editions/2019/en/0xa8-injection/)

"Injection can lead to information disclosure and data loss. It may also lead to DoS, or complete host takeover."

## Summary

Injection flaws exist when a request is passed to the API’s supporting infrastructure and the API provider doesn’t filter the input to remove unwanted characters (a process known as input sanitization). As a result, the infrastructure might treat data from the request as code and run it. When this sort of flaw is present, an attacker will be able to conduct injection attacks like SQL injection, NoSQL injection, and system command injection.

In each of these injection attacks, the API delivers an unsanitized payload directly to the operating system running the application or its database. As a result, if an attacker sends a payload containing SQL commands to a vulnerable API that uses a SQL database, the API will pass the commands to the database, which will process and perform the commands. The same will happen with vulnerable NoSQL databases and affected systems.

Verbose error messaging, HTTP response codes, and unexpected API behavior can all be clues to an attacker and will be an indication that they have discovered an injection flaw. Say, for example, an attacker were to send OR 1=0-- as an address in an account registration process. The API may pass that payload directly to the backend SQL database, where the OR 1=0 statement would fail (as 1 does not equal 0), causing some SQL error:
```http
POST /api/v1/register HTTP 1.1

Host: example.com

--snip--

{

“Fname”: “hAPI”,

“Lname”: “Hacker”,

“Address”: “' OR 1=0--”,

}
```

An error in the backend database could show up as a response to the consumer. In this case, the attacker might receive a response like “Error: You have an error in your SQL syntax…”, but any response directly from databases or the supporting system will serve as a clear indicator that there is likely an injection vulnerability.

Injection vulnerabilities are often complemented by other weaknesses like poor input sanitization. Injection flaws can have serious impacts by providing an attacker with the ability to manipulate an API’s supporting system or database.

Finding injection flaws requires diligently testing API endpoints and paying attention to how the API responds, then crafting requests that attempt to manipulate the backend systems. Injection attacks have been around for decades, so there are many standard security controls that can be used to protect API providers from them.

## [OWASP 2019 Preventative Measures](https://owasp.org/API-Security/editions/2019/en/0xa8-injection/)

#### Preventing injection requires keeping data separate from commands and queries.

- Perform data validation using a single, trustworthy, and actively maintained library.
- Validate, filter, and sanitize all client-provided data, or other data coming from integrated systems.
- Special characters should be escaped using the specific syntax for the target interpreter.
- Prefer a safe API that provides a parameterized interface.
- Always limit the number of returned records to prevent mass disclosure in case of injection.
- Validate incoming data using sufficient filters to only allow valid values for each input parameter.
- Define data types and strict patterns for all string parameters.

## Additional Resources

- [OWASP Injection Flaws](https://www.owasp.org/index.php/Injection_Flaws)
- [SQL Injection](https://www.owasp.org/index.php/SQL_Injection)
- [NoSQL Injection Fun with Objects and Arrays](https://www.owasp.org/images/e/ed/GOD16-NOSQL.pdf)
- [Command Injection](https://www.owasp.org/index.php/Command_Injection)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [Web Security Academy: OS Injection](https://portswigger.net/web-security/os-command-injection)
- [Web Security Academy: SQL Injection](https://portswigger.net/web-security/sql-injection)
- [Web Security Academy: XML Injection](https://portswigger.net/web-security/xxe)