# XXE to RCE

Yes, **Remote Code Execution (RCE)** can be achieved through **XXE** under certain conditions, although it is not a direct outcome of a typical XXE vulnerability. XXE mainly deals with exposing sensitive information or performing Server-Side Request Forgery (SSRF), but there are ways to escalate this vulnerability into **RCE** if the environment is vulnerable. Here's how:

#### Scenarios Leading to RCE via XXE:

**1. Local File Inclusion (LFI) to RCE:**

* If the application allows access to certain files on the server via XXE, such as configuration files, scripts, or logs, an attacker may use **Local File Inclusion (LFI)** to include and execute sensitive files.
* Some services store sensitive information, like credentials or tokens, in files that can lead to remote command execution.

For example:

* **Including web server logs**: An attacker may be able to inject malicious code into log files (e.g., through HTTP headers) and then use XXE to read that log file. If the application executes the content of the log files or a vulnerable script, this can lead to RCE.

**2. SSRF to RCE:**

* **Server-Side Request Forgery (SSRF)** can also lead to RCE. If the XXE vulnerability allows for SSRF, an attacker can abuse this to target internal services running on localhost (such as **admin panels**, **cloud metadata services**, or **API endpoints**).
* If the target service has any exploitable functionality (e.g., vulnerable endpoints or shell access), it could be used to trigger RCE.

For example:

* Using SSRF via XXE to access the AWS EC2 metadata service at `http://169.254.169.254/latest/meta-data/`, which could reveal temporary credentials to the AWS environment. These credentials might allow the attacker to launch EC2 instances or execute commands, leading to RCE.

**3. Java/PHP Deserialization:**

* Some applications use XML parsers that support **deserialization** of XML data into objects (especially in Java or PHP). If the XML parser deserializes untrusted data and the system is vulnerable to **deserialization attacks**, XXE can be used to inject malicious objects into the XML, which could lead to RCE.

For example:

* In a Java-based system, an attacker might be able to use XXE to inject an object that triggers a method in the application, leading to the execution of arbitrary code.

**4. Exploiting Out-of-Band (OOB) Channels:**

* If you can use XXE to trigger **out-of-band (OOB) requests**, such as DNS or HTTP requests to an external server controlled by the attacker, you could leverage this to exploit services that may provide RCE-like behavior.

For example:

* If the server fetches data from an attacker-controlled server, the attacker may deliver malicious payloads or files through the fetched data, potentially resulting in RCE.

**5. Shellshock:**

* If the vulnerable system has a **Bash shell** and is vulnerable to the **Shellshock** bug, XXE can trigger an RCE by crafting a malicious payload that invokes the vulnerable bash environment.

6. **PHP/EXPECT**

{% embed url="https://airman604.medium.com/from-xxe-to-rce-with-php-expect-the-missing-link-a18c265ea4c7" %}

#### Example Flow Leading to RCE:

Let's assume the application is vulnerable to XXE and runs on a system that logs incoming XML data to a file. If you can inject a malicious payload into a log file (e.g., via user input in HTTP headers), and that log file is later processed by a system command or script (without proper sanitization), you might be able to escalate this into RCE.

1.  **Inject into logs**:

    ```xml
    xmlCopy code<?xml version="1.0"?>
    <!DOCTYPE root [
    <!ENTITY xxe SYSTEM "file:///var/log/httpd/access.log">
    ]>
    <root>&xxe;</root>
    ```
2. If you can inject malicious code into the log (e.g., bash commands), and the system reads that log file in an unsafe way, it could lead to RCE.

#### Summary:

* **XXE** can lead to **RCE**, but it typically requires chaining other vulnerabilities or finding a misconfiguration, such as file inclusion, SSRF, deserialization flaws, or vulnerable scripts.
* The possibility depends on the environment and the specifics of how the XML parser and other services interact with the data processed by the vulnerable system.
