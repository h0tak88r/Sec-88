# DNS Dangling / NS Takeover

The Domain Name System (DNS) is the internet’s address book, translating domain names into IP addresses. However, vulnerabilities in DNS configurations, particularly Name Server (NS) takeovers, can expose organizations to severe security risks. Unlike other DNS misconfigurations, NS takeovers target the core of a domain’s DNS infrastructure, potentially granting attackers control over all DNS resolutions. This blog post dives into NS takeover vulnerabilities, their differences from subdomain takeovers, and how to test for them responsibly.

### What is an NS Takeover Vulnerability?

An NS takeover occurs when an attacker gains control over a domain’s Name Server records, which dictate where DNS queries for a domain are resolved. NS records are critical because they point to the authoritative servers responsible for the domain’s DNS data. If an attacker compromises these records—often by registering an expired or unclaimed nameserver—they can control the entire domain’s DNS resolution, redirecting traffic, intercepting communications, or disrupting services.

According to [Trickest](https://trickest.com/blog/dns-takeover-explained-protect-your-online-domain/), NS takeovers are particularly dangerous due to their "blast radius," affecting all subdomains and services under the targeted domain. Common causes include:

* **Expired Nameservers**: When a domain’s NS records point to nameservers hosted on expired or unregistered domains.
* **Misconfigured DNS Providers**: Vulnerabilities in DNS providers that allow attackers to claim or manipulate nameservers.
* **Improper Delegation**: Failure to update NS records after changing DNS providers, leaving old records vulnerable.

The impact of an NS takeover is profound:

* **Full Domain Control**: Attackers can redirect all traffic, including subdomains, to malicious servers.
* **Data Interception**: Sensitive communications, such as emails or API requests, can be intercepted.
* **Service Disruption**: Legitimate services can be replaced with fraudulent ones, eroding user trust.

### NS Takeover vs. Subdomain Takeover: Key Differences

While NS takeover is a type of DNS takeover, it differs significantly from subdomain takeover in scope and impact.

#### Subdomain Takeover

Subdomain takeover targets individual subdomains (e.g., `blog.example.com`) due to misconfigured records, often involving CNAMEs pointing to unclaimed resources. For example, a subdomain linked to a decommissioned cloud service can be claimed by an attacker. As noted by [Valimail](https://www.valimail.com/blog/subdomain-takeover/), subdomain takeovers are limited to specific subdomains and don’t affect the entire domain.

#### NS Takeover

NS takeover, in contrast, affects the entire domain by compromising its authoritative nameservers. According to [ProjectDiscovery](https://projectdiscovery.io/blog/guide-to-dns-takeovers), an NS takeover grants attackers control over all DNS records, including those for subdomains, making it far more severe. For instance, if `example.com`’s NS records point to a nameserver on an expired domain, an attacker can register that domain and control all DNS queries for `example.com`.

[SecurityTrails](https://securitytrails.com/blog/blast-radius-dns-takeovers) highlights that NS takeovers are less common than subdomain takeovers but have a higher impact due to their domain-wide control. Unlike subdomain takeovers, which often exploit specific services, NS takeovers target the DNS infrastructure itself.

### How to Test for NS Takeover Vulnerabilities

Testing for NS takeover vulnerabilities requires a focused approach to identify misconfigured or vulnerable NS records. Below are practical steps and tools to detect these issues responsibly. **Important**: Always obtain explicit permission before testing, as unauthorized attempts are illegal and unethical.

#### 1. Identify Vulnerable NS Records

Check if NS records point to expired or unclaimed domains. Use tools like `dig` or `whois` to query NS records and verify the status of the referenced nameservers. For example:

```bash
dig ns example.com
```

This command lists the NS records for `example.com`. If any point to a domain that is expired or available for registration, it’s a potential vulnerability. [Trickest](https://trickest.com/blog/dns-takeover-explained-protect-your-online-domain/) suggests looking for SERVFAIL or REFUSED responses, which may indicate nameserver issues.

#### 2. Verify DNS Provider Security

Some DNS providers are more susceptible to NS takeovers due to weak validation processes. The GitHub repository [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns) lists providers and their vulnerability status. Below is a sample of providers with known NS takeover risks (check the repository for updates):

| Provider      | Status     | Fingerprint          | Takeover Instructions |
| ------------- | ---------- | -------------------- | --------------------- |
| Digital Ocean | Vulnerable | ns1.digitalocean.com | Issue #22             |
| DNSMadeEasy   | Vulnerable | ns0.dnsmadeeasy.com  | Issue #6              |
| DNSimple      | Vulnerable | ns1.dnsimple.com     | Issue #16             |

Before reporting, perform a proof of concept (e.g., adding a TXT record via the claimed nameserver) to confirm the vulnerability, as advised by [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns).

#### 3. Use Automated Tools

Automated tools can streamline NS takeover detection:

* **Nuclei**: Scans for DNS misconfigurations, including NS-related issues, by detecting SERVFAIL or REFUSED responses, as per [Trickest](https://trickest.com/blog/dns-takeover-explained-protect-your-online-domain/).
* **DNSTake**: A Python tool ([GitHub](https://github.com/pwnesia/dnstake)) designed for DNS takeover detection, including NS vulnerabilities, offering scalability for large domain sets.
* [**dnsX**](https://github.com/projectdiscovery/dnsx)**:** dnsx is a fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.

Run these tools against a list of domains to identify potential NS takeover risks efficiently.

#### 4. Manual Verification

Manually verify NS takeovers by attempting to register the expired or unclaimed domain referenced in the NS records. For example, if `ns1.exampledns.com` is listed as an NS record and `exampledns.com` is available, registering it could allow control over the target domain’s DNS. Document findings carefully and avoid disrupting services.

#### 5. Monitor NS Delegation

Ensure NS records are correctly delegated to authorized nameservers. Use `whois` to check the registrar and nameserver status, and cross-reference with the DNS provider’s records. [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover) recommends regular audits to prevent unauthorized NS delegations.

### Best Practices to Prevent NS Takeovers

To protect against NS takeover vulnerabilities, organizations should:

* **Monitor NS Records**: Regularly verify that NS records point to active, authorized nameservers.
* **Secure Domain Registrations**: Ensure nameserver domains are renewed and locked to prevent unauthorized registration.
* **Choose Reputable DNS Providers**: Use providers with strong security practices and DNSSEC support.
* **Audit DNS Changes**: Implement strict processes for updating NS records, especially during provider migrations, as suggested by [MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers).

### Real-World Context

NS takeovers remain a critical threat. An X post by [@tinchoabbate](https://x.com/tinchoabbate/status/1640737272130674690) highlighted a critical bug in the Ethereum Name Service (ENS) that allowed DNSSEC-based NS takeovers, demonstrating their relevance in modern systems. Similarly, [SecurityTrails](https://securitytrails.com/blog/blast-radius-dns-takeovers) notes that while NS takeovers are rare, their impact is devastating, making proactive testing essential.

### Conclusion

NS takeover vulnerabilities are a high-stakes risk, granting attackers control over a domain’s entire DNS infrastructure. By understanding their differences from subdomain takeovers and employing rigorous testing methods—using tools like `dig`, `nuclei`, and [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns)—security professionals can mitigate these threats. Always test responsibly with explicit permission, and adopt best practices to safeguard your DNS environment.

Stay proactive, audit your NS records regularly, and leverage the resources below to protect your digital assets.

### References

* [DNS Takeover Explained: Protect Your Online Domain](https://trickest.com/blog/dns-takeover-explained-protect-your-online-domain/)
* [A Guide to DNS Takeovers: The Misunderstood Cousin of Subdomain Takeovers](https://projectdiscovery.io/blog/guide-to-dns-takeovers)
* [SecurityTrails: Blast Radius DNS Takeovers](https://securitytrails.com/blog/blast-radius-dns-takeovers)
* [GitHub: can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns)
* [DNSTake: Python Implementation for DNS Takeovers](https://github.com/pwnesia/dnstake)
* [Subdomain Takeovers - Security on the Web](https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers)
* [OWASP: Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
* [X Post: Critical Bug on ENS](https://x.com/tinchoabbate/status/1640737272130674690)
