# Dependency Confusion

### **Overview**

Dependency confusion, also known as a supply chain substitution attack, occurs when a software installer script is tricked into pulling a malicious code file from a public repository instead of the intended file from an internal repository.

### **Attack Techniques**

1. **Reconnaissance:**
   * **Identifying Private Packages:**
     * Scan for exposed `package.json` or similar configuration files using tools like Shodan.
     * Extract private package names from internal files, public repositories, or forums.
     * Use source maps to reconstruct front-end source code and identify import statements.
2. **Exploitation:**
   *   **Creating Malicious Packages:**

       * Develop packages with the same names as the identified private dependencies but with **higher versions**.
       * So if the package indexing is not properly done, it will automatically pull the **Higher** version package from the **Public** Registry.

       <figure><img src="../.gitbook/assets/image (5).png" alt="" width="360"><figcaption></figcaption></figure>

       * Upload these packages to public repositories such as npm, PyPI, or RubyGems.
   * **Executing Malicious Code:**
     * Utilize preinstall scripts to execute malicious code upon package installation.
   * **Using Confused tool**

{% embed url="https://github.com/visma-prodsec/confused" fullWidth="false" %}

* It can be also found using **`npm package.json disclosure`** nuclei template.

```yaml
id: package-json

info:
  name: npm package.json disclosure
  author: geeknik,afaq
  severity: info
  description: All npm packages contain a file, usually in the project root, called package.json - this file holds various metadata relevant to the project.
  tags: config,exposure

requests:
  - method: GET
    path:
      - "/package.json"
      - "/package-lock.json"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "name"
          - "version"
        condition: and

      - type: word
        words:
          - "application/json"
        part: header

      - type: status
        status:
          - 200

```

### **Data Exfiltration:**

* **DNS Exfiltration:**
  * Encode collected data (hostname, username, current path) in DNS queries.
  * Send these queries to a custom authoritative name server to log the information.

**Real-world Impact**

* **Case Study**

{% embed url="https://dhiyaneshgeek.github.io/web/security/2021/09/04/dependency-confusion/?source=post_page-----e0ed2a127013--------------------------------" %}

* **Remote Code Execution (RCE):**
  * Malicious packages executed on internal servers and developers' machines.
  * Exfiltrated data provided insights into vulnerable systems and potential attack vectors.
* **High-Profile Targets:**
  * Exploitation affected major companies, leading to significant security concerns and financial bounties.

### **Common Vulnerabilities**

1. **Insecure Command Usage:**
   * Use of `--extra-index-url` with pip allows fallback to public repositories if a package isn't found internally.
   * Similar issues with other package managers like npm and RubyGems.
2. **Package Management Configurations:**
   * JFrog Artifactory and Azure Artifacts using algorithms that default to higher version numbers from public repositories.
   * Misconfigured internal or cloud-based build servers and development pipelines.

**Mitigation Strategies**

1. **Secure Package Management:**
   * **Index Configuration:**
     * Use `--index-url` instead of `--extra-index-url` to ensure dependencies are pulled exclusively from trusted sources.
   * **Repository Settings:**
     * Prioritize internal packages over public ones in configuration settings.
     * Regularly audit and verify package sources.
2. **Security Policies:**
   * **Access Control:**
     * Implement strict access controls for internal repositories.
   * **Developer Education:**
     * Train developers on the risks of dependency confusion and best practices for secure dependency management.
   * **Regular Audits:**
     * Conduct periodic security assessments and vulnerability scans to identify and mitigate risks.
3. **Detection and Response:**
   * **Monitoring:**
     * Set up monitoring for unusual package installation activities.
     * Use automated alerts for newly published packages with internal names.
   * **Incident Response:**
     * Have a response plan in place for quickly addressing and mitigating discovered vulnerabilities.
   * **Collaboration:**
     * Work with security researchers and bug bounty programs to identify and fix issues proactively.

**Conclusion**

Dependency confusion vulnerabilities pose a significant threat to software supply chains. By adopting secure package management practices, implementing stringent security policies, and maintaining robust detection and response mechanisms, organizations can effectively mitigate the risks associated with these attacks.

### References

{% embed url="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610" %}

{% embed url="https://systemweakness.com/rce-via-dependency-confusion-e0ed2a127013" %}

{% embed url="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610" %}

{% embed url="https://dhiyaneshgeek.github.io/web/security/2021/09/04/dependency-confusion/?source=post_page-----e0ed2a127013--------------------------------" %}

{% embed url="https://hackerone.com/reports/925585" %}

{% embed url="https://github.com/visma-prodsec/confused" %}

{% embed url="https://incolumitas.com/2016/06/08/typosquatting-package-managers/" %}
