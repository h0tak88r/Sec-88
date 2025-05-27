# Amazon Cognito Misconfiguraitons

Amazon Cognito is a powerful service for managing user authentication and authorization in web and mobile applications. However, misconfigurations in Cognito can open the door to serious security risks, such as account takeovers, privilege escalations, and unauthorized access to AWS resources. In this blog post, we’ll explore common Cognito misconfigurations, provide a detailed table of test cases to identify vulnerabilities, and share practical tips to secure your Cognito setup. Whether you’re a developer, security professional, or DevOps engineer, this guide will help you strengthen your AWS environment.

### Why Amazon Cognito Security Matters

Amazon Cognito simplifies user management with its user pools (for sign-up and sign-in) and identity pools (for AWS resource access). However, its flexibility can lead to misconfigurations that attackers exploit. Recent research, including case studies like the Flickr account takeover, highlights how seemingly minor oversights—such as allowing unverified email updates or exposing sensitive IDs—can lead to catastrophic breaches. By proactively testing for these issues, you can protect your application and users from such risks.

### **Common UserPools attacks** <a href="#id-8c4c" id="id-8c4c"></a>

* [ ] &#x20;**Detect Cognito UserPools usage**: Extract UserPoolID or ClientId from the JS/HTML or Signup/Login
* [ ] **Unverified Email/Phone Attributes:** if an email address is configured as an alias and a new user is created with a duplicate email, the alias can be transferred to the newer user, un-verifying the former user's email\
  [https://repost.aws/knowledge-center/cognito-email-verified-attribute](https://repost.aws/knowledge-center/cognito-email-verified-attribute)
* [ ] **Insecure Callback URLs**: Insecure callback URL configurations are a common misconfiguration in OAuth 2.0 and OIDC flows used by Cognito. This includes using HTTP instead of HTTPS (except for `http://localhost` for testing), configuring overly broad wildcard URLs (e.g., `*` or `*.example.com`), or failing to strictly validate the redirect URI in authentication requests\
  [https://community.auth0.com/t/security-risks-of-using-localhost-for-callback-url/118781/1](https://community.auth0.com/t/security-risks-of-using-localhost-for-callback-url/118781/1)\
  [https://repost.aws/questions/QURn-XLoSyQoGDbfqr6H\_BAw/adding-localhost-to-hosted-ui-callback-urls-for-testing-security-risks](https://repost.aws/questions/QURn-XLoSyQoGDbfqr6H_BAw/adding-localhost-to-hosted-ui-callback-urls-for-testing-security-risks)
*   [ ] **Zero Click Account Takeover via Updating Email Before Verification:** Updating email attributes to already registere email addresses and before verification try to login with the new email address Leads to ATO \
    **Reference**: [Flickr Account Takeover Advisory](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/#assembling-the-puzzle-account-takeover) \
    `aws cognito-idp admin-update-user-attributes --user-pool-id <your-user-pool-id> --username <username> --user-attributes Name="email",Value="Victim@gmail.com"` \


    <figure><img src="../.gitbook/assets/image (323).png" alt=""><figcaption></figcaption></figure>
* [ ] **Privilege Escalation via Updating User Attributes:** Use AWS CLI to update custom attributes and check if it results in elevated privileges\
  `aws cognito-idp admin-update-user-attributes --user-pool-id <your-user-pool-id> --username <username> --user-attributes Name="custom:role",Value="admin"`\
  **Reference**: [Amazon Cognito Misconfiguration](https://shellmates.medium.com/amazon-cognito-misconfiguration-35dfde9e2037)\
  **Reference**: [Exploit Two of the Most Common Vulnerabilities in Amazon Cognito with CloudGoat](https://trustoncloud.com/blog/exploit-two-of-the-most-common-vulnerabilities-in-amazon-cognito-with-cloudgoat/)
*   [ ] **Authentication Bypass through Self Signup API**: Verify if the Signup API is enabled and attempt a direct sign-up using AWS\
    \- Self Registration\
    `aws cognito-idp sign-up --client-id <your-client-id> --username <test-user> --password <test-password>` \
    \- Confirm the email address\
    `aws cognito-idp confirm-sign-up — client-id — username — confirmation-code — region`\
    **Reference**: [Amazon Cognito Misconfiguration](https://shellmates.medium.com/amazon-cognito-misconfiguration-35dfde9e2037)\
    **Refrences:** [https://infosecwriteups.com/attacking-aws-common-cognito-misconfigurations-a898bf092218](https://infosecwriteups.com/attacking-aws-common-cognito-misconfigurations-a898bf092218)\


    <figure><img src="../.gitbook/assets/image (321).png" alt=""><figcaption><p>When creating a new user pool, self-registration may be enabled by default, allowing users to sign up for an account on their own.</p></figcaption></figure>

### Common IdentityPools attacks <a href="#id-8841" id="id-8841"></a>

*   [ ] **Leakage of Secrets like Identity Pool ID in JS Files:** Inspect client-side code or API responses for exposed Identity Pool IDs, then attempt to generate temporary AWS credentials then use tool to enumerate permissions associated with these credentials like [_**Enumerate-iam**_](https://github.com/andresriancho/enumerate-iam). \
    \`\`\
    `aws cognito-identity get-credentials-for-identity --identity-id <identity-pool-id>`\
    **Reference**: [AWS Cognito Pitfalls: Default Settings Attackers Love](https://www.secforce.com/blog/aws-cognito-pitfalls-default-settings-attackers-love-and-you-should-know-about/)\
    **Reference**: [Exploit Two of the Most Common Vulnerabilities in Amazon Cognito with CloudGoat](https://trustoncloud.com/blog/exploit-two-of-the-most-common-vulnerabilities-in-amazon-cognito-with-cloudgoat/)\
    **Reference**: [AWS Cognito Pitfalls: Default Settings Attackers Love](https://www.secforce.com/blog/aws-cognito-pitfalls-default-settings-attackers-love-and-you-should-know-about/)\
    **Reference**: [Hacking AWS Cognito Misconfigurations](https://notsosecure.com/hacking-aws-cognito-misconfigurations)

    <figure><img src="../.gitbook/assets/image (322).png" alt=""><figcaption><p>js file leak the AWS credentials ( User Pool ID, User Pool ID, Region)</p></figcaption></figure>

### How to Use These Test Cases

To execute these test cases, you’ll need tools like the AWS CLI, Burp Suite for intercepting requests, or enumeration tools like `enumerate-iam` and `ScoutSuite`. Here’s a quick guide to get started:

1. **Set Up AWS CLI**: Configure AWS CLI with temporary credentials or a test account to interact with Cognito APIs safely.
2. **Inspect Client-Side Code**: Use browser developer tools or Burp Suite to check for exposed IDs like App Client ID or Identity Pool ID in JavaScript files or API responses.
3. **Test Attribute Updates**: Use AWS CLI commands like `admin-update-user-attributes` to attempt modifying email or custom attributes, checking for verification bypasses or privilege escalations.
4. **Verify Permissions**: Review your Cognito user pool settings in the AWS Management Console, ensuring that self-signup is disabled (if not needed) and attribute permissions are restricted.

For example, to test for the "Zero Click Account Takeover" vulnerability (inspired by the Flickr case), you can try updating a user’s email attribute with a case-sensitive variation (e.g., `Victim@gmail.com` vs. `victim@gmail.com`) using the following AWS CLI command:

```bash
aws cognito-idp admin-update-user-attributes --user-pool-id <your-user-pool-id> --username <username> --user-attributes Name="email",Value="Victim@gmail.com"
```

If the update succeeds without verification, your setup may be vulnerable.

### Best Practices for Securing Amazon Cognito

To prevent these vulnerabilities, follow these best practices:

* **Disable Self-Signup**: Unless explicitly needed, disable self-signup in your user pool to prevent unauthorized account creation.
* **Restrict Attribute Permissions**: Limit Read/Write access to custom attributes, ensuring only necessary attributes are modifiable by users.
* **Secure Sensitive IDs**: Store App Client IDs, User Pool IDs, and Identity Pool IDs server-side, avoiding exposure in client-side code.
* **Enable Multi-Factor Authentication (MFA)**: Enforce MFA for critical actions to add an extra layer of security.
* **Regular Audits**: Use tools like ScoutSuite to periodically audit your Cognito configurations for misconfigurations.

### Conclusion

Amazon Cognito is a robust tool for user management, but misconfigurations can expose your application to significant risks. By systematically testing for vulnerabilities using the test cases above and implementing best practices, you can ensure your Cognito setup is secure. Stay proactive, audit regularly, and keep up with the latest security research to protect your users and AWS resources.

For further reading, check out these excellent resources:

* [Hacking AWS Cognito Misconfigurations](https://notsosecure.com/hacking-aws-cognito-misconfigurations)
* [Flickr Account Takeover Advisory](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/#assembling-the-puzzle-account-takeover)
* [Exploit Two of the Most Common Vulnerabilities in Amazon Cognito with CloudGoat](https://trustoncloud.com/blog/exploit-two-of-the-most-common-vulnerabilities-in-amazon-cognito-with-cloudgoat/)
* [AWS Cognito Pitfalls: Default Settings Attackers Love](https://www.secforce.com/blog/aws-cognito-pitfalls-default-settings-attackers-love-and-you-should-know-about/)

Stay secure, and happy testing!
