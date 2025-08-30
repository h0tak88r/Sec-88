# Amazon Cognito Misconfiguraitons

Amazon Cognito is a powerful service for managing user authentication and authorization in web and mobile applications. However, misconfigurations in Cognito can open the door to serious security risks, such as account takeovers, privilege escalations, and unauthorized access to AWS resources. In this blog post, we’ll explore common Cognito misconfigurations, provide a detailed table of test cases to identify vulnerabilities, and share practical tips to secure your Cognito setup. Whether you’re a developer, security professional, or DevOps engineer, this guide will help you strengthen your AWS environment.

### Why Amazon Cognito Security Matters

Amazon Cognito simplifies user management with its user pools (for sign-up and sign-in) and identity pools (for AWS resource access). However, its flexibility can lead to misconfigurations that attackers exploit. Recent research, including case studies like the Flickr account takeover, highlights how seemingly minor oversights—such as allowing unverified email updates or exposing sensitive IDs—can lead to catastrophic breaches. By proactively testing for these issues, you can protect your application and users from such risks.

### **Common UserPools attacks** <a href="#id-8c4c" id="id-8c4c"></a>

* [ ] &#x20;**Detect Cognito UserPools usage**: Extract UserPoolID or ClientId from the JS/HTML or Signup/Login
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
* [ ] **Unverified Email/Phone Attributes:**&#x20;

-   If application doesn't require email verification this may lead to duplicate registerationa, Account Overwrite and ATO attacks\


    <figure><img src="../.gitbook/assets/image (325).png" alt=""><figcaption></figcaption></figure>
- If an email address is configured as an alias and a new user is created with a duplicate email, the alias can be transferred to the newer user, un-verifying the former user's email\
  [https://repost.aws/knowledge-center/cognito-email-verified-attribute](https://repost.aws/knowledge-center/cognito-email-verified-attribute)

* [ ] **Insecure Callback URLs**: Insecure callback URL configurations are a common misconfiguration in OAuth 2.0 and OIDC flows used by Cognito. This includes using HTTP instead of HTTPS (except for `http://localhost` for testing), configuring overly broad wildcard URLs (e.g., `*` or `*.example.com`), or failing to strictly validate the redirect URI in authentication requests\
  [https://community.auth0.com/t/security-risks-of-using-localhost-for-callback-url/118781/1](https://community.auth0.com/t/security-risks-of-using-localhost-for-callback-url/118781/1)\
  [https://repost.aws/questions/QURn-XLoSyQoGDbfqr6H\_BAw/adding-localhost-to-hosted-ui-callback-urls-for-testing-security-risks](https://repost.aws/questions/QURn-XLoSyQoGDbfqr6H_BAw/adding-localhost-to-hosted-ui-callback-urls-for-testing-security-risks)
* [ ] **MFA Enforcement Bypass Scenarios:**&#x20;

- Attempt to authenticate without providing MFA after password entry.
- Test if MFA can be disabled by a standard user (User unintentionally has the `Wright` permission).

* [ ] **Password Reset and Account Recovery**: Test for race conditions or token replay vulnerabilities in the reset process

<figure><img src="../.gitbook/assets/image (324).png" alt=""><figcaption></figcaption></figure>

* [ ] **Misconfigured Attributes read and write permissions**: In some websites users can't update their info like email in the UI so attacker can change this info via the API if the attribute write permission is enabled
* [ ] **Token Revocation Issues:** Cognioto Succesfully revoked the code but the application's api didn't

<figure><img src="../.gitbook/assets/image (326).png" alt=""><figcaption></figcaption></figure>

* [ ] **Token Intigriti Issues:**

> - The session is indeed checked to see if it lines up with the correct username.
> - The **`IdToken`** is checked to see if it’s valid (i.e., not expired).
> - **However**, there wasn’t any code linking that **`IdToken`** to the specific session or user. That’s because the dev who wrote the custom challenge logic didn’t do that last piece of validation!

[**https://boom-stinger-c76.notion.site/AWS-Cognito-Chaos-The-Major-Flaw-That-Let-Attackers-Takeover-User-Accounts-17953b6a0d6e80bf8a75f6d03654eecf**](https://boom-stinger-c76.notion.site/AWS-Cognito-Chaos-The-Major-Flaw-That-Let-Attackers-Takeover-User-Accounts-17953b6a0d6e80bf8a75f6d03654eecf)



**Test Third-Party Identity Providers (IdP) and Federation**

* [ ] &#x20;**Test for Arbitrary Identity Token Acceptance**: If Cognito accepts ID tokens from any IdP without validation, it may allow attackers to impersonate users

1. Forge a valid-looking **JWT token** (for OIDC) with your own IdP (e.g., a local Keycloak or Auth0 instance).
2. Set the `iss` (issuer) to match the target’s expected IdP.
3. Replace the `aud` with the expected Cognito client ID.

```bash
curl -X POST https://<domain>.auth.<region>.amazoncognito.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=...&redirect_uri=..." \
  -H "Authorization: Bearer <your_forged_token>"
```

* [ ] &#x20;**IDP Role Injection via Claims Mapping:** If role/permission claims from IdP are mapped to AWS roles or Cognito groups without validation, an attacker could elevate privileges

- Forge or modify an identity assertion (SAML or JWT) that includes elevated claims like:

```json
jsonCopyEdit"custom:role": "admin"
```

* Use a test IdP you control to submit these claims.
* Watch if Cognito accepts the claim and assigns privileges (e.g., in app or AWS permissions).

- [ ] &#x20;**Scope/Claims Overreach**: If the application doesn’t restrict OIDC/SAML scopes/claims, attackers might access unintended user data.

* Try requesting **excessive scopes**:

```http
httpCopyEditscope=openid profile email aws.cognito.signin.user.admin
```

* Look at returned claims in `id_token` or `access_token`

### Common IdentityPools attacks <a href="#id-8841" id="id-8841"></a>

* [ ] &#x20;**Dorks**

```
IdentityPoolId 
Aws_cognito_identity_pool_id 
Identity Pool Id 
AWSCognitoIdentityService 
clientId 
client_id 
aws_user_pools_web_client_id
```

*   [ ] **Leakage of Secrets like Identity Pool ID in JS Files:** Inspect client-side code or API responses for exposed Identity Pool IDs, then attempt to generate temporary AWS credentials then use tool to enumerate permissions associated with these credentials like [_**Enumerate-iam**_](https://github.com/andresriancho/enumerate-iam). \
    \
    `aws cognito-identity get-id --identity-pool-id '[IdentityPoolId]' --logins "cognito-idp.{region}.amazonaws.com/{UserPoolId}={idToken}"`\
    \
    `aws cognito-identity get-credentials-for-identity --identity-id '{IdentityId}' --logins "cognito-idp.{region}.amazonaws.com/{UserPoolId}={idToken}"`\
    **Reference**: [AWS Cognito Pitfalls: Default Settings Attackers Love](https://www.secforce.com/blog/aws-cognito-pitfalls-default-settings-attackers-love-and-you-should-know-about/)\
    **Reference**: [Exploit Two of the Most Common Vulnerabilities in Amazon Cognito with CloudGoat](https://trustoncloud.com/blog/exploit-two-of-the-most-common-vulnerabilities-in-amazon-cognito-with-cloudgoat/)\
    **Reference**: [AWS Cognito Pitfalls: Default Settings Attackers Love](https://www.secforce.com/blog/aws-cognito-pitfalls-default-settings-attackers-love-and-you-should-know-about/)\
    **Reference**: [Hacking AWS Cognito Misconfigurations](https://notsosecure.com/hacking-aws-cognito-misconfigurations)

    <figure><img src="../.gitbook/assets/image (322).png" alt=""><figcaption><p>js file leak the AWS credentials ( User Pool ID, User Pool ID, Region)</p></figcaption></figure>

### Cognito + Google OAUTH

{% embed url="https://boom-stinger-c76.notion.site/Authentication-Bypass-17853b6a0d6e80f8aea8d59e9e5dc874" %}

An application uses **Google OAuth** and **Amazon Cognito** together. Here’s the vulnerable flow:

1. **Login via Google**\
   The user signs in via Google. Cognito returns tokens including an **IdToken** that contains the Google `user_id` (a unique identifier linked to the user's Google account).
2. **Account Linking**\
   The app calls a `/v1/user/connect` endpoint to link that `user_id` with the user's email in the app, using the IdToken of course.
3. **Changing Email via Cognito**\
   When a user updates their email in the app, Cognito processes the change (via `UpdateUserAttributes`) but marks the email as _unverified_.
4. **Token Refresh Leak**\
   If the user then refreshes their token using their **RefreshToken**, Cognito issues a new IdToken that now includes the _unverified_ email—because it's embedded directly in the token regardless of verification status.

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

### Refrences

For further reading, check out these excellent resources:

* [Hacking AWS Cognito Misconfigurations](https://notsosecure.com/hacking-aws-cognito-misconfigurations)
* [https://medium.com/@mukundbhuva/account-takeover-due-to-cognito-misconfiguration-earns-me-xxxx-3a7b8bb9a619](https://medium.com/@mukundbhuva/account-takeover-due-to-cognito-misconfiguration-earns-me-xxxx-3a7b8bb9a619)
* [https://www.youtube.com/watch?v=rJEealvGdJo](https://www.youtube.com/watch?v=rJEealvGdJo)
* [Flickr Account Takeover Advisory](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/#assembling-the-puzzle-account-takeover)
* [Exploit Two of the Most Common Vulnerabilities in Amazon Cognito with CloudGoat](https://trustoncloud.com/blog/exploit-two-of-the-most-common-vulnerabilities-in-amazon-cognito-with-cloudgoat/)
* [AWS Cognito Pitfalls: Default Settings Attackers Love](https://www.secforce.com/blog/aws-cognito-pitfalls-default-settings-attackers-love-and-you-should-know-about/)

Stay secure, and happy testing!
