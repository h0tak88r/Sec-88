# Auth0 Misconfigurations

## 1 Click Or 0-Click Account  Takeover  Due To Account Linking Misconfiguration In OAUTH

{% embed url="https://community.auth0.com/t/account-takeover-using-log-in-with-google/48208" %}

**0-Click**

* The victim will create a account using the option “Log In with Google”
* The attacker creates an account using the same email and a new password
* Logged in Without confirmation

**1-Click**&#x20;

* Victim will receive a email to confirm the account
* The attacker waits for the victim to click on the confirmation link and he will be able to log in using the password he set for the victim’s account

## Self Registration in Loggin-Only Targets

{% embed url="https://amjadali110.medium.com/how-i-exploited-an-auth0-misconfiguration-to-bypass-login-restrictions-c5d8c20d5505" %}

* **Intercept Login Requests**:
  * Enter random login credentials (any email and password) on the login page and intercept the request with Burp Suite.
  * Inspect the request structure and headers to confirm that it resembles an Auth0 request.
* **Modify the Request**:
  * Send the intercepted login request to Burp Repeater.
  * Change the endpoint from `/co/authenticate` (or similar) to `/dbconnections/signup`.
  * Replace the `username` parameter with `email`, and set the `realm` parameter to `connection`.
  * Add parameters such as `client_id`, `email`, `password`, and `connection` if they’re not already present.
* **Send the Request**:
  * In Burp Repeater, send the modified request.
  * Check for a `200 OK` response and a response body indicating account creation, such as `{"_id":"<id>","email":"<your-email>","email_verified":false}`.
* **Test Access with New Credentials**:
  * Use the credentials you specified in the signup request to attempt login on the application.
  * If successful, this confirms the misconfiguration, as you've bypassed the disabled signup restriction.

## Account Linking Misconfiguration in Aouth-Logging-Only Targets

{% embed url="https://medium.com/@iknowhatodo/exploiting-auth0-misconfigurations-a-case-study-on-account-linking-vulnerabilities-76fb6b9703f8" %}

{% embed url="https://kareemelsadek.github.io/posts/exploiting-auth0-misconfiguration/" %}

1. **Identify the Social Login Mechanism**:
   * Access the login page of the target application and check for any social login options, like "Sign up with Google."
   * Note the primary email address used during the social login (e.g., using `testacc2399@gmail.com`).
2. **Create an Account Using Social Login**:
   * Use the available social login option (like Google) to create an initial user account on the application.
3. **Intercept the Request to Identify the `dbconnection`**:
   * Attempt to create a new account with the same email via the email/password method. If you encounter a failed response, intercept this request in Burp to analyze the `dbconnection` parameter.
   * Identify the correct `dbconnection` name for the application.
4. **Craft a Signup Request with `dbconnection`**:
   * Using Burp Repeater, send a POST request to the Auth0 `/dbconnections/signup` endpoint.
   *   Modify the request as follows:

       ```http
       POST /dbconnections/signup HTTP/2
       Host: auth.<target_domain>.com
       Content-Length: 224
       Content-Type: application/json
       Origin: https://auth.<target_domain>.com
       Referer: https://auth.<target_domain>.com/

       {
         "client_id": "XXXXXXXXXXXXXXXXXXXX",
         "email": "testacc2399@gmail.com",
         "password": "testA@123",
         "connection": "app-prod-users",
         "credential_type": "http://auth0.com/oauth/grant-type/password-realm"
       }
       ```
5. **Verify Account Creation and Linkage**:
   * Submit the request with the correct `dbconnection` and client ID.
   * Check for a successful response indicating the account creation for the same email.
6. **Test Access with Modified Authorization URL**:
   *   Try logging in with the newly created email/password by modifying the authorization URL to use `dbconnection`:

       ```plaintext
       https://auth.<target_domain>.com/authorize?client_id=<client_id>&response_type=token&connection=app-prod-users&prompt=login&scope=openid%20profile%20phone&redirect_uri=<redirect_uri>
       ```
   * Confirm if logging in with email/password redirects you to the original social login account, indicating an unintended account linkage.

## Exploiting Email Normalization and Custom Database Configurations in Auth0 for Account Takeover

{% embed url="https://boom-stinger-c76.notion.site/AuthC-Under-Siege-Innovative-Approaches-to-Penetrate-Authentication-Across-All-Layers-12b53b6a0d6e806486f9ffb2150003e4" %}

1. **Identify the Email Registration Endpoint**:
   * Locate the target application's signup endpoint that uses Auth0, specifically for **Email and Password** authentication. This is where the potential vulnerability exists.
2. **Create a Primary Account**:
   * Register an account with an email like `victim@domain.com` using a password such as `Password123`.
   * Confirm that you can log in with these credentials and access your account details.
3. **Attempt Registration with a Unicode Variant**:
   * Construct an email address with a **visually similar Unicode character**. For example, change `i` to a Unicode dotless or dotted variant:
     * Example: Change `victim@domain.com` to `vıctim@domain.com` (with a dotted or dotless "i").
   * Try to register a new account with this email variant and a **different password** like `Password456`.
4. **Observe the Response**:
   * If Auth0’s **Get User Script** does not normalize Unicode characters, it may allow the creation of this account without triggering a duplicate email error.
   * If the account creation is successful, Auth0 likely has a misconfiguration with email normalization.
5. **Test for Account Credentials Overwrite**:
   * Log in with the Unicode variant email (`vıctim@domain.com`) using the password you set (`Password456`).
   * If this account gives you access to the original account details, Auth0’s **Create User Script** might be normalizing email addresses, leading to the overwriting of the original credentials.
6. **Confirm Account Takeover**:
   * Check if both email variants (`victim@domain.com` and `vıctim@domain.com`) can log in, especially if each set of credentials provides access to the same user data.
   * This behavior suggests that Auth0’s inconsistent email normalization is causing an **account takeover** scenario.
