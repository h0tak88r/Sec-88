# OAUTH Bugs

### Authentication Bypass via OAuth Implicit Flow

1. Study OAuth flow starting from the authorization request `GET /auth?client_id=[...]`.
2. Client receives user info from the OAuth service.
3. Client logs in by sending a POST request to its `/authenticate` endpoint with user info and access token.
4. In Burp Repeater, modify the email in the POST request to impersonate another user.
5. Right-click the POST request, select "Request in browser" > "In original session", visit the URL, and log in as another user.

### Forced OAuth Profile Linking

1. Sign in with a social media profile.
2. Capture the request that includes `redirect_uri` in `/auth?client_id[...]`.
3. Check if the `state` parameter is present. If not, it’s vulnerable to CSRF.
4. Copy the request URL from Burp, drop the request, and turn off intercept.
5. Log out, send the link to the victim, or use an iframe on your website.
6. Victim's browser completes the OAuth flow, linking your profile to their account.

### Insufficient Redirect URI Validation

#### Exploits:

1. **Open Redirect**: Redirect sensitive data to an attacker-controlled server.
   * Example: `https://yourtweetreader.com/callback?redirectUrl=https://evil.com`
2. **Path Traversal**: `https://yourtweetreader.com/callback/../redirect?url=https://evil.com`
3. **Weak Regexes**: `https://yourtweetreader.com.evil.com`
4. **HTML Injection**: `https://app.victim.com/login?redirectUrl=https://app.victim.com/dashboard</script><h1>test</h1>`
5. **XSS**: Reflecting redirect URL in response.

#### Steps:

1. Identify the `redirect_uri` parameter.
2. Construct an exploit URL to steal the authorization code.
3. Use the stolen code to complete the OAuth flow.

### SSRF via OpenID Dynamic Client Registration

1. Browse `/.well-known/openid-configuration` to find the registration endpoint.
2. Create a POST request to register a client.
3. Test if the `logo_uri` parameter is vulnerable to SSRF.

### Stealing OAuth Access Tokens via a Proxy Page

1. Register a client using a POST request.
2. Test `logo_uri` for SSRF to read metadata files.

### OAuth Account without email Address

1. Register account with phone number in 3rd party&#x20;
2. use this account to register on target&#x20;
3. in settings add victim email

### Microsoft nOAuth Misconfiguration

{% embed url="https://bibek-shah.medium.com/noauth-account-takeover-via-microsoft-oauth-cc653410b886" %}

### Facebook OAuth Misconfiguration

{% embed url="https://sl4x0.medium.com/fb-oauth-misconfiguration-leads-to-takeover-any-account-061316a5b31b" %}

1. Click Sign in with Facbook
2. Click "Edit Access"
3. Uncheck Email address
4. You loged in without email address

### OAuth Code Flaws

1. Reuse of authorization codes.
2. Brute-force attacks on codes.
3. Validity of a code across different applications.

### Access Token Scope Abuse

1. Use an access token to access elevated scope endpoints.

### Pre-Account Takeover

1. Register an account with the victim's email and attacker’s password.
2. Victim uses OAuth to register, linking their account to the attacker’s credentials.

### Disclosure of Secrets

* Leaking `client_secret` allows attackers to generate access tokens and access user data.

### Client Secret Brute Force

1.  Brute force the `client_secret` to steal accounts.

    ```plaintext
    POST /token HTTP/1.1
    content-type: application/x-www-form-urlencoded
    host: target-server
    content-length: 135
    Connection: close

    code=authorization_code&redirect_uri=callback_url&grant_type=authorization_code&client_id=client_id&client_secret=[bruteforce]
    ```

### Referrer Header Leaking Code + State

* Verify if the code and state are reflected in the Referrer header when the user navigates to another page.

### Access Token Stored in Browser History

* Ensure access tokens are not stored in browser history.

### Everlasting Authorization Code

* Authorization code should have a short lifespan to limit the attack window.

### Authorization/Refresh Token Not Bound to Client

* Ensure tokens are bound to the specific client.

### Refresh Token Issues

* [ https://medium.com/@iknowhatodo/what-about-refreshtoken-19914d3f2e46](https://medium.com/@iknowhatodo/what-about-refreshtoken-19914d3f2e46).

### Race Conditions in OAuth 2 API Implementations

* Verify for potential race conditions that can lead to security issues.

### Summary

OAuth implementations can be vulnerable to various security issues. By understanding these vulnerabilities and following the steps outlined, you can effectively test and secure OAuth flows.

#### References

* [Stealing Users OAuth Tokens through redirect\_uri parameter](https://hackerone.com/reports/665651)
* [What about Refresh Token](https://medium.com/@iknowhatodo/what-about-refreshtoken-19914d3f2e46)
* [Account Takeover Chain](https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html)
