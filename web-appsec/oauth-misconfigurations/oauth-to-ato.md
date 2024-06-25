# OAUTH Security Testing

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

### CSRF

```
-  Integration Linking
-  no state parameter or 
-  state parameter static value 
-  Remove static parameter 
```

<figure><img src="../../.gitbook/assets/image (68).png" alt=""><figcaption><p>Login CSRF</p></figcaption></figure>

### Insufficient Redirect URI Validation

<figure><img src="../../.gitbook/assets/image (69).png" alt=""><figcaption><p>Open Redirec in redirec_uri Leads to 1-Click ATO</p></figcaption></figure>

#### Exploits:

1. **Open Redirect**: Redirect sensitive data to an attacker-controlled server.
   * &#x20;`https://yourtweetreader.com/callback?redirectUrl=https://evil.com`
   *   `Redirec_uri` Bypasses

       ```
       - target.com.evil.com
       - //attacker.com
       - https://attacker.com\@target.com
       - https://attacker.com?@target.com
       - attacker.com%0d%0atarget.com
       - Open-Redirect/SSRF -> Bypass redirect_uri
       ```
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

#### ALL ATTACKS WITH `PROMPT=NONE` TO MINIMISE INTERACTION

<figure><img src="../../.gitbook/assets/image (70).png" alt=""><figcaption><p>With Interaction</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (71).png" alt=""><figcaption><p>With no Interaction</p></figcaption></figure>

### Play With `response_mode`  &#x20;

1.  The normal value to it is `&response_mode=query`

    <figure><img src="../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>
2.  By Changing it's value to fragment the code is leaked in the url after `#` character

    <figure><img src="../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

### Exploit XSS in the Authorization Server to steal Victim's code&#x20;

1. Make  `&response_mode=form_post`   and the response will be for that send's post request with code and state parameter

```http
HTTP 200 OK

<form method="post" 
  action="https://target.com/cb">
<input name="code" value="A9bc5D2e"/>
</form>
```

1.  Attacker can steal the code and state parameter using this code \


    <figure><img src="https://lh7-us.googleusercontent.com/slidesz/AGV_vUdicEhcU-xYnDfTydv3QLyzy9fD-9Gvh6htoLvN6gPWYBxkFeMr9GLBGF2_fioQQDt4l1FFbAiZBKSstMD9_yu02gs-e53ldL4QPty73FGtR8aZbU7p3T89dTPj85IHZPaY7DSA3Zt7TvbqL5fNMiHME9UoRCwN=s2048?key=wpvX88q0Z4uLzcitI4vWuQ" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

### POST-AUTH REDIRECT + LOGIN CSRF

1.  There is endpoint vulnerable to open redirect using it to bypass `redirect_uri` Restrictions and using `&response_mode=fragment` to send code in url&#x20;

    <figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>
2. The website is vulnerable to an open redirect. After a user logs in, we can exploit the `state` parameter to perform a CSRF attack, causing the user to log into our account after completing the OAuth process. However, to steal the user's session/code when they log into the attacker-owned account, we can use `&response_mode=fragment`. This will send the user's code to an attacker-controlled site in the URL after the `#` sign, along with the attacker's code in the query.

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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
