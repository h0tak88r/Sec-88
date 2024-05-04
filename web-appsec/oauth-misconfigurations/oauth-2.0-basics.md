# OAuth 2.0 Basics

**Common Usage of OAuth 2.0:**

* OAuth 2.0 is a widely used authorization framework allowing websites to request limited access to a user's account on another application.
* It facilitates access without exposing login credentials, letting users control the data they share.

**Three Main Parties:**

* **Client Application:** Requests user data.
* **Resource Owner:** User whose data is requested.
* **OAuth Service Provider:** Controls user data and provides APIs for authorization and resource servers.

**Elements in OAuth 2.0:**

* **Resource Owner:** User granting access to protected resources&#x20;
* **User-Agent**: The browser or mobile application through which the resource owner communicates with our authorization server.
* **Resource Server:** Server handling authenticated requests
* **Client Application:** The application that seeks access to resources.
* **Authorization Server:** Server issuing access tokens after authentication (e.g., twitter.com).
* **Client\_id & Client\_secret:** Identifiers for the application, with the secret known only to the app and authorization server.
* **Response\_type:** Specifies the type of token requested (e.g., code).
* **Scope:** Defines the level of access requested.
* **Redirect\_uri:** URL for user redirection after authorization.
* **State:** CSRF protection mechanism.
* **Grant\_type:** Explains the grant type for token retrieval.
* **Code & Access\_token:** A token which is issued as a result of successful authorization. An access token can be obtained for a set of permissions (scopes) and has a pre-determined lifetime after which it expires..
* **Refresh\_token:** Allows obtaining a new access token without user prompt.

### **OAuth 2.0 Flows (Grant Types):**

> [https://www.youtube.com/watch?v=ZDuRmhLSLOY](https://www.youtube.com/watch?v=ZDuRmhLSLOY)

* [Authorization Code](https://oauth.net/2/grant-types/authorization-code/) Grant flow

![This flow is optimized for confidential clients. Confidential clients are apps that can guarantee the secrecy of client\_secret. A part of this flow happens in the front-channel (until the authorization code is obtained). As you can see, the access\_token 🔑 exchange step happens confidentially via back-channel (server-to-server communication).](https://dev-to-uploads.s3.amazonaws.com/i/2j7kqc7qabtfpl250jf2.gif)

* Authorization Code Grant with [PKCE](https://oauth.net/2/pkce/)

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

![](https://dev-to-uploads.s3.amazonaws.com/i/odkf14kzlb5gcbvrmuvx.gif)

*   [Client Credentials](https://oauth.net/2/grant-types/client-credentials/) Grant flow\


    ![a resource owner (user) had to provide consent. There can also be scenarios where a user's authorization is not required every time. Think of machine-to-machine communication (or app-to-app). In this case, the client is confidential by nature and the apps may need to act on behalf of themselves rather than that of the user.](https://dev-to-uploads.s3.amazonaws.com/i/gp4n79x84xujj8mn625w.gif)
*   #### Resource Owner Password Credentials Grant flow <a href="#resource-owner-password-credentials" id="resource-owner-password-credentials"></a>



    ![](https://dev-to-uploads.s3.amazonaws.com/i/6hsfukc7f4rnopbsy04f.gif)
*   #### Resource Owner Password Credentials Grant flow <a href="#resource-owner-password-credentials" id="resource-owner-password-credentials"></a>



    ![](https://dev-to-uploads.s3.amazonaws.com/i/6hsfukc7f4rnopbsy04f.gif)
*   #### Implicit Grant flow <a href="#implicit-grant" id="implicit-grant"></a>



    ![However, the token is passed in the URL fragment (Begins with #) which will never be sent over the network to the redirect URL. Instead, the fragment part is accessed by a script that is loaded in the front-end (as a result of redirection). The access\_token will be extracted in this manner and subsequent calls are made to fetch the resources. As you can already see, this flow is susceptible to access token leakage and replay attacks](https://dev-to-uploads.s3.amazonaws.com/i/90t3te63144tcdven41w.gif)

**OAuth Authentication:**

* Although not originally intended for this purpose, OAuth has evolved into a means of authenticating users as well.
* The "Authorization Code" grant type is commonly used for authentication in websites when implementing features like "Sign in with Google" or similar social login functionalities.&#x20;
