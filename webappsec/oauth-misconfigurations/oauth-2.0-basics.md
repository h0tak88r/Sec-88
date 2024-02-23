# OAuth 2.0 Basics

1. **Common Usage of OAuth 2.0:**
   * OAuth 2.0 is a widely used authorization framework allowing websites to request limited access to a user's account on another application.
   * It facilitates access without exposing login credentials, letting users control the data they share.
2. **Three Main Parties:**
   * **Client Application:** Requests user data.
   * **Resource Owner:** User whose data is requested.
   * **OAuth Service Provider:** Controls user data and provides APIs for authorization and resource servers.
3. **Elements in OAuth 2.0:**
   * **Resource Owner:** User granting access to protected resources (e.g., Twitter user).
   * **Resource Server:** Server handling authenticated requests (e.g., Twitter server).
   * **Client Application:** Application requesting authorization (e.g., yourtweetreader.com).
   * **Authorization Server:** Server issuing access tokens after authentication (e.g., twitter.com).
   * **Client\_id & Client\_secret:** Identifiers for the application, with the secret known only to the app and authorization server.
   * **Response\_type:** Specifies the type of token requested (e.g., code).
   * **Scope:** Defines the level of access requested.
   * **Redirect\_uri:** URL for user redirection after authorization.
   * **State:** CSRF protection mechanism.
   * **Grant\_type:** Explains the grant type for token retrieval.
   * **Code & Access\_token:** Authorization code used to fetch access token.
   * **Refresh\_token:** Allows obtaining a new access token without user prompt.
4. **OAuth 2.0 Flows:**
   * Authorization Code and Implicit grant types are common. They involve stages such as requesting access, user consent, receiving access tokens, and using them for API calls.
5. **OAuth Authentication:**
   * Although not originally intended for this purpose, OAuth has evolved into a means of authenticating users as well.
   * Many websites offer logins through social media accounts using OAuth.
6. **OAuth Authentication Process:**
   * User chooses to log in with a social media account.
   * Client app uses social media OAuth service to request user-identifying data.
   * Access token received; client app requests user data from the resource server.
   * User is logged in using the received data, and the access token is often used as a substitute for a password.
7. **Vulnerabilities:**
   * OAuth 2.0 is prone to implementation mistakes, leading to vulnerabilities.
   * Exploiting these vulnerabilities can allow attackers to obtain sensitive user data or bypass authentication.
