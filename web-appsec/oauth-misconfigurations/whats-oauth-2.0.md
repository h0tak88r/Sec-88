# What's OAUTH 2.0

## OAuth 2.0 Basics:

1. **Overview:**
   * OAuth 2.0 is a framework for authentication and authorization.
   * Widely used for third-party applications to access user resources without exposing credentials.
2. **Elements in OAuth 2.0:**
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

#### Differentiating Authorization Code and Implicit Grant Type:

**Authorization Code Grant Type:**

1. **Authorization Request:**
   * Involves an authorization request to the /authorization endpoint.
   * Uses response\_type=code.
   * Redirects user to /callback with an authorization code.
2. **Authorization Code Grant:**
   * User is redirected to /callback with the authorization code.
   * Backend processes include access token grant and API calls.

**Implicit Grant Type:**

1. **Authorization Request:**
   * Similar to authorization code flow but with response\_type=token.
   * Redirects user to /callback with access token in the URL fragment.
2. **Access Token Grant:**
   * /callback contains access token as a parameter.
   * User authentication and consent redirect to /callback with access token.

#### OAuth 2.0 Workflow:

1. **Parties Involved:**
   * Client Application, Resource Owner, OAuth Service Provider.
2. **Common Stages:**
   * Requesting access, user consent, receiving access token, making API calls.

#### OAuth 2.0 for Authentication:

1. **Authentication Mechanism:**
   * OAuth evolved for user authentication.
   * Similar to SAML-based single sign-on (SSO).
2. **Authentication Process:**
   * User logs in with social media account.
   * Client app requests access to user data for identification.
   * Access token received, data fetched from /userinfo endpoint.
   * Access token used for user login.

#### Summary:

OAuth 2.0 is a versatile framework for authorization and, when used in conjunction with OpenID Connect, for authentication. It involves various components like the resource owner, resource server, client application, and authorization server. Different grant types, such as authorization code and implicit, determine the flow. The OAuth process includes requesting access, user consent, and token-based API calls. Additionally, OAuth has evolved to support user authentication, often used in scenarios resembling single sign-on. Understanding the basics and different grant types is crucial for secure implementation.
