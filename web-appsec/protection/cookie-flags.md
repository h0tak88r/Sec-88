---
description: https://www.invicti.com/white-papers/security-cookies-whitepaper/
---

# Cookie Flags

### Cookie Attributes:

* **`Name`:** Identifies the cookie, can be set without a value.
* **`Domain`:** Specifies the domain to which the cookie will be sent.
* **`Path`:** Determines the URL path for which the cookie will be sent.
* **`Secure`:** Requires the cookie to be sent over HTTPS connections.
* **`Expires`:** Sets the expiration time for the cookie.
* **`Max-Age`:** Specifies the duration of the cookie's validity in seconds.
* **`HttpOnly`:** Restricts cookie access to HTTP requests, preventing JavaScript access.
* **`SameSite`:** Controls how cookies are sent with cross-site requests.
* **`SameSite=Lax`:** cookies are sent with **cross-site GET requests** that result from top-level navigation by the user, such as clicking on a link. This provides a balance between security and usability
* **`SameSite=Strict`:** cookies are **not sent with cross-site requests**. This provides strong protection against CSRF attacks.

#### Cookie Prefixes:

Cookie prefixes play a crucial role in safeguarding cookies against various attacks, including session fixation and cookie overrides. They ensure that cookies are transmitted securely and cannot be tampered with by unauthorized parties.

* **\_\_Secure- Prefix**: When a cookie name is prefixed with `__Secure-`, it indicates that the cookie should only be accessed via HTTPS connections. This helps protect sensitive information from being intercepted over unsecured connections
* **\_\_Host- Prefix**: The `__Host-` prefix serves a similar purpose as `__Secure-`, ensuring that the cookie is only accessible via HTTPS. Additionally, it restricts the cookie to the domain that sets it, preventing subdomains from altering the cookie. This prefix is particularly useful for enhancing security in modern browsers
