# Logout Feature

<details>

<summary><strong>Server-Side Session Invalidation (The Replay Attack)</strong></summary>

* [ ] **Active session replay:** Capture a high-privilege state request (e.g., `/api/v1/settings`) in Burp Suite. Click logout in the browser, then replay the captured request from Burp Repeater. If it returns a `200 OK` with sensitive user data instead of `401 Unauthorized`, the session is still active on the server.
* [ ] **Token extraction from cookies:** Copy all session cookies (e.g., `session`, `JWT`, `auth_token`) before logging out. Log out, manually inject those copied cookies back into your browser storage, and refresh the page to see if you are logged back in.
* [ ] **Concurrent session termination:** Log into the account from two different browsers (Browser A and Browser B). Log out from Browser A. Check if Browser B is automatically logged out or if its session remains completely functional.
* [ ] **OAuth / OIDC token revocation:** If the app uses single sign-on (SSO), verify whether clicking logout actually invalidates the access/refresh tokens on the identity provider backend, or if it just deletes them locally from browser memory.

</details>

<details>

<summary><strong>Cross-Site Request Forgery (CSRF) on Logout</strong></summary>

* [ ] **Lack of CSRF tokens:** Inspect the logout request (whether it's a `GET /logout` link or a `POST /api/auth/logout` button). If there is no unique, unpredictable token validating the request, it is vulnerable to a forced logout attack.
* [ ] **GET method usage:** Check if the logout action can be triggered via a simple `GET` request. If an attacker can drop an image tag like `<img src="[https://target.com/logout](https://target.com/logout)">` onto a forum, any visiting user will be instantly logged out.
* [ ] **Token omission / alteration:** If a CSRF token _is_ present in a logout `POST` request, remove it entirely or swap it with a random string. If the server logs you out anyway, the token validation is broken.
* [ ] **SameSite cookie laxity:** Verify if the session cookies lack the `SameSite=Strict` or `SameSite=Lax` attributes. If they are marked `SameSite=None`, cross-site attacks can easily leverage them to force logout state changes.

</details>

<details>

<summary><strong>Browser cache back-button exposure</strong></summary>

* [ ] **Browser cache back-button exposure:** Log out of the application, then immediately click the browser's "Back" arrow. Check if sensitive pages cached in the browser state are fully readable without re-authenticating.

</details>
