# Ban Feature

<details>

<summary><strong>Inbound Interactions (Active User → Banned User)</strong></summary>

* [ ] **The Collaboration Test:** Can an active user invite, assign, or add the banned user's email/ID to a private project, team, or workspace?.
* [ ] [**Banned user still able to invited to reports as a collabrator and reset the password**](https://hackerone.com/reports/1959219)
* [ ] **The Asset Transfer Test**: Can an active user transfer ownership of a resource (e.g., a repository, a billing account, or funds) to the banned user?
* [ ] **The Mention/Ping Test**: Can an active user tag (@mention) or send Direct Messages to the banned user? Does the system process it and send an email notification to the banned user?

</details>

<details>

<summary><strong>Outbound Interactions (Banned User → Application)</strong></summary>

* [ ] **The Stale Session Test:** If you ban an account while it has an active session in another browser, does that session die immediately? Can the banned user still navigate the site or make API calls using the old session cookie?
* [ ] **The API Token Test:** Do Personal Access Tokens (PATs) or API keys get revoked upon banning? Try using an old API token to fetch or modify data.
* [ ] **The OAuth / SSO Test:** If the banned user logs in via a third party (like "Login with Google" or a corporate SSO), can they still authenticate into peripheral services, support portals, or subdomains?

</details>

<details>

<summary><strong>Unauthenticated Feature Access</strong></summary>

* **The Password Reset Test:** Can the banned user request a password reset, receive the email, and successfully change their password?
* **The Email Verification Test:** If the banned user tries to re-verify their email or click an old "Confirm Email" link, does the application process it and accidentally restore their account state?
* **The Support Portal Test:** Can the banned user create support tickets or interact with the Zendesk/Helpdesk integration using their banned email?

</details>

<details>

<summary><strong>Data Privacy &#x26; Leakage</strong></summary>

* **The Profile IDOR Test:** The frontend might return a 404 for the banned user's profile, but does the API (e.g., `/api/v1/users/{banned_id}`) still leak their PII (Personally Identifiable Information)?
* **The Webhook/Integration Test:** If the banned user previously set up webhooks or Slack/Discord integrations, are those integrations still firing and sending company data to the banned user's external servers?

</details>
