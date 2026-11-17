# Industry Based Web Checklist

### Testing Financially-Oriented WepApps

<details>

<summary><strong>TOCTOU / Race-Condition Tests</strong></summary>

* [ ] &#x20;Attempt concurrent transactions (e.g., two simultaneous money/points transfers) to see if checks are bypassed.&#x20;
* [ ] During checkout: open payment page, then from another tab/session modify basket or amount and return to pay — verify the final transaction reflects correct state (Deposit process when an application can hold user balances).&#x20;
* [ ] After payment completion: attempt to modify the order (items, quantity, details) and see if changes are allowed without fresh payment/validation.&#x20;

</details>

<details>

<summary><strong>Parameter Manipulation Tests</strong></summary>

* [ ] Price Manipulation: adjust hidden/posted “price” field (e.g., negative values, 0, manipulated discount) and verify final price is correct.&#x20;
* [ ] Currency Manipulation: change currency parameter in payment request (if multi-currency supported) to a lower value currency and check for inconsistent credit.&#x20;
* [ ] Currency Manipulation: In the Provider Itself

<figure><img src="../.gitbook/assets/image (360).png" alt=""><figcaption></figcaption></figure>

* [ ] Shipping Address / Posting Method Manipulation: modify shipping address/post method late in checkout (or after payment page loaded) and verify cost/tax adjustments are validated.&#x20;
* [ ] Additional Costs Manipulation: test gift-wrap, expedited shipping, other cost-adders – see if they can be removed or manipulated to reduce cost improperly.&#x20;
* [ ] Response Manipulation: intercept the server response or third-party payment callback and attempt to manipulate it (e.g., change “paid” status) and verify backend rejects tampered responses.&#x20;
* [ ] Repeating Input Parameters: send duplicate parameters (e.g., amount=2\&amount=3) or weird arrays and check how the server handles duplicates.&#x20;
* [ ] Omitting Input Parameter or Value: remove a parameter entirely or send null/empty or malformed (e.g., missing equals sign) and check for unintended behaviour.&#x20;
* [ ] Mass Assignment / Auto-Binding / Object Injection: send extra parameters (not expected by front end) to see if internal objects get manipulated (e.g., set “due\_date” far in future).&#x20;
* [ ] Combined Parameter Changes: change more than one parameter (e.g., price + quantity, shipping method + address) to detect logical flaws in combination.&#x20;
* [ ] Quantity Manipulation: test fractional, negative, zero quantities, very large quantities and verify price and quantity enforcement.&#x20;

</details>

<details>

<summary><strong>Replay Attacks</strong></summary>

* [ ] Replay an encrypted parameter request (or reuse encrypted token) and test if the system treats it as new/valid transaction.&#x20;
* [ ] Replay a successful payment callback (with same transaction id) and see if the system re‐credits or re‐processes the transaction.&#x20;

</details>

<details>

<summary><strong>Rounding &#x26; Numerical Processing Tests</strong></summary>

* [ ] Currency Rounding: deposit/convert currencies (or buy items) where rounding difference is exploited (e.g., $0.20 → £0.1352 → $0.2004) and check for profit behaviour.&#x20;

- Negative Numbers: test negative values for price, deposit, quantity to see if logic is reversed (e.g., user gets credit).&#x20;
- Decimal Numbers: test decimal values where integers expected for quantity/price and observe rounding or truncation issues.&#x20;
- Generic Rounding: deposit e.g., £10.0049 but only £10.00 withdrawn and balance credited incorrectly — repeat many times to verify exploitability.&#x20;
- Large or Small Numbers: send very large or very small numbers beyond normal bounds and verify validations.&#x20;
- Overflows/Underflows: test inputs near variable limits (e.g., max int, min int) and check for roll-over behaviour.&#x20;
- Zero / Null / Subnormal Numbers: test “0”, “0.00”, “-0.00”, “1e-50”, etc and check if system handles them properly.&#x20;
- Exponential Notation: send numbers like “9e99”, “1e-1” to test parsing and logic bypass.&#x20;
- Numbers in Different Formats: test “001.0000”, “$10”, “£0”, “-0.00”, etc to verify correct numeric parsing across tech stacks.&#x20;

</details>

<details>

<summary><strong>Card Number / Payment Card Related Tests</strong></summary>

* [ ] Ensure that saved card numbers are not fully displayed during checkout or in HTTP responses; only last 4 digits if needed.&#x20;
* [ ] Attempt enumeration: test registering duplicate cards across accounts (if site blocks duplicates) to see if card numbers of other users can be deduced.&#x20;

</details>

<details>

<summary><strong>Dynamic Prices / Referral Schemes Tests</strong></summary>

* [ ] If dynamic pricing exists (based on currency, device, referral code, time), submit a price number close (± 0.01) to original and check if unexpected margin accepted.&#x20;
* [ ] Verify that the dynamic pricing logic is properly signed/cryptographically protected so user can’t manipulate input.&#x20;

</details>

<details>

<summary><strong>Discount Codes / Vouchers / Reward Points / Gift Cards Tests</strong></summary>

* [ ] Earning More Points/Cash than Price: purchase with points, then verify if points are earned in the same transaction, resulting in net gain.&#x20;
* [ ] Using Expired/Invalid/Other Users’ Codes: apply expired or someone else’s codes to see if system rejects correctly.&#x20;
* [ ] Refund Abuse: buy item, refund it, in between spend points or get free items — check full reversal of associated rewards.&#x20;
* [ ] State & Basket Manipulation: modify basket after discount calculation (remove items, mix discounted & non-discounted) and check discount still valid incorrectly.&#x20;
* [ ] Ordering Out of Stock or Unreleased Items: attempt to buy items flagged “out of stock” or “not yet released” to check if order is still processed with discount/exploit.&#x20;
* [ ] Bypassing Restrictions: test limited-quantity offers, customer-specific offers, one-time vouchers in multiple accounts to verify restrictions.&#x20;
* [ ] Point Transfer: if users can transfer loyalty points or rewards (e.g., closing account or lost card) test for abuse of transfer + race conditions.&#x20;
* [ ] Enumeration / Guessing: attempt to guess voucher/gift card codes or loyalty codes for other users; verify code generation randomness/unpredictability.&#x20;
* [ ] Buy-X-Get-Y-Free: check if cheapest vs expensive items are correctly discounted or if logic allows paying for cheaper and getting expensive item free.&#x20;
* [ ] Offers/Voucher Stacking: check if multiple promotions (buy-one-get-one, 3-for-2, etc) can be combined incorrectly to reduce cost unfairly.&#x20;

</details>

<details>

<summary><strong>Cryptography &#x26; Backend/API Tests</strong></summary>

* [ ] Encryption/Decryption misuse: check if encrypted parameters can be used to shape arbitrary data (replay, manipulate).&#x20;
* [ ] Downloadable/Virtual Goods: attempt direct object reference (e.g., guess URL of non-free asset) and check if access is restricted.&#x20;
* [ ] Hidden/insecure backend APIs: discover APIs not exposed in UI (e.g., admin, bulk operations) and test for unauthorized access or balance adjustment.&#x20;
* [ ] Test data in production: check for debug/test payment endpoints, dummy card numbers left in production environment that can be exploited.&#x20;
* [ ] Hash/signature concatenation issues: test if signature protects against tampering - e.g., moving part of one parameter into another but same signature.&#x20;
* [ ] Review cryptography implementation: ensure strong algorithms (avoid custom weak crypto), check for brute-force vulnerability of secret keys.&#x20;

</details>

<details>

<summary><strong>Currency Arbitrage / Deposit/Refund Tests</strong></summary>

* [ ] Verify if different parts of system (deposit API / withdrawal API) use inconsistent exchange rates or rounding rules.&#x20;
* [ ] Deposit in one currency, withdraw in another, exploit rounding/exchange rate differences for profit.&#x20;

</details>

<details>

<summary><strong>References</strong></summary>

{% embed url="https://soroush.me/downloadable/common-security-issues-in-financially-orientated-web-applications.pdf" %}

</details>

### Testing localization - Translation WebApps

<details>

<summary><strong>Authentication &#x26; Account Verification</strong></summary>

* Test bypass of email verification by verifying a victim’s email with an attacker’s email-verification code.
* Test OAuth misconfiguration in Facebook, Microsoft, and GitLab.
* Usually these targets have a domain verification feature, so if anyone signs up with an email from your domain your Org/Workspace will show up as a suggested workspace to join. Try to perform email verification for domains you don’t own or for @gmail.com; if it succeeds, it is a bug.
* Test paywall bypass bugs on 2FA enforcement.
* Test paywall bypass enforcing 2FA on the free plan.

</details>

<details>

<summary><strong>Roles, Permissions &#x26; Access Control</strong></summary>

* Those targets usually consist of orgs/workspaces and members with permissions. Common permissions in such targets are Owner, Manager, Proofreader, Translator, Language Coordinator, and sometimes hidden or custom roles that are not available to you or are a paid feature. Make sure to analyze the JavaScript files and try to make requests to invite a user with this role or try to attach this role in the invitation acceptance process.
* Usually the org/workspace supports managing multiple projects, so one user can be invited workspace-wide as a manager but removed from one project. The bug is that via the API this removed manager can still access some data/features from the project they were removed from.
* Usually the Language Coordinator role has an access control issue: direct API calls can get words, translations, or files from other languages you are not assigned to.
* Test exposing user-groups of a specific project to a translator-role member.
* Test translator improper access control on api.target.cloud/v1/owners/\[UID]/workflows/live that leads to leakage of workflow details.
* Test improper access control that leads to unauthorized access to all screenshots, including unassigned screenshots that translators cannot see.
* Test improper access control that leads to unauthorized access to project processes.
* Test improper access control that leads to exposure of all contributors’ PII.
* Test broken access control in API endpoints that allows removed developers/managers to read and delete archived reports.

</details>

<details>

<summary><strong>API, IDORs &#x26; Data Exposure</strong></summary>

* There are reports for translations that usually have UUID IDORs and privilege escalation in this section.
* Test IDOR on `app.target.com/translation/{translation_id}/history` that leads to access of all history information for unassigned language translations.
* Some targets don’t share real emails for org members, so test excessive data exposure in the API endpoint `api.target.com/api2/projects/{project_id}/translations` that leads to unauthorized access to team members’ real emails.
* Test IDORs in translation comments.
* Test IDOR on `api.target.com/project/[PROJECT_ID]/keys/[KEY_ID]`.
* Test IDOR in API endpoints that allows translators unauthorized access to owner-generated reports.
* Test IDORs and excessive data exposure that could reveal contributor PII or private emails.

</details>

<details>

<summary><strong>UI, Input Validation &#x26; Stored Vulnerabilities</strong></summary>

* Usually these targets don’t implement AI well and have many problems. They may allow adding a custom prompt, and this specific section is often vulnerable to stored XSS.
* There are multiple sections that have XSS/HTML bugs too, such as the editor and the translation values input, and so on.
* Test for stored XSS in custom prompt features and in editors/translation input fields.
* Sometimes there is a feature to move/copy a project to other workspaces. This usually bypasses external project ownership and can exceed free-tier user limits.
* Test if there are features to make your project public and try to get some URLs from the web archive and self-join it as the lowest role; then test if privilege escalation allows public access to tasks of any public project.
* Test project branching feature for paywall bypass or privilege escalation.
* Some workflows are Pro-only, so test business logic errors on api.target.cloud through /v1/groups/{group\_id}/workflows/{workflow\_id}/actions/activate to see if it leads to bypassing Pro-only workflow restrictions.
* Test project copy/move and branching behaviors for potential free-tier or ownership bypasses.

</details>

<details>

<summary><strong>Notifications &#x26; Information Leakage</strong></summary>

* Test misconfiguration in the notification system that leads to exposure of translation information for unassigned languages (test email-based and in-app notifications).

</details>

<details>

<summary><strong>Integrations, CSRF &#x26; Privilege Escalation</strong></summary>

* Test privilege escalation + CSRF in the org integrations.
* Test CSRF and privilege escalation risks in integration management flows.

</details>

<details>

<summary><strong>Race Conditions &#x26; Concurrency</strong></summary>

* Test race conditions that allow exceeding the maximum number of invites for a free plan and other feature limits.

</details>
