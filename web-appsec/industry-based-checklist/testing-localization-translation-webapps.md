# Testing localization - Translation WebApps

### Authentication & Account Verification

* Test bypass of email verification by verifying a victim’s email with an attacker’s email-verification code.
* Test OAuth misconfiguration in Facebook, Microsoft, and GitLab.
* Usually these targets have a domain verification feature, so if anyone signs up with an email from your domain your Org/Workspace will show up as a suggested workspace to join. Try to perform email verification for domains you don’t own or for @gmail.com; if it succeeds, it is a bug.
* Test paywall bypass bugs on 2FA enforcement.
* Test paywall bypass enforcing 2FA on the free plan.

### Roles, Permissions & Access Control

* Those targets usually consist of orgs/workspaces and members with permissions. Common permissions in such targets are Owner, Manager, Proofreader, Translator, Language Coordinator, and sometimes hidden or custom roles that are not available to you or are a paid feature. Make sure to analyze the JavaScript files and try to make requests to invite a user with this role or try to attach this role in the invitation acceptance process.
* Usually the org/workspace supports managing multiple projects, so one user can be invited workspace-wide as a manager but removed from one project. The bug is that via the API this removed manager can still access some data/features from the project they were removed from.
* Usually the Language Coordinator role has an access control issue: direct API calls can get words, translations, or files from other languages you are not assigned to.
* Test exposing user-groups of a specific project to a translator-role member.
* Test translator improper access control on api.target.cloud/v1/owners/\[UID]/workflows/live that leads to leakage of workflow details.
* Test improper access control that leads to unauthorized access to all screenshots, including unassigned screenshots that translators cannot see.
* Test improper access control that leads to unauthorized access to project processes.
* Test improper access control that leads to exposure of all contributors’ PII.
* Test broken access control in API endpoints that allows removed developers/managers to read and delete archived reports.

### API, IDORs & Data Exposure

* There are reports for translations that usually have UUID IDORs and privilege escalation in this section.
* Test IDOR on `app.target.com/translation/{translation_id}/history` that leads to access of all history information for unassigned language translations.
* Some targets don’t share real emails for org members, so test excessive data exposure in the API endpoint `api.target.com/api2/projects/{project_id}/translations` that leads to unauthorized access to team members’ real emails.
* Test IDORs in translation comments.
* Test IDOR on `api.target.com/project/[PROJECT_ID]/keys/[KEY_ID]`.
* Test IDOR in API endpoints that allows translators unauthorized access to owner-generated reports.
* Test IDORs and excessive data exposure that could reveal contributor PII or private emails.

### UI, Input Validation & Stored Vulnerabilities

* Usually these targets don’t implement AI well and have many problems. They may allow adding a custom prompt, and this specific section is often vulnerable to stored XSS.
* There are multiple sections that have XSS/HTML bugs too, such as the editor and the translation values input, and so on.
* Test for stored XSS in custom prompt features and in editors/translation input fields.

- Sometimes there is a feature to move/copy a project to other workspaces. This usually bypasses external project ownership and can exceed free-tier user limits.
- Test if there are features to make your project public and try to get some URLs from the web archive and self-join it as the lowest role; then test if privilege escalation allows public access to tasks of any public project.
- Test project branching feature for paywall bypass or privilege escalation.
- Some workflows are Pro-only, so test business logic errors on api.target.cloud through /v1/groups/{group\_id}/workflows/{workflow\_id}/actions/activate to see if it leads to bypassing Pro-only workflow restrictions.
- Test project copy/move and branching behaviors for potential free-tier or ownership bypasses.

### Notifications & Information Leakage

* Test misconfiguration in the notification system that leads to exposure of translation information for unassigned languages (test email-based and in-app notifications).

### Integrations, CSRF & Privilege Escalation

* Test privilege escalation + CSRF in the org integrations.
* Test CSRF and privilege escalation risks in integration management flows.

### Race Conditions & Concurrency

* Test race conditions that allow exceeding the maximum number of invites for a free plan and other feature limits.
