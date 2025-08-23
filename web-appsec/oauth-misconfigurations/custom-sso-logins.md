# Custom SSO Logins

{% embed url="https://rikeshbaniya.medium.com/account-takeover-using-sso-logins-fa35f28a358b" %}

## Okta SSO

**Normal Flow**:

* On `target.com`, “OrganizationA” has users like `admin@gmail.com`, `user1@gmail.com`.
* Admin sets up Okta SSO for OrganizationA, creating Okta accounts for these emails.
* Users log in via Okta; `target.com` trusts Okta’s claim (e.g., “you’re `user1@gmail.com`”), granting access to OrganizationA.

**The Bug**:

* Victim (`victim@gmail.com`) belongs to `VictimOrganization` on `target.com`.
* Attacker creates `AttackerOrganization` on `target.com` and invites `victim@gmail.com`.
* Attacker sets up their own Okta instance for `AttackerOrganization`, creating a fake user with `victim@gmail.com` (no email verification required).
* Attacker logs into `target.com` via their Okta, authenticated as `victim@gmail.com`.
* Since `victim@gmail.com` is in `VictimOrganization`, attacker switches to it, accessing victim’s data/functionality (e.g., sensitive files, settings).

## Bug Bounty Guide

**Reproduce the Bug**:

1. **Check SSO**: Register/login on `target.com`; look for custom SSO (Okta, Auth0). Check if email verification is skipped.
2. **Create Fake Org**: Create your own organization (e.g., `AttackerOrg`) on `target.com`. Invite `victim@gmail.com` (use a test email you control).
3. **Setup SSO**: In your Okta/Auth0 dev account, create a user with `victim@gmail.com`. Link this SSO to `AttackerOrg`.
4. **Login & Switch**: Log into `target.com` via your Okta as `victim@gmail.com`. Check if you can switch to `VictimOrg` in the UI.
5. **Prove Impact**: Access sensitive data (e.g., files, settings) or perform actions (e.g., invite others). Screenshot for report.
