---
tags:
  - target_data
---
1. Leaked 
(https://js.stripe.com/v3/ "https://js.stripe.com/v3/")apiKey:"AIzaSyCab6eIMNih34mQb3XI_QWXagmF2_rvQAg"

## Account Takeover For unsigned users

###  Attack Scenario

1. The attacker creates an account using OAuth Google authentication.
2. The attacker changes the email associated with their account to an email address of their choice. This email should not be previously registered with the platform.
3. A confirmation link is sent to the old email address used in step 1, (attacker's email )
4. The attacker confirms the email change to Victim's account
5. The attacker attempts to authenticate using OAuth.
6. The platform erroneously grants access to the victim's account, allowing the attacker to take control.

### Steps to Reproduce

1. Create an account using OAuth Google authentication.
2. Change the email associated with your account to an email address that is not registered on the platform.
3. Confirm the email change using the confirmation link sent to your old email( that was used in step 1).
4. Attempt to authenticate using OAuth.
5. Observe that you gain access to the victim's account, even after the email change.

Now victim whatever he does you can access his account using OAuth


## Improper Session Management
- Broken Authentication and Session Management > Failure to Invalidate Session > On Password Reset and/or Change
### Steps to Reproduce

1. Open Account in Browser A
2. Victim in Browser B Requesting Reset Password link
3. Victim uses the link to reset password and successfully login
4. Attacker Still Can use The Account in the Browser A

---

### Impact

Account Takeover: This vulnerability could allow an attacker to take over a user's account without their knowledge or consent. By exploiting the failure to invalidate the session after a password reset, an attacker may gain unauthorized access to the victim's account.

Data Access: Once the attacker gains control of the victim's account, they may have access to sensitive personal information, such as email addresses, contact details, or stored data within the account. Depending on the platform, this could include financial information, private messages, or personal files.

Impersonation: An attacker could impersonate the legitimate user, potentially engaging in malicious activities on their behalf. This might include sending fraudulent messages, making unauthorized transactions, or changing account settings.

Data Loss or Manipulation: Depending on the nature of the account, an attacker could delete, manipulate, or steal data stored within it. This could have serious consequences, particularly for users who rely on the affected platform for business or personal use.

Reputation Damage: If the attacker engages in harmful or malicious activities while using the compromised account, it could harm the reputation of the legitimate user or the platform itself. For example, sending phishing emails from a compromised email account can damage trust in the platform.



- CPanel -> http://104.16.137.94:2083/