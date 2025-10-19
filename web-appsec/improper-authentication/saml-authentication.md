# SAML Authentication

{% embed url="https://0xoverlord.medium.com/authentication-bypass-mis-scoped-saml-sessions-enable-user-impersonation-fd73ce7fbea0" %}

1. Sign into `target.com` as an organization owner (attacker).
2. Configure a SAML 2.0 Provider (Okta) on your attacker account by following SAML docs
3. Enable SAML authentication and Enable user provisioning
4. In your SAML IdP (Okta admin console), create/add a person with the victim email and set a password for that account.

Press enter or click to view image in full size

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*cEkbRV8VOvXw46eTGJK4_A.png" alt="" height="665" width="700"><figcaption></figcaption></figure>

5\. Also at Okta assign that newly created user to the Org application in Okta (so SAML assertions can be made).

* Okta assignments path :\
  `https://trial-#lol-admin.okta.com/admin/app/org/instance/<INSTANCE_ID>#tab-assignments`
* Add user `<victim@example.com>` to the org app.

Press enter or click to view image in full size

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*Yore9K23KYZgfvaztK756Q.png" alt="" height="644" width="700"><figcaption></figcaption></figure>

6\. Open an incognito/private browser window and navigate to your org’s SAML login URL (IdP-initiated) and sign-in with the victim email and the password you set in Okta:

* Email: [victim@example.com](mailto:victim@example.com)
* Password: (the password attacker set during creation)

7\. After successful IdP authentication, the SP ( `target.com`) issues a session.\
`As the attacker (exploit actions enabled by the victim session)`

8\. With the attacker-controlled session that now contains the victim user id (but attacker account id in token), issue requests that rely on user id for authorization (example: edit user settings).

\
