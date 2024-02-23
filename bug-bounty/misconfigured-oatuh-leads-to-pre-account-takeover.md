# Misconfigured OATUH leads to Pre-Account Takeover

_**In the name of Allah, the most gracious and merciful,**_

Dear Security Researchers,

Today, I would like to share a fascinating discovery I made while examining the security of target.com.

During my Testing of the target.com platform, I noticed unusual change email feature that allows users to freely modify their registered email addresses to any email without confirmation from the other side (New email side).

Interestingly, the confirmation email pertaining to this change is dispatched to the old email address without any confirmation required from the new email address. This behavior struck me as rather unusual, prompting me to contemplate ways in which I could establish a backdoor or persist in controlling an account after changing its email to that of a potential victim.

I considered the possibility of maintaining access to the account even if the victim were to reset their password. I explored avenues such as associating my phone number with the account, creating a duplicate registration using a username, or exploiting OAuth misconfiguration.

My curiosity led me to wonder how target.com would respond if I connected via OAuth and subsequently altered the email ID to that of the victim’s email ID. Would this disconnect the OAuth connection or would it persistently link my Google OATUH to the Victim account? To my surprise, upon implementing this technique, I found that even when the victim changed their password or performed any other account-related activities, their account remained associated with my Google OATUH.

However, it’s worth noting that I could only change my email to an unregistered address, making this a pre-account takeover scenario. Attack Scenario:

1. The attacker establishes an account using OAuth Google authentication.
2. The attacker modifies the email associated with their account to an email address of their choice, ensuring it is not previously registered with the platform.
3. A confirmation link is sent to the old email address used in step 1 (attacker’s email).
4. The attacker validates the email change, linking it to the victim’s account.
5. The attacker attempts to authenticate using OAuth.
6. The platform mistakenly grants access to the victim’s account, allowing the attacker to take control.
7. Subsequently, no matter what actions the victim takes (changing their password or email), the attacker retains access to the account.
