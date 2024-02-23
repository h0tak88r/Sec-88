# API BAC leads to PII Data Disclosure

> _**In the name of Allah, the Most Beneficent, the Most Merciful**_

Hello Ethical Hackers,

Today, I'd like to share a recent discovery - a vulnerability I reported to one of my target websites.

### The Story

As I explored the intricate workings of a web application, employing a meticulous function-based methodology, I stumbled upon an unusual anomaly within the email change feature. Rather than sending the confirmation link for the new email, it was sent to the old one. Initially, this peculiarity wasn't deemed a bug, but it piqued my curiosity. It led me to an ingenious idea: to link this account to Google OAuth. By doing so, I could sign in with Google, change the email to the victim's, and have the confirmation link sent to my old email. This allowed me to avoid relying on the victim's actions. After changing the email to the victim's, I attempted to sign in using OAuth Google, successfully taking over the victim's account. More details are available [here](https://h0tak88r.github.io/posts/OAuth-Misconfiguration-Exploitation-Leading-to-Pre-Account-Takeover-\(ATO\)/).

As I delved deeper, I realized that this email change misconfiguration could lead to various vulnerabilities. During my evaluation of the newsletter feature, I subscribed and changed my email to the victim's using the same method, bypassing the need for validation from the victim. Since the confirmation email was still being sent to the old email address, I continued my exploration. After the victim signed into their email and made changes, including adding payment information and making purchases, I found an 'unsubscribe' button in the old email's ads and newsletters. This button contained a link with a JWT (JSON Web Token). Everything seemed normal until I scrutinized the backend requests, revealing that the request `/v7/customers/notification-preferences` was leaking customer details:

```json
{
  "customer": {
    "id": 35173273,
    "facebook_id": 0,
    "first_name": "Babe",
    "last_name": "-",
    "email": "victim88000@gmail.com",
    "is_vip": false,
    ...
    (Other customer details)
    ...
  }
}
```

This was undoubtedly a security flaw. I reported it as a potential issue, possibly a P4/P3, and decided to take a break.

Here's a high-level scenario of how this vulnerability can be exploited:

1. Create an account.
2. Change the email to the victim's email.
3. Wait for the victim to update their information.
4. Send an API request vulnerable to exclusive data disclosure.

The next day, with a fresh perspective, I decided to give this bug another attempt, aiming to elevate its impact. I used the JWT found in the unsubscribe link from the old email and integrated it into a Burp extension called Auth-Analyzer. By reverse-engineering and collecting all the API requests and calls, I discovered that I could impersonate the victim in critical actions, such as:

* `GET /v8/cart` (View the victim's cart).
* `POST /v8/carts/items` (Add items to the victim's cart).
* `GET /wishlist` (View the victim's favorites).
* `GET /v8/payment_methods` (Retrieve payment methods for the victim).
* `GET /v7/customers/details` (Access all customer details). Though I attempted to carry out critical actions like changing passwords or emails that could lead to account takeover, I wasn't successful. Nevertheless, this exposed an authorization bug, enabling an old email session to access the account and payment details, even making purchases while impersonating the victim.

Here's the workflow:

1. An attacker creates an account (attacker@gmail.com).
2. The attacker requests to change the email address to the victim's (victim@gmail.com).
3. The confirmation link is sent to the attacker's email, not the victim's.
4. The attacker confirms the change to the victim's email address.
5. The victim logs in successfully, makes changes to their account, including payment details and shipping information.
6. The attacker clicks on any ads sent to the victim's email.
7. The attacker observes the traffic through the web.
8. The attacker intercepts the response for the unsubscribe action and sends it to repeater.
9. The attacker edits the path to `GET /v7/customers/details` or copies the JWT and uses it with another test account, making a request for `GET /v7/customers/details` while intercepting the request. The attacker replaces their JWT with the one obtained from the unsubscribe session, gaining access to the victim's details.
10. Now the attacker can access all customer (victim) details, including personally identifiable information (PII).

This vulnerability unveils numerous security risks. I'm eager to see how this issue will be addressed.

In conclusion, this experience highlights the significance of not only identifying unusual behavior in features but also proactively seeking workarounds that may turn them into vulnerabilities. It's fascinating how initially observing the abnormal behavior of the email change feature eventually revealed a cluster of security flaws. So, the next time you encounter an anomaly, remember that it might be hiding doors that, when opened, reveal new insights and enhance the security of the systems we interact with. Happy hacking, and stay curious!
