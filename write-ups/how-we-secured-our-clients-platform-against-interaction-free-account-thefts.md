# How We Secured Our Client’s Platform Against Interaction-Free Account Thefts

During a recent pentest engagement with [CyberAR LLC](https://cyberar.io/), we uncovered a critical security vulnerability in the OTP (One-Time Password) verification process of a popular web application. This vulnerability allowed us to bypass OTP verification, leading to a complete takeover of user accounts. Here's how it went down.

***

### **The Discovery**

Our target was a web application that implemented OTP-based authentication as an added layer of security. The user would enter their email, request an OTP, and then submit the received code to gain access to their account. It all seemed secure at first glance—until we dug deeper.

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

### **Initial Exploration**

The first thing we noticed was that the OTP mechanism didn't include any rate limiting. This was curious because, without proper rate limiting, an attacker could theoretically brute force the OTP. But we weren't just going to theorize—we needed to test it.

Using Burp Suite, we intercepted the OTP submission request. The request looked simple enough:

```http
POST /api/v1/signin/email/verify HTTP/1.1
Host: api.target.io
Content-Type: application/json

{"email":"victim@gmail.com","verificationCode":123456}
```

At this point, we set up Burp Suite's Intruder tool to brute force the OTP field.

### **Executing the Attack**

We configured the Intruder to iterate through possible OTP values. Since the OTP was six digits long. We figured that even with no rate limiting, the attack might take a while, but we were patient.

With the Intruder running, we monitored the responses. After several attempts, the server responded with an HTTP 200 status code. Bingo! We had guessed the correct OTP.

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

### **The Exploit: Account Takeover**

With the correct OTP in hand, we extracted the `OneTimeToken` from the server’s response. This token was the key to the kingdom.

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Next, we used the `OneTimeToken` in a follow-up request to the API:

```http
GET /api/v1/oneTimeAuth?oneTimeToken=VALID_TOKEN HTTP/1.1
Host: api.target.io
```

This request returned the full authorization token for the victim’s account, effectively logging us in as the user. From there, we had full control over the account—accessing personal data, modifying account settings, and more.

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

### **Lessons Learned**

This vulnerability highlighted several critical issues in the OTP verification process:

* **Lack of Rate Limiting:** Without rate limiting, brute-forcing the OTP was trivial.
* **Insecure OTP Mechanism:** The system should invalidate OTPs after a few incorrect attempts or after a short period.
* **Inadequate Monitoring:** The application lacked sufficient logging and monitoring, allowing such an attack to go undetected.

### **Recommendations**

* **Implement Rate Limiting:** Add rate limiting on OTP submissions to prevent brute force attacks.
* **Session Management:** Ensure OTPs expire after a set time or after a few failed attempts.
* **Enhanced Monitoring:** Log all failed OTP attempts and set up alerts for suspicious activity.

### **Conclusion**

This pentest engagement with [CyberAR LLC](https://cyberar.io/) served as a stark reminder of how seemingly minor oversights in security mechanisms like OTP can lead to severe consequences, such as full account takeovers. Always think critically about how each piece of the security puzzle fits together, and never underestimate the importance of comprehensive security testing.

Stay curious, stay secure, and happy hacking!
