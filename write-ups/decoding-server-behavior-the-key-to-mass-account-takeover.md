# Decoding Server Behavior: The Key to Mass Account Takeover

In my ongoing quest to uncover security vulnerabilities, I came across a critical flaw within the password reset functionality of a well-known platform. This flaw, if exploited, could enable a malicious actor to take over accounts en masse without any interaction from the users. What follows is a detailed journey through the discovery, exploration, and exploitation of this vulnerability.

### Sometimes It's Not That Direct: The Silent Signals of a Password Reset

The story begins with a routine password reset request for a test account, `0x88@wearehackerone.com`. I received a reset link in the following format:

```
https://target.com/auth/#/resetPassword/uczvfg
```

In this link, the verification code, `uczvfg`, is embedded directly in the URL. Curiosity piqued, I began by fuzzing the `verificationCode` parameter. I attempted to replace the code with random values and observed the server's response. Surprisingly, each request consistently returned a `200 OK` response, regardless of whether the code was valid or not.

This lack of feedback from the server caught my attention. Something wasn’t right here—the server wasn’t giving away any clues on the validity of the code, which presented a unique challenge.

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

### The Turning Point

Next, I followed the standard password reset flow to see if the network traffic might hold more insight. I clicked the password reset link, selected a new password, and carefully examined the API requests. During this process, I observed the following HTTP request:

```http
POST /ws/account/reset-password-commit HTTP/2
Host: target.com
Content-Type: application/json
Content-Length: 74

{
   "password":"NewPassword123",
   "verificationCode":"uczvfg",
   "recaptchaToken":"<recaptcha_token>"
}
```

This was the point where things got interesting. I decided to fuzz the `verificationCode` parameter within this API request itself. However, there was an obstacle—reCAPTCHA.

### The Challenge

Bypassing CAPTCHA is always a tricky endeavor. I attempted a range of techniques, from passing `null` values to omitting the CAPTCHA token entirely. Unfortunately, each of these attempts resulted in a `400 Bad Request`, indicating that the server required some form of CAPTCHA validation.

At this stage, I was focused on analyzing server responses with various CAPTCHA tokens to observe any behavioral changes. Despite several attempts, progress seemed stalled. However, an unusual discovery emerged when I set the `recaptchaToken` to the boolean value `true`. This configuration triggered distinct responses from the server, revealing different outcomes for valid versus invalid tokens when `captchaToken` was set to `true`. This inconsistency suggested a potential vulnerability and hinted at a deeper issue that could be exploited.

### The Discovery and Root Cause

<figure><img src="../.gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

Based on my analysis and this [research](https://www.youtube.com/watch?v=hWmXEAi9z5w) , the peculiar server behavior didn't definitively indicate the presence of a secondary context. However, the inconsistencies in the responses suggested that the request might be processed by multiple servers. I hypothesized that two separate servers were involved: one handling the CAPTCHA validation and the verification code validity and  the other completing the captcha token's value check (valid or not )  and handles changing user's passwords .

The first server seemed responsible for checking whether the CAPTCHA token was present and verifying the validity of the verification code or password reset token. When the token was invalid or missing, the response from this server was:

```http
HTTP/2 400 Bad Request
{"errorMessage":"Incorrect verification token."}
```

In contrast, when the CAPTCHA token exists and the reset password token is valid:

<pre class="language-json"><code class="lang-json"><strong>{"password":"Tester@88","verificationCode":"yurdox","recaptchaToken":true}
</strong></code></pre>

The request was forwarded to the second server for further processing the captcha token value and the takes the reset code and changing the password with the password provided in `"password"` . If  the CAPTCHA token was incorrect, the response from the second server was:

```http
HTTP/2 401 Unauthorized
Content-Type: application/json

{"errorMessage":{"code":"authorization.invalid_recaptcha","params":{}}}
```

Example code in first server&#x20;

```php
```

To further confirm this theory, I made malformed requests with arbitrary values in the `recaptchaToken` field:

*   **Example Requests:**

    ```json
    {"password":"NewPassword123","verificationCode":"adcdef","recaptchaToken":null}
    {"password":"NewPassword123","verificationCode":"uczvfg"}
    ```

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption><p>"recaptchaToken":null</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption><p>Empty captcha</p></figcaption></figure>

Each of these requests returned a `400 Bad Request` and CAPTCHA error, whether the token was valid or not, confirming that CAPTCHA existence validation. However, by setting the CAPTCHA token to any random value or `true`, the response was a `400 Bad Request` with a verification code error if the verification code  was invalid. If the verification code was valid, the request was passed to the second server, which validated the entire request to change the user's password and returned a CAPTCHA error with a different response body structure and status. This confirmed that another server was handling the request. See the example of its response below:

```http
HTTP/2 401 Unauthorized
Content-type: application/json

{"errorMessage":{"code":"authorization.invalid_recaptcha","params":{}}}
```

<figure><img src="../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption><p>captcha exist and the verification code is valid the secode nserver validated the value of the captcha and said it is nto valid</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption><p>Captcha true and valid code</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (9) (1).png" alt=""><figcaption><p>captcha true but invalid code</p></figcaption></figure>

### Exploitation: Cracking the Verification Code

With this newfound understanding, I began fuzzing the `verificationCode` parameter while keeping the `recaptchaToken` set to random values. Here’s where the server’s behavior worked in my favor:

* **400 Bad Request**: Indicated an invalid verification code.
* **401 Unauthorized**: Signaled a valid verification code but failed CAPTCHA validation.

Using these distinct response codes, I was able to efficiently brute-force valid verification codes. Once a valid code was identified, all that remained was to substitute it into the password reset process and manually provide a valid CAPTCHA, enabling me to reset the password for any account.

### The Impact: Mass Account Takeover

The implications of this vulnerability are severe. An attacker could initiate a password reset for their own account, fuzz the `verificationCode` to identify valid codes for other users, and then reset the passwords of those accounts and the target will  automatically log him in the account if there3 is no 2FA.

This vulnerability opens the door for mass account takeovers, leading to potentially catastrophic consequences for both users and the platform’s reputation.

### Conclusion: Closing the Security Gap

This critical flaw underscores the importance of robust security mechanisms, especially when handling sensitive processes like password resets. By addressing the underlying issues—implementing rate-limiting, improving CAPTCHA validation, and ensuring consistent error messages—the platform can mitigate the risk of such attacks in the future.
