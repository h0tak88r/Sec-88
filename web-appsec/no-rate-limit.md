---
description: 'CWE-400: Uncontrolled Resource Consumption'
---

# No Rate Limit

* [ ] [Rate-Limit-Bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)
* [ ] add `%00` at the end of mail in intruder whenever error 429 comes Or `%2e`,`%0d` ,`%0a`
* [ ] add `X-Forwarded-For: 127.0.0.1`
* [ ] If rate limit is based on ip use ip rotator burp extention
* [ ] signupt form → catch post req for adding users → send to intruder → h0tak88r+1000@bugcrowdninja.com→ make more than 400 accs → report it
* [ ] [(21) Techniques For Bypassing Rate Limiting on OTP/2FA Endpoints | LinkedIn](https://www.linkedin.com/pulse/techniques-bypassing-rate-limiting-otp2fa-endpoints-aravind-s/)

**P4**

* [ ] Server Security Misconfiguration > No Rate Limiting on Form > Registration
* [ ] Server Security Misconfiguration > No Rate Limiting on Form > Login
* [ ] Server Security Misconfiguration > No Rate Limiting on Form > Email-Triggering
* [ ] Server Security Misconfiguration > No Rate Limiting on Form > SMS-Triggering **P5**
* [ ] Server Security Misconfiguration > No Rate Limiting on Form > Change Password
* [ ] Remove the `user-agent` header -> [https://medium.com/@mrxdevil404/how-i-bypassed-rate-limits-to-trigger-account-takeovers-sms-flooding-and-impersonation-9ed42ca1501](https://medium.com/@mrxdevil404/how-i-bypassed-rate-limits-to-trigger-account-takeovers-sms-flooding-and-impersonation-9ed42ca1501f)
* [ ] Modifying the phone number parameter on each request—effectively submitting unique numbers—the attacker bypassed rate-limiting -> [https://medium.com/@mrxdevil404/how-i-bypassed-rate-limits-to-trigger-account-takeovers-sms-flooding-and-impersonation-9ed42ca1501f](https://medium.com/@mrxdevil404/how-i-bypassed-rate-limits-to-trigger-account-takeovers-sms-flooding-and-impersonation-9ed42ca1501f)
