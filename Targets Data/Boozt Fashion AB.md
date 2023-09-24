---
tags:
  - target_data
---
## Scope 
```python
	- com.boozt.app
	- com.boozt.boozlet
	- com.boozt
	- com.boozlet
	- *.boozt.com
	- *.boozlet.com
	- analytics.boozt.com
```
### Subdomains
- boozlet.com 
```python
m.boozlet.com
store.boozlet.com
magento.boozlet.com
demo.boozlet.com
ww01.boozlet.com
shop.boozlet.com
cfshopeesg-a.boozlet.com
	test.boozlet.com
staging.boozlet.com
www.boozlet.com
ww7.boozlet.com
esm-p.usps.ssn.boozlet.com
boozlet.com
```
- boozt.com
```python
email.boozt.com
boozt.com
fpt.boozt.com
fb.boozt.com
analytics.boozt.com
mta.email.boozt.com
view.email.boozt.com
www.boozt.com
t.boozt.com
sp.boozt.com
nw.boozt.com
pub.email.boozt.com
rel.boozt.com
links.boozt.com
click.boozt.com
gcp.boozt.com
parcel-api.boozt.com
m.boozt.com
o1.sendgrid.boozt.com
drive.boozt.com
calendar.boozt.com
sp-dev.boozt.com
o2.ptr4956.boozt.com
www.parcel-api.boozt.com
sendgrid.boozt.com
groups.boozt.com
mail.boozt.com
transactional.boozt.com
delivery-time.boozt.com
mta2.email.boozt.com
image.email.boozt.com
click.email.boozt.com
```


### Hosts
- boozt.com
```python
https://boozt.com
https://gcp.boozt.com
https://www.parcel-api.boozt.com
https://click.boozt.com
https://analytics.boozt.com
https://click.email.boozt.com
https://pub.email.boozt.com
https://fpt.boozt.com
https://www.boozt.com
https://sendgrid.boozt.com
https://image.email.boozt.com
http://calendar.boozt.com
https://sp.boozt.com
https://m.boozt.com
https://nw.boozt.com
https://links.boozt.com
http://groups.boozt.com
https://sp-dev.boozt.com
https://parcel-api.boozt.com
https://delivery-time.boozt.com
https://rel.boozt.com
https://view.email.boozt.com
http://mail.boozt.com
http://fb.boozt.com
```




## JS Files Analysis
- Tokens:clientToken: 'pub2558ecc66883a79e7e8fd0c9a61259d9

## user1
```json
{"id":11402712,"delivery_firstname":null,"delivery_lastname":null,"delivery_company":null,"username":"mszttest1@gmail.com","billing_email":null,"delivery_housenr":null,"delivery_street":null,"delivery_city":null,"delivery_postcode":null,"delivery_country":null,"billing_phone":null,"billing_firstname":"tester2","billing_lastname":"tester","billing_company":null,"billing_housenr":null,"billing_street":null,"billing_city":null,"billing_postcode":null,"billing_country":null,"gender":null,"verified":false,"roles":["ROLE_TOKEN_USER"],"birthday":null,"children":[],"customer_club":null}
```

## user2
- lol

## Lack of password confirmation Leads to Full Account Takeover
#### steps to reproduce Full ATO 
1. Open a browser in which a user has previously logged into an account on public computer(say office or café) , but hasn't logged out.
2. Go to Change Email and enter attacker Gmail
3. attacker receives confirmation link 
4. with no password confirmation or( verification mail should be send on old email id registered ) 
5. attacker confirm the email change with the confirmation link he received 
6. now victim email became associated with attacker gmail but attacker doesnt know the password hah? 
7. no need to password as an attacker could then easily login with OAUTH to the victim account leads to full Account Takeover 
#### Impact
if some one left his account open on public computer(say office or cafe), then attacker can change the email ,verify it himself. Then abuse forgot password field to take over whole account.

Suggested mitigation: a password field can be applied (just like Facebook do) or verification mail should be send on old email id registered.

If you required any POC then Let me know.
#### References
- [Coursera | Report #292673 - No Password Verification on Changing Email Address Cause Account takeover | HackerOne](https://hackerone.com/reports/292673)
- [What is the Lack of Password Confirmation Change Email Address Vulnerability? (zofixer.com)](https://zofixer.com/what-is-the-lack-of-password-confirmation-change-email-address-vulnerability/)

## OAUTH Misconfiguration Leads To Pre-Account Takeover
### Steps To Reproduce
1. (Attacker Step) Navigate to the target application and register a new account using the **victim user’s email.** Since the application also has a Google Authentication option, I used a Gmail account for registration as a victim account.
2. Observe that the application successfully logs in a user upon registration process completion, and all the features of the applications are accessible.
3. Now, log out and navigate back to the target application’s login functionality.
4. (Victim Step) This time, use **Google Authentication** and login to the application using the same Email address that is used in **Step-1**
5. Observe that the login is successful and the victim user can access the application. Then, perform any changes in the application, such as profile update.
6. (Attacker Step) Now, In a separate browser window, attempt to log in using the `Email:Password` used for registration in `Step-1` 
7. Observe that the attacker is successfully logged in to the victim user’s account and can see all the changes that the victim performed.
### Impact
- Since there is no email confirmation, an attacker can easily create an account in the application using the Victim’s Email. This allows an attacker to gain pre-authentication to the victim’s account.
- Further, due to the lack of proper validation of email coming from Social Login and failing to check if an account already exists, the victim will not identify if an account is already existing. Hence, the attacker’s persistence will remain.
- An attacker would be able to see all the activities performed by the victim user impacting the confidentiality and attempt to modify/corrupt the data impacting the integrity and availability factor.
- This attack becomes more interesting when an attacker can register an account from an employee’s email address. Assuming the organization uses G-Suite, it is much more impactful to hijack into an employee’s account.
- The overall severity usually lies from High to Critical depending upon the data that is being stored.
### Remediation
- Ensuring that the social logins are correctly implemented, the email extracted from the social login is verified against the existing user’s database to ensure that the victim asked to reset the password. By doing so, it is possible to remove the attacker’s persistence.
### References
[HackerOne](https://hackerone.com/reports/1074047)
![[Pasted image 20230907045606.png]]