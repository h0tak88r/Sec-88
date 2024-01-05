---
description: 'CWE-384: Session Fixation'
---

# Session Fixation

## Session Fixation Local Vector

### **Steps to reproduce**

1.  As the attacker go to `[https://wallet.sandbox.romit.io](https://wallet.sandbox.romit.io/)` (but do not login!) and check the cookies `romit.sandbox.session` and `SANDBOX-XSRF-TOKEN`, that are set. For example:

    ```
    SANDBOX-XSRF-TOKEN=AAG02cId-yyza3k8uhQR7JKuB-4YOmhizkjM; romit.sandbox.session=s%3AEHm0kA9uwWYHayOwdRQXbuZWEIRIliQZ.ndejz36ofa52c9ENnApLuaLkMnTYCot3IiY1qdTvz0w;
    ```

    1. Now simulate the victim by opening a second browser and setting those two cookies.
    2. As the victim, login in the second browser.
    3. As the attacker, go to `https://wallet.sandbox.romit.io` (using the first browser / same cookies as in step 1).
    4. You are now logged in to the victims account.

    #### Possible exploitation scenarios

    1. This can be exploited if there is another bug like HTTP Response Splitting on your website.
    2. But a far easier way is to exploit this on shared computers. For example in a library, as an attacker open https://wallet.sandbox.romit.io (but do not login!) and keep note of the cookies as above in step 1.
    3. Then simply go away and now when a victim will use the same computer and try to login, the attacker will have access to the victims account.

    #### Mitigation

    1. If you assign a new session when someone logs in, this flaw should be fixed.

*   **Method 2**

    1. open chrome and download edit this cookie ad-don
    2. now open [https://www.reddapi.com/](https://www.reddapi.com/) and log in
    3. now goto edit this cookie addon and click export all cookies ...by clicking this we get the cookie copied in clipboard..
    4. logout from your [https://www.reddapi.com/](https://www.reddapi.com/) account...
    5. if needed u can close and open your browser.
    6. now again go to [https://www.reddapi.com/](https://www.reddapi.com/) but dont login..just simply go to edit this cookie addon and click import a cookie and paste the code which we previously exported.
    7. after pasting just refresh the page and thats done you are now logged into your account without login details...

    #### problems faced

    the problems face if the vulnerability exits are

    1. anyone can easily hijack victims or users session and get into his account
    2. cookie stealing is the best way the hacker can get into and account..it would not take more than 5min to steal someones cookie using php n all...
    3. even friends can fool the victim and get him hacked..

    #### Solution

    Manage session properly.this problem is mainly faced because the session doesn't get expired or doesn't get closed when logout is pressed.each time the user logins the cookie must hold a unique different session id to proceed..

    facebook,google,any many more sites overtook this site....

## Session fixation remote vector

A session fixation attack is a type of web security vulnerability that occurs when an attacker sets or "fixates" the session identifier (usually a session cookie) of a victim user to a known value. The attacker typically does this before the victim logs into a web application. Once the victim logs in, the attacker can use the known session identifier to hijack the victim's session.

The "remote" aspect in "session fixation remote vector" refers to the fact that the attacker can perform this attack from a different location or device than the victim. In other words, the attacker doesn't need to be physically present on the victim's computer or network to carry out the attack.

Here's how a session fixation attack with a remote vector works:

1. **Attacker's Preparation**: The attacker visits the target web application and receives a session identifier (usually in the form of a session cookie) from the server.
2. **Session Identifier Fixation**: Instead of using the received session identifier for their own session, the attacker sends or provides this session identifier to the victim, often through social engineering, phishing, or by tricking the victim into clicking on a malicious link.
3. **Victim's Interaction**: The victim, unaware of the attack, logs into the web application using the session identifier provided by the attacker.
4. **Attacker's Access**: Since the attacker knows the session identifier, they can now access the victim's session, effectively hijacking it. This allows the attacker to perform actions on behalf of the victim, potentially compromising their account.

When a victim uses a known Session ID in a request to a vulnerable application, the attacker can use this vulnerability to make their own requests using the same Session ID – acting as if they were the rightful owner of the Session. This attack differs from Session Hijacking in that the attacker already has the Session ID and forces it on the victim, as opposed to the attacker finding the token through another vulnerability.

To protect against session fixation attacks, web applications should implement strong session management practices, including:

* **Session Regeneration**: Change the session identifier when a user logs in, ensuring that any previously known session identifier becomes invalid.
* **Timeouts**: Implement session timeouts to automatically log users out after a period of inactivity.
* **Secure Session Storage**: Ensure that session identifiers are stored securely and are not exposed in URLs or easily accessible to attackers.
* **Random Session Identifiers**: Use long and random session identifiers that are difficult for attackers to guess.
* **Secure Transmission**: Ensure that session identifiers are transmitted securely over HTTPS to prevent eavesdropping.
* Session IDs are not accepted as arguments in GET or POST requests.
* Allow users to log out and expire previous sessions.
* After logging in, update the Session ID.

There are several techniques to execute the attack; it depends on how the Web application deals with session tokens. Below are some of the most common techniques: **• Session token in the URL argument:** The Session ID is sent to the victim in a hyperlink and the victim accesses the site through the malicious URL. **• Session token in a hidden form field:** In this method, the victim must be tricked to authenticate in the target Web Server, using a login form developed for the attacker. The form could be hosted in the evil web server or directly in html formatted e-mail. **• Session ID in a cookie**

### Resources

* https://owasp.org/www-community/attacks/Session\_fixation
* https://zofixer.com/what-is-session-fixation-remote-attack-vector-vulnerability/#:\~:text=Session%20Fixation%20is%20a%20sort,a%20previously%20known%20Session%20ID.
* https://www.geeksforgeeks.org/session-fixation-attack/
* https://hackerone.com/reports/806577
