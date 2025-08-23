# Session Puzzling Attack

{% embed url="https://medium.com/@maheshlsingh8412/session-puzzling-attack-bypassing-authentication-29f4ff2fd4f5" %}

### What Is Session Puzzling Attack?

**Session Puzzling** (or **Session Variable Overloading**) is a web application security flaw that arises when a session variable is used for multiple, inconsistent purposes. This creates a logical vulnerability where attackers can hijack or bypass authentication flows.([owasp.org](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling?utm_source=chatgpt.com), [Medium](https://knnx.medium.com/what-is-a-session-puzzling-attack-7a50e48b9c25?utm_source=chatgpt.com))

For instance, one part of the application might set a session variable (like `userID`) during a password recovery process, and another part might rely on that same variable for authorizing access to sensitive sections—without verifying actual login. This mismatch allows attackers to bypass authentication by triggering these variables in the right order.([owasp.org](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling?utm_source=chatgpt.com), [appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com), [Medium](https://knnx.medium.com/what-is-a-session-puzzling-attack-7a50e48b9c25?utm_source=chatgpt.com))

***

### How It Works

1. **Session Variables**: These are values tied to a user’s session—like `username`, `authenticated`, etc.—used to preserve state across stateless HTTP requests.([Medium](https://medium.com/%40maheshlsingh8412/session-puzzling-attack-bypassing-authentication-29f4ff2fd4f5?utm_source=chatgpt.com), [appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com))
2. **Overloading Issue**: When the same variable is reused in different contexts (with different semantics), an attacker can manipulate the flow. For example, a password reset page sets `session['user'] = victimUsername`. Without proper checks, the attacker might later access `/myAccount`, which simply checks if `session['user']` is present—bypassing real login.([owasp.org](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling?utm_source=chatgpt.com), [appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com), [Medium](https://medium.com/%40maheshlsingh8412/session-puzzling-attack-bypassing-authentication-29f4ff2fd4f5?utm_source=chatgpt.com))
3. **Low Detectability**: Because the attacker is using legitimate application flows (e.g., password recovery), many security systems (like SIEM) don’t flag anything suspicious.([appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com), [Medium](https://knnx.medium.com/what-is-a-session-puzzling-attack-7a50e48b9c25?utm_source=chatgpt.com))
4. **2FA Bypass**: Invicti’s research shows session puzzling can even bypass two-factor authentication by manipulating session variables that should only be set post-authentication.([Invicti](https://www.invicti.com/blog/web-security/two-interesting-session-related-vulnerabilities/?utm_source=chatgpt.com))

***

### Why It’s Dangerous

* **Authentication bypass** — attackers can access protected areas without credentials.
* **Privilege escalation** — if the variable influences access levels.
* **Flow skipping** — skip steps in multi-step processes (like multi-factor auth).
* **Stealthy exploits** — they mimic normal user behavior, making detection difficult.([Medium](https://knnx.medium.com/what-is-a-session-puzzling-attack-7a50e48b9c25?utm_source=chatgpt.com), [appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com))

***

### Example Scenario

* **Step 1**: Attacker hits the password recovery page, entering a victim’s username.
* **Step 2**: The application sets `session['username'] = victimUsername` before emailing a reset link.
* **Step 3**: Without verifying actual login, the attacker navigates to their account page.
* **Step 4**: The page checks if `session['username']` exists—and displays data for the victim. Boom: access granted without credentials.([owasp.org](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling?utm_source=chatgpt.com), [appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com), [Medium](https://medium.com/%40maheshlsingh8412/session-puzzling-attack-bypassing-authentication-29f4ff2fd4f5?utm_source=chatgpt.com))

***

### Mitigation Strategies

1. **One Variable, One Purpose**
   * Never reuse session variables across distinct contexts. A variable set during recovery should not be trusted for authorization.([owasp.org](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling?utm_source=chatgpt.com), [appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com))
2. **Strict Initialization**
   * Always initialize variables with safe and clear default values (e.g., `authenticated = false`, `username = null`).([appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com))
3. **Separate Session Contexts**
   * Handle different user roles (e.g., admin vs end-user) in isolated session flows to minimize cross-impact.([appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com))
4. **Validate Sources**
   * Never allow user input to directly set session variables without validation.([appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com), [Invicti](https://www.invicti.com/blog/web-security/two-interesting-session-related-vulnerabilities/?utm_source=chatgpt.com))
5. **Secure Coding & Code Review**
   * Detecting such logic flaws is most effective via thorough code or design reviews rather than automated scanning.([owasp.org](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling?utm_source=chatgpt.com), [appcheck-ng.com](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/?utm_source=chatgpt.com))

***

### TL;DR Summary

* **What?** Session Puzzling = reusing session variables for different contexts, enabling bypass and privilege abuse.
* **Why care?** It's stealthy, powerful, and can undermine even robust authentication like 2FA.
* **Fix it by**: isolating session variables, validating, initializing properly, and reviewing code logic.
