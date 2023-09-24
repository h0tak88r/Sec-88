Password Reset or Forgot Password are application functionalities which allow users to retrieve/reset the password of their account in case they have forgotten their password or believe that their password has been compromised.  
Applications implement different mechanisms for this purpose such as:

- Cookie Swap
    
    Password reset functionality which ask the user to provide an answer(s) to a security question(s) usually works based on the ‘sessionid’ cookie. This cookie is used to manage the complete password reset session for the user. Three steps of the process are:
    
    - The user provides the email address and a session cookie is set by the server.
    - The user is then presented with secret questions.
    - If correct answers are provided for the secret questions, the user can set a new password
    - In another browser instance initiating password reset for another user and making a note of the sessionid set for this password reset session.
    - Moving back to the previous instance (setting a new password for own account) and swapping own sessionid with the sessionid of another user (noted in the previous step).
    - The password is now set for another user and the attacker can login into that account.
    
- Token Abuse
    
    Assessing The Forget Password Functionality - Attack Scenarios:
    
    - Check if the token is predictable (cryptographically insecure)
    - Check if the token is one time use only
    - A few more tests (is it over SSL or HTTP etc)
    
    Check that you cannot use the token of one user to reset the password of another user. So you may try to generate a link: Password reset tokens:
    
    - [http://host/resetpass.php?email=user1@notsosecure.com&token=caea1f6](http://host/resetpass.php?email=user1@notsosecure.com&token=caea1f6)  
        1ee90a135d1bb1a0ddc37b115
    - [http://host/resetpass.php?email=user2@notsosecure.com&token=caea1f6](http://host/resetpass.php?email=user2@notsosecure.com&token=caea1f6)  
        1ee90a135d1bb1a0ddc37b115 (It only worked, if user2 has initiated password reset request)
    
- Other Fails
    
    - The password reset token does not expire after single usage. On a shared machine a user can go through the browser history and misuse the password reset link of other user(s).
    - Logical DoS: Lock out other users by sending password reset requests  
        for their account.
    - Predictable token or no-rate limiting allowing token brute-force.