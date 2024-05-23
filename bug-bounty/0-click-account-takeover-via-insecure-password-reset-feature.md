# 0-Click Account Takeover via Insecure Password Reset Feature

Hello Hackers! Today, I am excited to share my recent discovery of a 0-Click Account Takeover vulnerability on a public program on the HackerOne platform.

The vulnerability I found resides in the password reset mechanism. This flaw allows an attacker to manipulate the password reset URL parameters, specifically the `p_hash` and `p_sign` parameters, to access the password reset page without any further authentication. Here’s a step-by-step explanation of how this vulnerability can be exploited

1.  **Subdomain Monitoring**: I started by monitoring subdomains using my tool [subfalcon](https://github.com/h0tak88r/subfalcon) with the following command:

    ```bash
    subfalcon -l domains.txt -w "YOUR_DISCORD_WEBHOOK_URL" -m
    ```

    During this process, I found an employee portal at `https://brandcentral.target.com/`.\


    <figure><img src="../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>
2.  **Exploring JavaScript Files**: I examined the JavaScript files for unauthenticated paths using this script:

    ```javascript
    javascript:(function(){var scripts=document.getElementsByTagName("script"),regex=/(?<=(\"|\%27|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\%60))/g;const results=new Set;for(var i=0;i<scripts.length;i++){var t=scripts[i].src;""!=t&&fetch(t).then(function(t){return t.text()}).then(function(t){var e=t.matchAll(regex);for(let r of e)results.add(r[0])}).catch(function(t){console.log("An error occurred: ",t)})}var pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const match of matches)results.add(match[0]);function writeResults(){results.forEach(function(t){document.write(t+"<br>")})}setTimeout(writeResults,3e3);})();
    ```

    Unfortunately, I didn’t find anything significant with this method.
3.  **Discovering the Vulnerable Feature**: I then found an interesting feature called "request user," which allows the creation of a new user and sends an email with the credentials provided.\


    <figure><img src="../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>
4.  Initially, I thought of testing HTML injection in the email and found it was vulnerable. The portal was sending credentials via email, so an attacker could potentially steal the user's credentials using HTML injection. For instance, the attacker could use payloads like those found in [HackTricks' guide on Dangling Markup](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection). However, I didn’t fully explore this avenue because I received a quick response indicating the issue was a duplicate.

    <figure><img src="../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>
5.  **Exploring the Forgot Password Feature**: I tried to log in with the credentials but couldn’t because my user was not activated and needed approval from someone on the portal. So, I turned my attention to the "Forgot Password" feature.\


    <figure><img src="../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>
6. **Password Reset Process**:
   * Enter the victim's email address (e.g., 0x88@wearehackerone.com) in the provided field and submit the password reset request.
   *   Intercept the password reset email sent to the victim. This email contains the password reset token URL, which looks like this:

       ```perl
       https://brandcentral.ecobee.com/mars/reset.hash_reset?p_hash=B367AD4F&p_sign=4ixUHUGmhW6YZ6VyKCdzxoqAaaU%3D
       ```
   *   Manipulate the reset URL by fuzzing the `p_hash` parameter while leaving the `p_sign` parameter empty:

       ```arduino
       https://brandcentral.ecobee.com/mars/reset.hash_reset?p_hash={FUZZ}&p_sign=
       ```
   *   Through fuzzing, identify that the specific reset token `B367AD4F` is valid and leads to the password reset page.\


       <figure><img src="../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

*   Click on the manipulated URL containing the valid reset token:

    ```arduino
    https://brandcentral.ecobee.com/mars/reset.hash_reset?p_hash=B367AD4F&p_sign=
    ```
* This URL grants access to the password reset page without requiring further authentication.
* On the password reset page, set a new password for the victim's account.

<figure><img src="../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

* Use the newly set password to log in to the victim's account.\

* If credentials true you will receive this response \


<figure><img src="../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

* If credentials is not true you will get this response \


<figure><img src="../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>
