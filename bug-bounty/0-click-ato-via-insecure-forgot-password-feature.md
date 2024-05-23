# 0-Click ATO via Insecure forgot password feature

Hello Hackers today i am gonna talk about my recent finding 0-Click Account Takeover on a bublick program on hackerone platoorm\
The identified vulnerability resides in the password reset mechanism. The flaw allows an attacker to manipulate the password reset URL parameters, specifically the `p_hash` and `p_sign` parameters, to access the password reset page without any further authentication. Here is a step-by-step explanation of how this vulnerability can be exploited:

\
In the first i was doing monitoring subdomains using my tool subfalcon [https://github.com/h0tak88r/subfalcon](https://github.com/h0tak88r/subfalcon) \
via this command&#x20;

```
subfalcon -l domains.txt -w "YOUR_DISCORD_WEBHOOK_URL" -m
```

I found this employee portal [ https://brandcentral.target.com/](https://brandcentral.ecobee.com/)

while exploring i was looking on the js file to search for some unauthenticated paths used this js code to extract the paths from the js files \


```javascript
javascript:(function(){var scripts=document.getElementsByTagName("script"),regex=/(?<=(\"|\%27|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\%60))/g;const results=new Set;for(var i=0;i<scripts.length;i++){var t=scripts[i].src;""!=t&&fetch(t).then(function(t){return t.text()}).then(function(t){var e=t.matchAll(regex);for(let r of e)results.add(r[0])}).catch(function(t){console.log("An error occurred: ",t)})}var pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const match of matches)results.add(match[0]);function writeResults(){results.forEach(function(t){document.write(t+"<br>")})}setTimeout(writeResults,3e3);})();
```

but found nothing \
so i found a very interesting feature called request user \


<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

So this feature primary do make new user and got email with the credentials i provided&#x20;

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

So the first thing i was thinking about is html injection on email and i got it found it is viulnerable to it&#x20;

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

So i continued exploration on the portal tried to login but i can't login with the credentials cauue mty user is not activated i need someone on the portal to aprove my request new user&#x20;

so i went to the forgot password feature to explore it&#x20;

when i enter my email i recieve link like this&#x20;

1. Enter the victim's email address (e.g., `0x88@wearehackerone.com`) in the provided field.
2.

    1.
       * Click on the "Forgot Password" link.
       * Enter the victim's email address (e.g., `0x88@wearehackerone.com`) in the provided field.
       * Submit the password reset request.
    2.

        1.
           *   Intercept the password reset email sent to the victim. This email contains the password reset token URL, which looks like this:

               ```perl
               perlCopy codehttps://brandcentral.ecobee.com/mars/reset.hash_reset?p_hash=B367AD4F&p_sign=4ixUHUGmhW6YZ6VyKCdzxoqAaaU%3D
               ```
        2. **Manipulate the Reset URL:**
           *   Fuzz the `p_hash` parameter while leaving the `p_sign` parameter empty:

               ```arduino
               arduinoCopy codehttps://brandcentral.ecobee.com/mars/reset.hash_reset?p_hash={FUZZ}&p_sign=
               ```
           * Through fuzzing, identify that the specific reset token `B367AD4F` is valid and leads to the password reset page.
        3. **Access the Password Reset Page:**
           *   Click on the manipulated URL containing the valid reset token:

               ```arduino
               arduinoCopy codehttps://brandcentral.ecobee.com/mars/reset.hash_reset?p_hash=B367AD4F&p_sign=
               ```
           * This URL grants access to the password reset page without requiring further authentication.
        4. **Set a New Password:**
           * On the password reset page, set a new password for the victim's account.
        5. **Log In:**
           * Use the newly set password to log in to the victim's account.

        \


    \
