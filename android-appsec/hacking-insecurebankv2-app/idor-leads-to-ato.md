# IDOR Leads to ATO

*   While Proxifying the trafiic with burp suite i Looked up some functions like change-password feature&#x20;

    <figure><img src="../../.gitbook/assets/image (203).png" alt=""><figcaption></figcaption></figure>
* I noticed the part that contains username but i cant edit the username on it&#x20;
* After sending acorrect request and the password successufully changed&#x20;

<figure><img src="../../.gitbook/assets/image (204).png" alt=""><figcaption></figcaption></figure>

*   In burp the request was sple api request with parameters username and newpassword\


    <figure><img src="../../.gitbook/assets/image (205).png" alt=""><figcaption></figcaption></figure>
*   So I Edited the username parameter to another username and it worked i changed other user's password\


    <figure><img src="../../.gitbook/assets/image (206).png" alt=""><figcaption></figcaption></figure>
