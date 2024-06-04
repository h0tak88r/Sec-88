# Modifying Resource Files Leads to Privilege Escalation

* Fire up JADX and open up the `base.apk` file&#x20;
* Now you can see the source code and the apk data like the resources files
*   After searching for keywords like "admin" in the LoginActivity if ound this \


    <figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>
* this guy using a boolean value from resources to hide some functionalities
*   Go to `res/values/stings.xml` and notice "**is\_admin**" is equal to no

    <figure><img src="../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>
*   Now Using code editors like sublime change it to yes and save the project

    <figure><img src="../../.gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>
* Now Change the name of directory to&#x20;
*   Use APKTOOL  to build our updated version and use sign tool to sign the application

    ![](<../../.gitbook/assets/image (9) (1).png>)
* And that's it you just remove the old version from phone and install your updated version instead
* the signed apk will be `insecurebankv2.s.apk`&#x20;
* Notice Now there is a functionality for registration added&#x20;

<figure><img src="../../.gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>
