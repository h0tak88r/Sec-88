# Pending Intents

#### Pending Intents from Pentester pov: [https://valsamaras.medium.com/pending-intents-a-pentesters-view-92f305960f03](https://valsamaras.medium.com/pending-intents-a-pentesters-view-92f305960f03)

<figure><img src="../../../.gitbook/assets/image (6) (1) (1) (1) (1) (1).png" alt=""><figcaption><p><a href="https://valsamaras.medium.com/pending-intents-a-pentesters-view-92f305960f03">https://valsamaras.medium.com/pending-intents-a-pentesters-view-92f305960f03</a></p></figcaption></figure>

**Using a PendingIntent**

* **Purpose:** A PendingIntent is a wrapper around an Intent, primarily granting permission to a foreign application to execute the contained Intent as if it were from the originating app's process.
* **Use Cases:**
  * Execute an intent when the user interacts with a Notification (handled by `NotificationManager`).
  * Execute an intent when the user interacts with an App Widget (executed by the Home screen app).
  * Schedule an intent to be executed at a specified future time (executed by the Android system's `AlarmManager`).
* **Considerations:**
  * Each PendingIntent corresponds to a specific type of app component (Activity, Service, or BroadcastReceiver).
  * When creating a PendingIntent, the respective creator method must be used:
    * `PendingIntent.getActivity()` for starting an Activity.
    * `PendingIntent.getService()` for starting a Service.
    * `PendingIntent.getBroadcast()` for starting a `BroadcastReceiver`.
  * It is essential to set the appropriate flags that specify the intent's usage.
* **Safety Measures:**
  * The PendingIntent's mutability can be controlled using flags like `FLAG_MUTABLE` or `FLAG_IMMUTABLE`.
  * Recommended to use `FLAG_IMMUTABLE` when creating a PendingIntent unless functionality relies on modifying the underlying intent.
* **Security Concerns:**
  * Pending Intents can be vulnerable to hijacking, especially when a malicious app gets hold of a pending intent.
  * Caution required when using PendingIntent in scenarios such as notifications, where other apps might interact with them.
  * Misconfigurations, like not explicitly setting target package and component, can lead to security risks.
* **Code Example:**
  *   Creating a PendingIntent:

      ```java
      Intent internalIntent = new Intent("My.Action");
      internalIntent.setClassName("application.a", "application.a.NonExportedActivity");
      internalIntent.putExtra("msg", "Secret Msg");
      PendingIntent pendingIntent = PendingIntent.getActivity(getApplicationContext(), 0, internalIntent, FLAG_IMMUTABLE);
      ```
* **References:**
  * Android Developers Page: [PendingIntent](https://developer.android.com/reference/android/app/PendingIntent)
  * Security Concerns: [Android Security - Pending Intent Vulnerabilities](https://developer.android.com/topic/security/risks/pending-intent#resources)
