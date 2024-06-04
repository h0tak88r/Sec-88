# Intents

## Intent Overview

An **Intent** is a messaging object used for communication between different components of an Android application. It serves three fundamental use cases:

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Hpw Intents Works</p></figcaption></figure>

1. **Starting an Activity:**
   * Represents a single screen in an app.
   * New instances are started by passing an Intent to `startActivity()`.
   * `startActivityForResult()` is used for receiving results from the activity.
2. **Starting a Service:**
   * A background component performing operations without a user interface.
   * Started using `startService()` for one-time operations.
   * `bindService()` is used for a client-server interface interaction.
3. **Delivering a Broadcast:**
   * A message that any app can receive.
   * System delivers broadcasts for various events.
   * Delivered using `sendBroadcast()` or `sendOrderedBroadcast()`.

### Intent Types

#### Explicit Intents

* Specify the exact component (activity or service) that will satisfy the intent.
* Uses a full `ComponentName` or Package Name to specify the target.
* Typically used for starting components within the same app.

```java
// Explicit Intent to start another activity within the same app
Intent explicitIntent = new Intent(CurrentActivity.this, TargetActivity.class);
explicitIntent.putExtra("key", "value"); // Optional: Adding extra data
startActivity(explicitIntent);
```

#### Implicit Intents

* Do not specify a specific component but declare a general action to perform.
* Allow components from other apps to handle the intent.
* Used when the exact component is unknown or when interacting with other apps.

```java
// Implicit Intent to open a webpage using a browser
String url = "https://www.example.com";
Intent implicitIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
startActivity(implicitIntent);
```

## Intent Components

1. **Name:**
   * **Definition:** The name of the component (activity, service) that the intent is targeting.
   * **Usage:** In explicit intents, specifies the exact component to be invoked.
2. **Action:**
   * **Definition:** Describes the requested action to be performed by the targeted component.
   * **Usage:** Specifies the type of operation, such as viewing, sending, or opening.
3. **Data:**
   * **Definition:** Represents the data to be operated upon by the targeted component.
   * **Usage:** Contains a URI or data type that helps define the context of the action.
4. **Category:**
   * **Definition:** Describes additional information about the kind of component that should handle the intent.
   * **Usage:** Categorizes the intent for better filtering by the system.
5. **Extras:**
   * **Definition:** Carries additional key-value pairs providing extended information.
   * **Usage:** Used for passing extra data between components, enhancing the intent's payload.

### Intent Filters

* **Definition:** Expressions in an app's manifest file specifying the type of intents a component would like to receive.
* **Use Cases:**
  * Declaring an intent filter for an activity allows other apps to directly start that activity.
  * Components without intent filters can only be started with explicit intents.

## Notes on Intent Filters and android:exported Attribute

* **android:exported Attribute:**
  * Set explicitly in each app component's `<intent-filter>` element.
  * Indicates the accessibility of the app component to other apps.
  * For activities with LAUNCHER category, set to true; otherwise, set to false for safety.
  * Warning: Android 12 or higher requires explicit setting; failure may result in app installation issues.
* **Elements:**
  * Specify the type of intents accepted within the `<intent-filter>` using three elements:
    * `<action>`: Declares the accepted intent action.
    * `<data>`: Declares the accepted data type, specifying URI aspects and MIME type.
    * `<category>`: Declares the accepted intent category.
* **Implicit Intents and CATEGORY\_DEFAULT:**
  * To receive implicit intents, include the CATEGORY\_DEFAULT category in the intent filter.
  * `startActivity()` and `startActivityForResult()` treat all intents as if they have CATEGORY\_DEFAULT.
  * Failure to declare this category results in no resolution for implicit intents.
* **Example:**
  *   Activity declaration with an intent filter to receive ACTION\_SEND intent with text MIME type:

      ```xml
      <activity android:name="ShareActivity" android:exported="false">
          <intent-filter>
              <action android:name="android.intent.action.SEND"/>
              <category android:name="android.intent.category.DEFAULT"/>
              <data android:mimeType="text/plain"/>
          </intent-filter>
      </activity>
      ```

Understanding intent filters, the `android:exported` attribute, and proper declaration is crucial for secure and effective communication between Android app components.
