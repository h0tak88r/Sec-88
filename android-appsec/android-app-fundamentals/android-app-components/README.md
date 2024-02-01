# Android App Components

## App Components

App components are fundamental building blocks of an Android app, each providing an entry point for the system or user. These components, loosely coupled by the manifest file (`AndroidManifest.xml`), include:

1. **Activities**
2. **Services**
3. **Broadcast Receivers**
4. **Content Providers**

### 1. Activities

* Entry point for user interaction, representing a single screen with a UI (user interface).
* Independent instances work together to create a cohesive user experience.
* Key Interactions:
  * Tracking the user's on-screen focus.
  * Handling process interruptions.
  * Facilitating user flows between apps (e.g., sharing).

```java
public class MainActivity extends Activity {
}
```

### 2. Services

* Background component for long-running operations, running independently of UI.
* Can play music, fetch data, etc., while allowing other components to interact.
* Two Types: Started services (for background tasks) and Bound services (provides API for other processes).

```java
public class MyService extends Service {
}
```

### 3. Broadcast Receivers

* Responds to broadcast messages from other apps or the system.
* Handle Communications between Android OS and Applications.
* Handles system-wide events, even when the app is not running.
* Example: Handling alarms to post notifications.

```java
public class MyReceiver extends BroadcastReceiver {
   public void onReceive(Context context, Intent intent) {}
}
```

### 4. Android Local Storage

#### -> Shared Preferences

**Definition:** Shared Preferences provide a way to store small pieces of data as key-value pairs. They are often used for storing app settings, user preferences, and simple data that needs to persist between app sessions.

**Usage:**

* Lightweight data storage.
* Ideal for settings and preferences.
* Easily accessed across app sessions.

**Implementation:**

```java
// Writing to Shared Preferences
SharedPreferences preferences = getSharedPreferences("MyPrefs", MODE_PRIVATE);
SharedPreferences.Editor editor = preferences.edit();
editor.putString("username", "JohnDoe");
editor.apply();

// Reading from Shared Preferences
SharedPreferences preferences = getSharedPreferences("MyPrefs", MODE_PRIVATE);
String username = preferences.getString("username", "DefaultUsername");
```

#### -> Files

**Definition:** File-based storage is a versatile method for storing larger data sets, such as images, documents, or databases. It allows direct control over the file structure and is often used for offline data storage.

**Usage:**

* Storing large files and data sets.
* Offline data storage.
* Direct control over file structure.

**Implementation:**

```java
// Writing to File
String data = "Hello, World!";
File file = new File(context.getFilesDir(), "myfile.txt");
try (FileOutputStream fos = new FileOutputStream(file)) {
    fos.write(data.getBytes());
} catch (IOException e) {
    e.printStackTrace();
}

// Reading from File
File file = new File(context.getFilesDir(), "myfile.txt");
try (BufferedReader br = new BufferedReader(new FileReader(file))) {
    String line;
    while ((line = br.readLine()) != null) {
        // Process each line
    }
} catch (IOException e) {
    e.printStackTrace();
}
```

#### -> Content Providers

* Manages shared app data accessible by other apps (e.g., contacts).
* Provides a standardized method for data sharing.
* Implemented as a subclass of `ContentProvider`.

```java
public class MyContentProvider extends ContentProvider {
   public void onCreate() {}
}
```

### Additional Components

1. **Fragments:**
   * Represents a portion of the user interface within an Activity.
2. **Views:**
   * UI elements like buttons, lists, and forms.
3. **Layouts:**
   * View hierarchies controlling screen format and appearance.
4. **Intents:**
   * Messages facilitating communication between components.
5. **Resources:**
   * External elements (strings, constants, drawable pictures).
6. **Manifest:**
   * Configuration file for the application.

Understanding and utilizing these components is crucial for effective Android app development.
