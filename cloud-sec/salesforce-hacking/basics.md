# Basics

### **SAAS (Software as a Service):**

* A software delivery model where software is accessible via the web.
* The infrastructure and platform are managed by the vendor.

### **CRM (Customer Relationship Management):**

* Helps businesses maintain relationships with customers and suppliers.
* Example: An e-commerce company uses CRM to manage relationships with suppliers, track activities, and provide analytics.

### **Salesforce for CRM:**

* Offers SAAS applications that can be managed and customized via an admin panel.
* Minimal coding is required, utilizing Salesforce programming technologies such as:
  * **Lightning Component Framework**: A UI development framework similar to AngularJS or React.
  * **Apex**: Salesforce’s proprietary programming language with Java-like syntax.
  * **Visualforce**: A markup language for creating custom Salesforce pages, similar to HTML, often combined with Apex and JavaScript.

### **Differences from Traditional Web App Pen-Testing**

* **Web Application Aspect**: Traditional web app pen-testing skills still apply.
* **Software Aspect**: Separate access controls for managing data and users, accessible via the admin panel.
  * Misconfigurations can lead to Improper Authorization vulnerabilities and data leaks.

### **Salesforce Specific Vulnerability Exploitations**

1. **Improper Authorization**:
   * Misconfigured security controls can result in sensitive data leakage.
   * Requires understanding the format of Salesforce HTTP request parameters.
2. **SOQL Injection**:
   * SOQL (Salesforce's SQL query language) is limited to SELECT statements.
   * Directly injecting user input into SOQL queries can modify the query to pull more data than allowed.
   * Requires understanding SOQL query format and applying payloads.

### **Salesforce Terminologies**

* **Objects**: Tables for storing data.
  * **Standard Objects**: Pre-formatted tables provided by Salesforce.
  * **Custom Objects**: Tables created by an organization.
* **Fields**: Columns in the tables.
* **Records**: Rows in the tables.
* **Controllers**: Contain functions (Actions) that retrieve data from Objects.
  * **Standard Controllers**: Pre-formatted functions available to all Salesforce users.
  * **Custom Controllers**: Functions developed by an organization.
* **Guest User**: An unauthenticated user in Salesforce.

### **Understanding Salesforce HTTP Request**

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

* Key parameters in POST requests: `message`, `aura.context`, `aura.pageURI`, `aura.token`.

<figure><img src="../../.gitbook/assets/image (227).png" alt=""><figcaption></figcaption></figure>

* Focus on the `message` parameter, particularly the `descriptor` and `params` key-value pairs.

<figure><img src="../../.gitbook/assets/image (228).png" alt=""><figcaption></figcaption></figure>

### **Mapping Misconfigurations to Pen-Test**

* **Permissions Misconfigurations**:
  1. Over-permissive record permissions via the admin panel.
  2. Improper use of methods like `@RemoteAction` or `@AuraEnabled` in Apex, bypassing UI permissions.
* Pen-testing involves identifying objects and controllers and fuzzing them with the right parameters to retrieve records with misconfigured permissions.
* Retrieving records as a Guest User is considered critical.
