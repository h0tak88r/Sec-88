# JSON Request Testing

| Test Case Name                                         | JSON Credentials                                                                                                                        |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Basic credentials                                      | `{"login": "admin", "password": "admin"}`                                                                                               |
| Empty credentials                                      | `{"login": "", "password": ""}`                                                                                                         |
| Null values                                            | `{"login": null, "password": null}`                                                                                                     |
| Credentials as numbers                                 | `{"login": 123, "password": 456}`                                                                                                       |
| Credentials as boolean                                 | `{"login": true, "password": false}`                                                                                                    |
| Credentials as arrays                                  | `{"login": ["admin"], "password": ["password"]}`                                                                                        |
| Credentials as objects                                 | `{"login": {"username": "admin", "password": {"password": "password"}}}`                                                                |
| Special characters in credentials                      | `{"login": "@dm!n", "password": "p@ssw0rd#"}`                                                                                           |
| SQL Injection                                          | `{"login": "admin' --", "password": "password"}`                                                                                        |
| HTML tags in credentials                               | `{"login": "# admin", "password": "ololo-HTML-XSS"}`                                                                                    |
| Unicode in credentials                                 | `{"login": "\u0061\u0064\u006D\u0069\u006E", "password": "\u0070\u0061\u0073\u0073\u0077\u006F\u0072\u0064"}`                           |
| Credentials with escape characters                     | `{"login": "ad\\nmin", "password": "pa\\ssword"}`                                                                                       |
| Credentials with white space                           | `{"login": " ", "password": " "}`                                                                                                       |
| Overlong values                                        | `{"login": "a"*10000, "password": "b"*10000}`                                                                                           |
| Malformed JSON (missing brace)                         | `{"login": "admin", "password": "admin"}`                                                                                               |
| Malformed JSON (extra comma)                           | `{"login": "admin", "password": "admin"}`                                                                                               |
| Missing login key                                      | `{"password": "admin"}`                                                                                                                 |
| Missing password key                                   | `{"login": "admin"}`                                                                                                                    |
| Swapped key values                                     | `{"admin": "login", "password": "password"}`                                                                                            |
| Extra keys                                             | `{"login": "admin", "password": "admin", "extra": "extra"}`                                                                             |
| Missing colon                                          | `{"login" "admin", "password": "password"}`                                                                                             |
| Invalid Boolean as credentials                         | `{"login": yes, "password": no}`                                                                                                        |
| All keys, no values                                    | `{"": "", "": ""}`                                                                                                                      |
| Nested objects                                         | `{"login": {"innerLogin": "admin", "password": {"innerPassword": "password"}}}`                                                         |
| Case sensitivity testing                               | `{"LOGIN": "admin", "PASSWORD": "password"}`                                                                                            |
| Login as a number, password as a string                | `{"login": 1234, "password": "password"}`                                                                                               |
| Login as a string, password as a number                | `{"login": "admin", "password": 1234}`                                                                                                  |
| Repeated keys                                          | `{"login": "admin", "login": "user", "password": "password"}`                                                                           |
| Single quotes instead of double                        | `{'login': 'admin', 'password': 'password'}`                                                                                            |
| Login and password with only special characters        | `{"login": "@#$%^&*", "password": "!@#$%^&*"}`                                                                                          |
| Unicode escape sequence                                | `{"login": "\u0041\u0044\u004D\u0049\u004E", "password": "\u0050\u0041\u0053\u0053\u0057\u004F\u0052\u0044"}`                           |
| Value as object instead of string                      | `{"login": {"$oid": "507c7f79bcf86cd7994f6c0e"}, "password": "password"}`                                                               |
| Nonexistent variables as values                        | `{"login": undefined, "password": undefined}`                                                                                           |
| Extra nested objects                                   | `{"login": "admin", "password": "password", "extra": {"key1": "value1", "key2": "value2"}}`                                             |
| Hexadecimal values                                     | `{"login": "0x1234", "password": "0x5678"}`                                                                                             |
| Extra symbols after valid JSON                         | `{"login": "admin", "password": "password"}@@@@@@}`                                                                                     |
| Only keys, without values                              | `{"login":, "password":}`                                                                                                               |
| Insertion of control characters                        | `{"login": "ad\u0000min", "password": "pass\u0000word"}`                                                                                |
| Null characters in strings                             | `{"login": "admin\0" , "password": "password\0"}`                                                                                       |
| Exponential numbers as strings                         | `{"login": "1e5" , "password": "1e10"}`                                                                                                 |
| Hexadecimal numbers as strings                         | `{"login": "0xabc" , "password": "0x123"}`                                                                                              |
| Leading zeros in numeric strings                       | `{"login": "000123" , "password": "000456"}`                                                                                            |
| Multilingual input (here, English and Korean)          | `{"login": "adminê´€ë¦¬ìž" , "password": "passwordë¹ „ë°€ë²ˆí˜¸"}`                                                                      |
| Extremely long keys                                    | `{"a"*10000: "admin" , "b"*10000: "password"}`                                                                                          |
| Extremely long unicode strings                         | `{"login": "\u0061"*10000, "password": "\u0062"*10000}`                                                                                 |
| JSON strings with semicolon                            | `{"login": "admin;" , "password": "password;"}`                                                                                         |
| JSON strings with backticks                            | {"login": "`admin`" , "password": "`password`"}                                                                                         |
| JSON strings with plus sign                            | `{"login": "admin+" , "password": "password+"}`                                                                                         |
| JSON strings with equal sign                           | `z{"login": "admin=" , "password": "password="}`                                                                                        |
| Strings with Asterisk (\*) Symbol                      | `{"login": "admin*" , "password": "password*"}`                                                                                         |
| Long Unicode Strings                                   | `{"login": "\u0061"*10000, "password": "\u0061"*10000}`                                                                                 |
| Newline Characters in Strings                          | `{"login": "ad\nmin", "password": "pa\nssword"}`                                                                                        |
| Tab Characters in Strings                              | `{"login": "ad\tmin", "password": "pa\tssword"}`                                                                                        |
| Test with HTML content in Strings                      | `{"login": "**admin", "password": "password"}`                                                                                          |
| JSON Injection in Strings                              | `{"login": "{\"injection\":\"value\"}", "password": "password"}`                                                                        |
| Test with XML content in Strings                       | `{"login": "admin", "password": "password"}`                                                                                            |
| Combination of Number, Strings, and Special characters | `{"login": "ad123min!@", "password": "pa55w0rd!@"}`                                                                                     |
| Floating numbers as Strings                            | `{"login": "123.456", "password": "789.123"}`                                                                                           |
| Value as a combination of languages                    | `{"login": "adminà¤µà¥à¤à¤¸à¥à¤ ¥à¤¾à¤à¤", "password": "passwordà¤à¤¸à¤à¤à¤à¤à¤क"}`                                                    |
| Non-ASCII characters in Strings                        | `{"login": "âˆ†adminâˆ†", "password": "âˆ†passwordâˆ†"}`                                                                                |
| Single Character Keys and Values                       | `{"l": "a", "p": "p"}`                                                                                                                  |
| Use of environment variables                           | `{"login": "${USER}", "password": "${PASS}"}`                                                                                           |
| Backslashes in Strings                                 | `{"login": "ad\\min", "password": "pa\\ssword"}`                                                                                        |
| Long strings of special characters                     | `{"login": "!@#$%^&*()"*1000, "password": "!@#$%^&*()"*1000}`                                                                           |
| Empty Key in JSON                                      | `{"": "admin", "password": "password"}`                                                                                                 |
| JSON Injection in Key                                  | `{" {\"injection\":\"value\"} ": "admin", "password": "password"}`                                                                      |
| Quotation marks in strings                             | `{"login": "\"admin\"", "password": "\"password"}`                                                                                      |
| Credentials as nested arrays                           | `{"login": [["admin"]], "password": [["password"]]}`                                                                                    |
| Credentials as nested objects                          | `{"login": {"username": {"value": "admin", "password": {"password": {"value": "password"}`                                              |
| Keys as numbers                                        | `{123: "admin", 456: "password"}`                                                                                                       |
| Testing with greater than and less than signs          | `{"login": "admin>1" , "password": "<password"}`                                                                                        |
| Testing with parentheses in credentials                | `{"login": "(admin)" , "password": "(password)"}`                                                                                       |
| Credentials containing slashes                         | `{"login": "admin/user" , "password": "pass/word"}`                                                                                     |
| Credentials containing multiple data types             | `{"login": ["admin" , 123, true, null, {"username": ["admin"], "password": ["password" , 123, false, null, {"password": "password"]}}}` |
| Using escape sequences                                 | `{"login": "admin\\r\\n\\t" , "password": "password\\r\\n\\t"}`                                                                         |
| Using curly braces in strings                          | `{"login": "{admin}" , "password": "{password}"}`                                                                                       |
| Using square brackets in strings                       | `{"login": "[admin]" , "password": "[password]"}`                                                                                       |
| Strings with only special characters                   | `{"login": "!@#$$%^&*()" , "password": "!@#$$%^&*()"}`                                                                                  |
| Strings with control characters                        | `{"login": "admin\b\f\n\r\t\v\0" , "password": "password\b\f\n\r\t\v\0"}`                                                               |
| JSON containing JavaScript code                        | `{"login": "admin" , "password": "password"}`                                                                                           |
| Negative numbers as strings                            | `{"login": "-123", "password": "-456"}`                                                                                                 |
| Values as URLs                                         | `{"login": "https://admin.com", "password": "https://password.com"}`                                                                    |
| Strings with email format                              | `{"login": "admin@admin.com", "password": "password@password.com"}`                                                                     |
| Strings with IP address format                         | `{"login": "192.0.2.0", "password": "203.0.113.0"}`                                                                                     |
| Strings with date format                               | `{"login": "2023-08-03", "password": "2023-08-04"}`                                                                                     |
| JSON with exponential values                           | `{"login": 1e+30, "password": 1e+30}`                                                                                                   |
| JSON with negative exponential values                  | `{"login": -1e+30, "password": -1e+30}`                                                                                                 |
| Using Zero Width Space (U+200B) in strings             | `{"login": "adminâ€‹", "password": "passwordâ€‹"}`                                                                                      |
| Using Zero Width Joiner (U+200D) in strings            | `{"login": "adminâ€", "password": "passwordâ€"}`                                                                                        |
| JSON with extremely large numbers                      | `{"login": 12345678901234567890, "password": 12345678901234567890}`                                                                     |
| Strings with backspace characters                      | `{"login": "admin\b", "password": "password\b"}`                                                                                        |
| Test with emoji in strings                             | `{"login": "adminðŸ˜€", "password": "passwordðŸ˜€"}`                                                                                    |
| JSON with comments                                     | `{/*"login": "admin", "password": "password"*/}`                                                                                        |
| JSON with base64 encoded values                        | `{"login": "YWRtaW4=", "password": "cGFzc3dvcmQ="}`                                                                                     |
| Including null byte character                          | `{"login": "admin\0", "password": "password\0"}`                                                                                        |
| JSON with credentials in scientific notation           | `{"login": 1e100, "password": 1e100}`                                                                                                   |
| Strings with octal values                              | `{"login": "\141\144\155\151\156", "password": "\160\141\163\163\167\157\162\144"}`                                                     |
