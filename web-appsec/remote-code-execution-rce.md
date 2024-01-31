# Remote Code Execution (RCE)

* **Remote Code/Command Execution (RCE) Checklist**
  * Server Side Request Forgery (SSRF) to RCE:
    * [ ] if you found an SSRF try to escalate it to RCE by interacting with internal services, to do this you can craft a Gopher payload to interact with services like MySQL, you can use [Gopherus](https://github.com/tarunkant/Gopherus)
  * File Upload to RCE:
    * [ ] if you found an unrestricted file upload vulnerability try to upload a malicious file to get a reverse shell
  * Dependency Confusion Attack:
    * [ ] Search for packages that may be used internally by your target, then register a malicious public package with the same name, you can use [confused](https://github.com/visma-prodsec/confused) tool
  * Server Side Template Injection (SSTI) to RCE:
    * [ ] if you found and SSTI you can exploit it with [tplmap](https://github.com/epinna/tplmap) to get an RCE
  * SQL Injection To RCE:
    * [ ] if you found an SQL injection, you can craft a special query to write an arbitrary file on the system, [SQL Injection shell](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#shell)
  * Latex Injection To RCE:
    * [ ] if you found a web-based Latex Compiler, test If it is vulnerable to RCE, Latex to [command execution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection#command-execution)
  * Local File Inclusion (LFI) to RCE:
    * [ ] if you found an LFI try to escalate it to RCE via these [methods](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi-to-rce-via-procfd) and you can automate the process using [liffy](https://github.com/mzfr/liffy)
  * Insecure deserialization to RCE:
    * [ ] check if the application is vulnerable to Insecure deserialization
    * [ ] how to identify if the app is vulnerable:
    * [ ] check this [cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization\_Cheat\_Sheet.html)
    * [ ] [Java Deserialization Scanner](https://github.com/PortSwigger/java-deserialization-scanner) : a Burp Suite plugin to detect and exploit Java deserialization vulnerabilities
* **Top RCE reports from HackerOne:**
  1. [RCE on Steam Client via buffer overflow in Server Info](https://hackerone.com/reports/470520) to Valve - 1254 upvotes, $18000
  2. [Potential pre-auth RCE on Twitter VPN](https://hackerone.com/reports/591295) to Twitter - 1157 upvotes, $20160
  3. [RCE via npm misconfig -- installing internal libraries from the public registry](https://hackerone.com/reports/925585) to PayPal - 797 upvotes, $30000
  4. [H1514 Remote Code Execution on kitcrm using bulk customer update of Priority Products](https://hackerone.com/reports/422944) to Shopify - 791 upvotes, $15000
  5. [Remote Code Execution on www.semrush.com/my\_reports on Logo upload](https://hackerone.com/reports/403417) to Semrush - 788 upvotes, $10000
  6. [Git flag injection - local file overwrite to remote code execution](https://hackerone.com/reports/658013) to GitLab - 759 upvotes, $12000
  7. [RCE and Complete Server Takeover of](https://hackerone.com/reports/502758) [http://www.█████.starbucks.com.sg/](http://www.xn--4zhaaaa.starbucks.com.sg/) to Starbucks - 538 upvotes, $4000
  8. [Remote Code Execution in Slack desktop apps + bonus](https://hackerone.com/reports/783877) to Slack - 481 upvotes, $1750
  9. [RCE when removing metadata with ExifTool](https://hackerone.com/reports/1154542) to GitLab - 476 upvotes, $20000
  10. [SQL injection on contactws.contact-sys.com in TScenObject action ScenObjects leads to remote code execution](https://hackerone.com/reports/816254) to QIWI - 465 upvotes, $5500
  11. [RCE via unsafe inline Kramdown options when rendering certain Wiki pages](https://hackerone.com/reports/1125425) to GitLab - 408 upvotes, $20000
  12. [Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message](https://hackerone.com/reports/631956) to Valve - 407 upvotes, $9000
  13. [Remote code execution on Basecamp.com](https://hackerone.com/reports/365271) to Basecamp - 400 upvotes, $5000
  14. [Multiple bugs leads to RCE on TikTok for Android](https://hackerone.com/reports/1065500) to TikTok - 359 upvotes, $11214
  15. [RCE on shared.mail.ru due to "widget" plugin](https://hackerone.com/reports/518637) to [Mail.ru](http://mail.ru/) - 359 upvotes, $10000
  16. [RCE on build server via misconfigured pip install](https://hackerone.com/reports/946409) to Yelp - 346 upvotes, $15000
  17. [\[ RCE \] Through stopping the redirect in /admin/\* the attacker able to bypass Authentication And Upload Malicious File](https://hackerone.com/reports/683957) to [Mail.ru](http://mail.ru/) - 340 upvotes, $4000
  18. [RCE via npm misconfig -- installing internal libraries from the public registry](https://hackerone.com/reports/1007014) to Uber - 313 upvotes, $9000
  19. [RCE on TikTok Ads Portal](https://hackerone.com/reports/1024575) to TikTok - 301 upvotes, $12582
  20. [RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)](https://hackerone.com/reports/1609965) to GitLab - 243 upvotes, $33510
  21. [RCE via github import](https://hackerone.com/reports/1672388) to GitLab - 233 upvotes, $33510
  22. [Unchecked weapon id in WeaponList message parser on client leads to RCE](https://hackerone.com/reports/513154) to Valve - 226 upvotes, $3000
  23. [Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg](https://hackerone.com/reports/1027822) to Starbucks - 225 upvotes, $5600
  24. [RCE by command line argument injection to](https://hackerone.com/reports/212696) [`gm convert`](https://hackerone.com/reports/212696) [in](https://hackerone.com/reports/212696) [`/edit/process?a=crop`](https://hackerone.com/reports/212696) to Imgur - 223 upvotes, $5000
  25. [Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice](https://hackerone.com/reports/592400) to Starbucks - 217 upvotes, $4000
  26. [Unauthenticated SSRF in jira.tochka.com leading to RCE in confluence.bank24.int](https://hackerone.com/reports/713900) to QIWI - 217 upvotes, $1000
  27. [RCE using bash command injection on /system/images (toimitilat.lahitapiola.fi)](https://hackerone.com/reports/303061) to LocalTapiola - 207 upvotes, $6800
  28. [OOB reads in network message handlers leads to RCE](https://hackerone.com/reports/807772) to Valve - 205 upvotes, $7500
  29. [Debug Mode Leak Critical Information \[ AWS Keys , SMTP , Database , Django Secret Key ( RCE ) , Dodoc , Telegram , Twilio .. \]](https://hackerone.com/reports/1083543) to [Mail.ru](http://mail.ru/) - 203 upvotes, $7500
  30. [Test-scripts for postgis in mason-repository using unsafe unzip of content from unclaimed bucket creates potential RCE-issues](https://hackerone.com/reports/329689) to Mapbox - 200 upvotes, $12500
  31. [RCE on CS:GO client using unsanitized entity ID in EntityMsg message](https://hackerone.com/reports/584603) to Valve - 198 upvotes, $9000
  32. [Remote Code Execution on contactws.contact-sys.com via SQL injection in TCertObject operation "Delete"](https://hackerone.com/reports/816086) to QIWI - 193 upvotes, $1000
  33. [Git flag injection leading to file overwrite and potential remote code execution](https://hackerone.com/reports/653125) to GitLab - 168 upvotes, $3500
  34. [\[Portal 2\] Remote Code Execution via voice packets](https://hackerone.com/reports/733267) to Valve - 167 upvotes, $5000
  35. [RCE as Admin defeats WordPress hardening and file permissions](https://hackerone.com/reports/436928) to WordPress - 158 upvotes, $800
  36. [Path traversal, SSTI and RCE on a MailRu acquisition](https://hackerone.com/reports/536130) to [Mail.ru](http://mail.ru/) - 152 upvotes, $2000
  37. [Malformed .BSP Access Violation in CS:GO can lead to Remote Code Execution](https://hackerone.com/reports/351014) to Valve - 149 upvotes, $12500
  38. [MobileIron Unauthenticated RCE on mdm.qiwi.com with WAF bypass](https://hackerone.com/reports/983548) to QIWI - 147 upvotes, $3500
  39. [Path traversal, to RCE](https://hackerone.com/reports/733072) to GitLab - 136 upvotes, $12000
  40. [Remote Code Execution via Extract App Plugin](https://hackerone.com/reports/546753) to Nextcloud - 121 upvotes, $0
  41. [Remote Code Execution on Git.imgur-dev.com](https://hackerone.com/reports/206227) to Imgur - 117 upvotes, $2500
  42. [SQL injection on contactws.contact-sys.com in TRateObject.AddForOffice in USER\_ID parameter leads to remote code execution](https://hackerone.com/reports/816560) to QIWI - 117 upvotes, $1000
  43. [Possible RCE through Windows Custom Protocol on Windows client](https://hackerone.com/reports/1001255) to Nord Security - 117 upvotes, $500
  44. [Urgent: Server side template injection via Smarty template allows for RCE](https://hackerone.com/reports/164224) to Unikrn - 117 upvotes, $400
  45. [Apache Flink RCE via GET jar/plan API Endpoint](https://hackerone.com/reports/1418891) to Aiven Ltd - 112 upvotes, $6000
  46. [Read files on application server, leads to RCE](https://hackerone.com/reports/178152) to GitLab - 111 upvotes, $0
  47. [Remote Code Execution (Reverse Shell) - File Manager](https://hackerone.com/reports/768322) to Concrete CMS - 111 upvotes, $0
  48. [Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games](https://hackerone.com/reports/463286) to Valve - 107 upvotes, $7500
  49. [uber.com may RCE by Flask Jinja2 Template Injection](https://hackerone.com/reports/125980) to Uber - 96 upvotes, $10000
  50. [User-assisted RCE in Slack for macOS (from official site) due to improper quarantine meta-attribute handling for downloaded files](https://hackerone.com/reports/470637) to Slack - 94 upvotes, $750
  51. [Remote Code Execution in ██████](https://hackerone.com/reports/710864) to U.S. Dept Of Defense - 93 upvotes, $0
  52. [Tricking the "Create snippet" feature into displaying the wrong filetype can lead to RCE on Slack users](https://hackerone.com/reports/833080) to Slack - 92 upvotes, $1500
  53. [XXE in DoD website that may lead to RCE](https://hackerone.com/reports/227880) to U.S. Dept Of Defense - 89 upvotes, $0
  54. [Privilege Escalation via REST API to Administrator leads to RCE](https://hackerone.com/reports/1107282) to WordPress - 86 upvotes, $1125
  55. [Remote Unrestricted file Creation/Deletion and Possible RCE.](https://hackerone.com/reports/191884) to Twitter - 85 upvotes, $0
  56. [Remote Code Execution on contactws.contact-sys.com via SQL injection in TAktifBankObject.GetOrder in parameter DOC\_ID](https://hackerone.com/reports/1104120) to QIWI - 84 upvotes, $2500
  57. [Vanilla Forums AddonManager getSingleIndex Directory Traversal File Inclusion Remote Code Execution Vulnerability](https://hackerone.com/reports/411140) to Vanilla - 84 upvotes, $900
  58. [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/248116) to U.S. Dept Of Defense - 83 upvotes, $0
  59. [\[app-01.youdrive.club\] RCE in CI/CD via dependency confusion](https://hackerone.com/reports/1104693) to [Mail.ru](http://mail.ru/) - 82 upvotes, $3000
  60. [File writing by Directory traversal at actionpack-page\_caching and RCE by it](https://hackerone.com/reports/519220) to Ruby on Rails - 79 upvotes, $1000
  61. [Remote Code Execution on Proxy Service (as root)](https://hackerone.com/reports/401136) to ██████ - 79 upvotes, $0
  62. [Pre-auth Remote Code Execution on multiple Uber SSL VPN servers](https://hackerone.com/reports/540242) to Uber - 72 upvotes, $2000
  63. [Nextcloud Desktop Client RCE via malicious URI schemes](https://hackerone.com/reports/1078002) to Nextcloud - 72 upvotes, $1000
  64. [RCE on facebooksearch.algolia.com](https://hackerone.com/reports/134321) to Algolia - 72 upvotes, $500
  65. [Old WebKit HTML agent in Template Preview function has multiple known vulnerabilities leading to RCE](https://hackerone.com/reports/520717) to Lob - 68 upvotes, $1500
  66. [RCE, SQLi, IDOR, Auth Bypass and XSS at \[staff.███.edu.eg \]](https://hackerone.com/reports/404874) to ██████ - 68 upvotes, $0
  67. [RCE on █████ via CVE-2017-10271](https://hackerone.com/reports/576887) to U.S. Dept Of Defense - 68 upvotes, $0
  68. [GMP Deserialization Type Confusion Vulnerability \[MyBB <= 1.8.3 RCE Vulnerability\]](https://hackerone.com/reports/198734) to Internet Bug Bounty - 67 upvotes, $1500
  69. [Grafana RCE via SMTP server parameter injection](https://hackerone.com/reports/1200647) to Aiven Ltd - 66 upvotes, $5000
  70. [CS:GO Server -> Client RCE through OOB access in CSVCMsg\_SplitScreen + Info leak in HTTP download](https://hackerone.com/reports/1070835) to Valve - 61 upvotes, $7500
  71. [Remote Code Execution at](https://hackerone.com/reports/269066) [http://tw.corp.ubnt.com](http://tw.corp.ubnt.com/) to Ubiquiti Inc. - 61 upvotes, $5000
  72. [Remote Code Execution (upload)](https://hackerone.com/reports/116575) to Legal Robot - 59 upvotes, $120
  73. [\[Source Engine\] Material path truncation leads to Remote Code Execution](https://hackerone.com/reports/544096) to Valve - 58 upvotes, $2500
  74. [Store Development Resource Center was vulnerable to a Remote Code Execution - Unauthenticated Remote Command Injection (CVE-2019-0604)](https://hackerone.com/reports/536134) to Starbucks - 57 upvotes, $4000
  75. [Ability to access all user authentication tokens, leads to RCE](https://hackerone.com/reports/158330) to GitLab - 56 upvotes, $0
  76. [Remote Code Execution through DNN Cookie Deserialization](https://hackerone.com/reports/876708) to U.S. Dept Of Defense - 56 upvotes, $0
  77. [CVE-2022-40127: RCE in Apache Airflow <2.4.0 bash example](https://hackerone.com/reports/1776476) to Internet Bug Bounty - 54 upvotes, $4000
  78. [Remote Code Execution on contactws.contact-sys.com via SQL injection in TPrabhuObject.BeginOrder in parameter DOC\_ID](https://hackerone.com/reports/1104111) to QIWI - 52 upvotes, $2500
  79. [Remote code execution on rubygems.org](https://hackerone.com/reports/274990) to RubyGems - 49 upvotes, $1500
  80. [WordPress SOME bug in plupload.flash.swf leading to RCE](https://hackerone.com/reports/134738) to Automattic - 49 upvotes, $1337
  81. [LFI with potential to RCE on ██████ using CVE-2019-3396](https://hackerone.com/reports/538771) to U.S. Dept Of Defense - 49 upvotes, $0
  82. [Remote Code Execution (RCE) at "juid" parameter in /get\_zip.php (printshop.engelvoelkers.com)](https://hackerone.com/reports/914392) to Engel & Völkers Technology GmbH - 49 upvotes, $0
  83. [Java Deserialization RCE via JBoss on card.starbucks.in](https://hackerone.com/reports/221294) to Starbucks - 48 upvotes, $0
  84. [RCE in 'Copy as Node Request' BApp via code injection](https://hackerone.com/reports/1167530) to PortSwigger Web Security - 48 upvotes, $0
  85. [Remote Code Execution at](https://hackerone.com/reports/1379130) [https://169.38.86.185/](https://169.38.86.185/) (edst.ibm.com) to IBM - 48 upvotes, $0
  86. [Log4Shell: RCE 0-day exploit on █████████](https://hackerone.com/reports/1429014) to U.S. Dept Of Defense - 48 upvotes, $0
  87. [\[CS:GO\] Unchecked texture file name with TEXTUREFLAGS\_DEPTHRENDERTARGET can lead to Remote Code Execution](https://hackerone.com/reports/550625) to Valve - 47 upvotes, $2500
  88. [\[Kafka Connect\] \[JdbcSinkConnector\]\[HttpSinkConnector\] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia](https://hackerone.com/reports/1547877) to Aiven Ltd - 46 upvotes, $5000
  89. [RCE via WikiCloth markdown rendering if the](https://hackerone.com/reports/1401444) [`rubyluabridge`](https://hackerone.com/reports/1401444) [gem is installed](https://hackerone.com/reports/1401444) to GitLab - 46 upvotes, $3000
  90. [SMB SSRF in emblem editor exposes taketwo domain credentials, may lead to RCE](https://hackerone.com/reports/288353) to Rockstar Games - 46 upvotes, $1500
  91. [Remote Code Execution in Basecamp Windows Electron App](https://hackerone.com/reports/1016966) to Basecamp - 45 upvotes, $1250
  92. [\[3DS\]\[SSL\]\[SDK\] Unchecked number of audio channels in Mobiclip SDK leads to RCE in eShop movie player](https://hackerone.com/reports/897606) to Nintendo - 43 upvotes, $3200
  93. [RCE via Local File Read -> php unserialization-> XXE -> unpickling](https://hackerone.com/reports/415501) to h1-5411-CTF - 43 upvotes, $0
  94. [F5 BIG-IP TMUI RCE - CVE-2020-5902 (██.packet8.net)](https://hackerone.com/reports/1519841) to 8x8 - 42 upvotes, $0
  95. [RCE which may occur due to](https://hackerone.com/reports/473888) [`ActiveSupport::MessageVerifier`](https://hackerone.com/reports/473888) [or](https://hackerone.com/reports/473888) [`ActiveSupport::MessageEncryptor`](https://hackerone.com/reports/473888) [(especially Active storage)](https://hackerone.com/reports/473888) to Ruby on Rails - 41 upvotes, $1500
  96. [Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet on card.starbucks.in](https://hackerone.com/reports/153026) to Starbucks - 41 upvotes, $0
  97. [Remote Code Execution via Insecure Deserialization in Telerik UI](https://hackerone.com/reports/838196) to U.S. Dept Of Defense - 41 upvotes, $0
  98. [RCE due to ImageTragick v2](https://hackerone.com/reports/402362) to pixiv - 40 upvotes, $2000
  99. [CVE-2019-11043: a buffer underflow in fpm\_main.c can lead to RCE in php-fpm](https://hackerone.com/reports/722327) to Internet Bug Bounty - 40 upvotes, $1500
  100. [Log4j RCE on](https://hackerone.com/reports/1427589) [https://judge.me/reviews](https://judge.me/reviews) to [Judge.me](http://judge.me/) - 40 upvotes, $50
* \==**Remote Code Execution (RCE) Write\_ups**==
  * [Microsoft RCE bugbounty](https://blog.securitybreached.org/2020/03/31/microsoft-rce-bugbounty/)
  * [OTP bruteforce account takeover](https://medium.com/@ranjitsinghnit/otp-bruteforce-account-takeover-faaac3d712a8)
  * [Attacking helpdesk RCE chain on deskpro with bitdefender](https://blog.redforce.io/attacking-helpdesks-part-1-rce-chain-on-deskpro-with-bitdefender-as-case-study/)
  * [Remote image upload leads to RCE inject malicious code](https://medium.com/@asdqwedev/remote-image-upload-leads-to-rce-inject-malicious-code-to-php-gd-image-90e1e8b2aada)
  * [Finding a p1 in one minute with shodan.io RCE](https://medium.com/@sw33tlie/finding-a-p1-in-one-minute-with-shodan-io-rce-735e08123f52)
  * [From recon to optimizing RCE results simple story with one of the biggest ICT company](https://medium.com/bugbountywriteup/from-recon-to-optimizing-rce-results-simple-story-with-one-of-the-biggest-ict-company-in-the-ea710bca487a)
  * [Uploading backdoor for fun and profit RCE DB creds P1](https://medium.com/@mohdaltaf163/uploading-backdoor-for-fun-and-profit-rce-db-cred-p1-2cdaa00e2125)
  * [Responsible Disclosure breaking out of a sandboxed editor to perform RCE](https://jatindhankhar.in/blog/responsible-disclosure-breaking-out-of-a-sandboxed-editor-to-perform-rce/)
  * [Wordpress design flaw leads to woocommerce RCE](https://blog.ripstech.com/2018/wordpress-design-flaw-leads-to-woocommerce-rce/)
  * [Path traversal while uploading results in RCE](https://blog.harshjaiswal.com/path-traversal-while-uploading-results-in-rce)
  * [RCE jenkins instance](https://blog.securitybreached.org/2018/09/07/rce-jenkins-instance-dosomething-org-bug-bounty-poc/)
  * [Traversing the path to RCE](https://hawkinsecurity.com/2018/08/27/traversing-the-path-to-rce/)
  * [RCE due to showexceptions](https://sites.google.com/view/harshjaiswalblog/rce-due-to-showexceptions)
  * [Yahoo luminate RCE](https://sites.google.com/securifyinc.com/secblogs/yahoo-luminate-rce)
  * [Latex to RCE private bug bounty program](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
  * [How I got hall of fame in two fortune 500 companies an RCE story](https://medium.com/@emenalf/how-i-got-hall-of-fame-in-two-fortune-500-companies-an-rce-story-9c89cead81ff)
  * [RCE by uploading a web config](https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/)
  * [36k Google app engine RCE](https://sites.google.com/site/testsitehacking/-36k-google-app-engine-rce)
  * [How I found 2.9 RCE at yahoo](https://medium.com/@kedrisec/how-i-found-2-9-rce-at-yahoo-bug-bounty-program-20ab50dbfac7)
  * [Bypass firewall to get RCE](https://medium.com/@logicbomb\_1/bugbounty-how-i-was-able-to-bypass-firewall-to-get-rce-and-then-went-from-server-shell-to-get-783f71131b94)
  * [RCE in duolingos tinycards app from android](https://wwws.nightwatchcybersecurity.com/2018/01/04/rce-in-duolingos-tinycards-app-for-android-cve-2017-16905/)
  * [Unrestricted file upload to RCE](https://blog.securitybreached.org/2017/12/19/unrestricted-file-upload-to-rce-bug-bounty-poc/)
  * [Getting a RCE (CTF WAY)](https://medium.com/@uranium238/getting-a-rce-ctf-way-2fd612fb643f)
  * [RCE starwars](https://blog.zsec.uk/rce-starwars/)
  * [How I got 5500 from yahoo for RCE](https://medium.com/bugbountywriteup/how-i-got-5500-from-yahoo-for-rce-92fffb7145e6)
  * [RCE in Addthis](https://whitehatnepal.tumblr.com/post/149933960267/rce-in-addthis)
  * [Paypal RCE](https://artsploit.blogspot.com/2016/01/paypal-rce.html)
  * [My First RCE (Stressed Employee gets me 2x bounty)](https://medium.com/@abhishake100/my-first-rce-stressed-employee-gets-me-2x-bounty-c4879c277e37)
  * [Abusing ImageMagick to obtain RCE](https://strynx.org/imagemagick-rce/)
  * [How Snapdeal Kept their Users Data at Risk!](https://medium.com/@nanda\_kumar/bugbounty-how-snapdeal-indias-popular-e-commerce-website-kept-their-user-data-at-risk-3d02b4092d9c)
  * [RCE via ImageTragick](https://rezo.blog/hacking/2019/11/29/rce-via-imagetragick.html)
  * [How I Cracked 2FA with Simple Factor Brute-force!](https://medium.com/clouddevops/bugbounty-how-i-cracked-2fa-two-factor-authentication-with-simple-factor-brute-force-a1c0f3a2f1b4)
  * [Found RCE but got Duplicated](https://medium.com/@smilehackerofficial/how-i-found-rce-but-got-duplicated-ea7b8b010990)
  * [“Recon” helped Samsung protect their production repositories of SamsungTv, eCommerce eStores](https://blog.usejournal.com/how-recon-helped-samsung-protect-their-production-repositories-of-samsungtv-ecommerce-estores-4c51d6ec4fdd)
  * [IDOR to RCE](https://www.rahulr.in/2019/10/idor-to-rce.html?m=1)
  * [RCE on AEM instance without JAVA knowledge](https://medium.com/@byq/how-to-get-rce-on-aem-instance-without-java-knowledge-a995ceab0a83)
  * [RCE with Flask Jinja tempelate Injection](https://medium.com/@akshukatkar/rce-with-flask-jinja-template-injection-ea5d0201b870)
  * [Race Condition that could result to RCE](https://medium.com/bugbountywriteup/race-condition-that-could-result-to-rce-a-story-with-an-app-that-temporary-stored-an-uploaded-9a4065368ba3)
  * [Chaining Two 0-Days to Compromise An Uber Wordpress](https://www.rcesecurity.com/2019/09/H1-4420-From-Quiz-to-Admin-Chaining-Two-0-Days-to-Compromise-an-Uber-Wordpress/)
  * [Oculus Identity Verification bypass through Brute Force](https://medium.com/@karthiksoft007/oculus-identity-verification-bypass-through-brute-force-dbd0c0d3c37e)
  * [Used RCE as Root on marathon Instance](https://omespino.com/write-up-private-bug-bounty-usd-rce-as-root-on-marathon-instance/)
  * [Two easy RCE in Atlassian Products](https://medium.com/@valeriyshevchenko/two-easy-rce-in-atlassian-products-e8480eacdc7f)
  * [RCE in Ruby using mustache templates](https://rhys.io/post/rce-in-ruby-using-mustache-templates)
  * [About a Sucuri RCE…and How Not to Handle Bug Bounty Reports](https://www.rcesecurity.com/2019/06/about-a-sucuri-rce-and-how-not-to-handle-bug-bounty-reports/)
  * [Source code disclosure vulnerability](https://medium.com/@mohamedrserwah/source-code-disclose-vulnerability-b9e49584e2d2)
  * [Bypassing custom Token Authentication in a Mobile App](https://medium.com/@dortz/how-did-i-bypass-a-custom-brute-force-protection-and-why-that-solution-is-not-a-good-idea-4bec705004f9)
  * [Facebook’s Burglary Shopping List](https://www.7elements.co.uk/resources/blog/facebooks-burglary-shopping-list/)
  * [From SSRF To RCE in PDFReacter](https://medium.com/@armaanpathan/pdfreacter-ssrf-to-root-level-local-file-read-which-led-to-rce-eb460ffb3129)
  * [Apache strust RCE](https://www.mohamedharon.com/2019/04/apache-strust-rce.html)
  * [Dell KACE K1000 Remote Code Execution](https://www.rcesecurity.com/2019/04/dell-kace-k1000-remote-code-execution-the-story-of-bug-k1-18652/)
  * [Leaked Salesforce API access token at IKEA.com](https://medium.com/@jonathanbouman/leaked-salesforce-api-access-token-at-ikea-com-132eea3844e0)
  * [Zero Day RCE on Mozilla's AWS Network](https://blog.assetnote.io/bug-bounty/2019/03/19/rce-on-mozilla-zero-day-webpagetest/)
  * [Escalating SSRF to RCE](https://medium.com/cesppa/escalating-ssrf-to-rce-f28c482eb8b9)
  * [Fixed : Brute-force Instagram account’s passwords](https://medium.com/@addictrao20/fixed-brute-force-instagram-accounts-passwords-938471b6e9d4)
  * [Bug Bounty 101 — Always Check The Source Code](https://medium.com/@spazzyy/bug-bounty-101-always-check-the-source-code-1adaf3f59567)
  * [ASUS RCE vulnerability on rma.asus-europe.eu](https://mustafakemalcan.com/asus-rce-vulnerability-on-rma-asus-europe-eu/)
  * [Magento – RCE & Local File Read with low privilege admin rights](https://blog.scrt.ch/2019/01/24/magento-rce-local-file-read-with-low-privilege-admin-rights/)
  * [RCE in Nokia.com](https://medium.com/@sampanna/rce-in-nokia-com-59b308e4e882)
  * [Two RCE in SharePoint](https://soroush.secproject.com/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/)
  * [Token Brute-Force to Account Take-over to Privilege Escalation to Organization Take-Over](https://medium.com/bugbountywriteup/token-brute-force-to-account-take-over-to-privilege-escalation-to-organization-take-over-650d14c7ce7f)
  * [Github Desktop RCE](https://pwning.re/2018/12/04/github-desktop-rce/)
  * [eBay Source Code leak](https://slashcrypto.org/2018/11/28/eBay-source-code-leak/)
  * [Facebook source code disclosure in ads API](https://www.amolbaikar.com/facebook-source-code-disclosure-in-ads-api/)
  * \[XS-Searching Google’s bug tracker to find out vulnerable source code]\([https://medium.com/@luanherrera/xs-searching-googles-bug-tracker-to-find-out-vulnerable-source-](https://medium.com/@luanherrera/xs-searching-googles-bug-tracker-to-find-out-vulnerable-source-)
