# IDN Homograph Attack

### What is an IDN Homograph Attack?

**IDN** stands for **Internationalized Domain Name**. These are domain names that include characters from various languages and scripts, not just the ASCII characters (a-z, 0-9) traditionally used in domain names.

A **homograph** refers to characters that look alike but are different. Technically, the term **homoglyph** is more accurate because it denotes characters that look similar across different scripts.

### How Does an IDN Homograph Attack Work?

An IDN homograph attack exploits the visual similarity between characters from different scripts to deceive users about the true nature of a domain name.

#### Example of Homographs

* **Latin "a"** (U+0061)
* **Cyrillic "а"** (U+0430)

These two characters look almost identical but are different from a computer’s perspective.

### Script Spoofing

Also known as script spoofing, this attack involves using characters from different scripts to create deceptive domain names. Unicode, the character encoding standard, includes characters from many writing systems. Some characters look similar but have different codes and meanings. For example:

* Greek Ο (U+039F)
* Latin O (U+004F)
* Cyrillic О (U+041E)

| IDN                   | Unicode        | Legitimate match |
| --------------------- | -------------- | ---------------- |
| xn--alixpress-d4a.com | aliéxpress.com | aliexpress.com   |
| xn--go0gl-3we.fm      | go0glе.fm      | google.com       |
| xn--mazon-wqa.com     | ámazon.com     | amazon.com       |

### Checklist

* [ ] OAuth `redirect_uri` bypass using IDN homograph attack&#x20;

{% embed url="https://hackerone.com/reports/861940" %}

* [ ] Bypass Redirection Filters&#x20;

{% embed url="https://hackerone.com/reports/271324" %}

* [ ] Steal Victim's Reset Password Tokens&#x20;

```go
1. Open the burp collaborator client > Generate Collaborator payload .
2. Go to the sign up page of target.com and create a new account with email- abc@gmail.com.burpcollaboratorpayloadhere
3. Now if the target.com has email confirmation > you will receive the email confirmation link in burp collaborator client > verify the email.
4. Go to password reset page of target.com > enter email as abc@gmáil.com.burpcollaboratorpayloadhere
5. If the target.com is vulnerable then it will send password reset link to the mail- abc@xn — gmil-6na.com.burpcollaboratorpayloadhere and you will receive password reset link in burp collaborator client. Make sure to check in burp collaborator client -received email details: To- abc@xn — gmil-6na.com.burpcollaboratorpayloadhere.
6. Now you can change the password and access the victim’s account.
```

{% embed url="https://infosecwriteups.com/how-i-was-able-to-change-victims-password-using-idn-homograph-attack-587111843aff" %}

* [ ] Password Reset Link Poisoning (Host Injection)

{% embed url="https://shahjerry33.medium.com/idn-homograph-attack-reborn-of-the-rare-case-99fa1e342352" %}

* [ ] &#x20;File Names Attacks
* [ ] Usernames Attavk
* [ ] Account Overwrite in email change function

```
Change Email to vctim's email but with idn homograph attack 
Victim's Email: victim@gmail.com
Attacker's Email: victim@gmáil.com
```

### Tools

{% embed url="https://github.com/evilsocket/ditto" %}

{% embed url="https://0xacb.com/normalization_table" %}

{% embed url="https://github.com/JesseClarkND/abnormalizer" %}

{% embed url="https://www.irongeek.com/homoglyph-attack-generator.php" %}



### Another Resources

{% embed url="https://shahjerry33.medium.com/idn-homograph-attack-and-response-manipulation-the-rarest-case-85f64c272a1c" %}

{% embed url="https://www.paubox.com/blog/homograph-attack-what-is-it-and-how-to-avoid-it" %}

{% embed url="https://honey-march-a14.notion.site/IDN-Homograph-38450662f8dc427cbf67c52f639f65ae" %}
