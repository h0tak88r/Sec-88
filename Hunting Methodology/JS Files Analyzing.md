---
tags:
  - web_hunting
---
- [Scripts/python scripts/JS_Leaks_spider.py](https://github.com/h0tak88r/Scripts/blob/main/python%20scripts/JS_Leaks_spider.py)
- Use This Extension to analyse JS Files [FindSomething - Chrome Web Store (google.com)](https://chrome.google.com/webstore/detail/findsomething/kfhniponecokdefffkpagipffdefeldb/related)
- [Can analyzing javascript files lead to remote code execution? | by Asem Eleraky | Medium](https://melotover.medium.com/can-analyzing-javascript-files-lead-to-remote-code-execution-f24112f1aa1f)

```bash
# Collect JS Files
katana -list scope.txt -jc | grep “\\.js$” | uniq | sort -u | tee JS.txt

# or use gau tool
cat subdomains.txt | gau |  grep “\\.js$” | uniq | sort -u | tee JS2.txt

# JS Beutifier 
<https://beautifier.io/>

# Analyzing JS files
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt

# Download all JS files 
file="js.txt"
while IFS= read -r link
do
    wget "$link"
done < "$file"

# Use This Regex to search for sensitive info 
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp|GTM-" *.js
```


