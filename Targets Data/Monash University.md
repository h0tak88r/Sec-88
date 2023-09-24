---
tags:
  - target_data
---
- Scope: `*.monash.edu` |  
- Login Account Without Email Confirmation
- Unauthorized Password Reset via Session Management Vulnerability
- http://www.adm.monash.edu.au/bass/atem/
phantom
- https://users.monash.edu/~dprice/phantom/
- https://users.monash.edu/~dprice/phantom/nightly/logs/

Enpoints
- https://flair.monash.edu/research/collaboration.php
- https://flair.monash.edu/funding/index_old.php#
- https://gitlab.erc.monash.edu/api/v4/projects.json?search=&per_page=20&simple=true&order_by=similarity --> Projects Leaks
- https://gitlab.erc.monash.edu/api/v4/groups.json?search=&per_page=20&order_by=similarity   --> Groups Info Laaks
- https://gitlab-ci.erc.monash.edu/hpc-team/HPCasCode/-/blob/b0ca306976f653a00d7f2c313d68d191b7d20a8a/buildKaraage3.x.yml  --> internal Credentials Leaked 
- internal credentials -> https://github.com/davidhubbard/cwave/blob/bab04a2a8b266adff677e01a8a8a311edba755b0/tools/migrate.pl#L71
-  good subdomains
```python
    www.irt.monash.edu
    irt.monash.edu.au
    www.ctie.monash.edu.au
    eng-web81-v01.ocio.monash.edu
    www.ctieware.eng.monash.edu
    ctieware.eng.monash.edu
    ctie.monash.edu.au
    irt.monash.edu
    www.ecse.monash.edu
    www.ctieware.eng.monash.edu.au
    www.irrc.monash.edu
    ecse.monash.edu.au
    www.ctie.monash.edu
    ctie.monash.edu
    www.ecse.monash.edu.au
    eng-web81-v01.ocio.monash.edu.au
    www.irt.monash.edu.au
    www.irrc.monash.edu.au
    ctieware.eng.monash.edu.au
    ecse.monash.edu
    ezproxy.lib.monash.edu.au
    www.ezproxy.lib.monash.edu.au
    ezproxy.lib.monash.edu
    webfarm2.ocio.monash.edu.au
    www.ezproxy.lib.monash.edu
    retail.apps.monash.edu
    classtimetable.monash.edu
	aa-genoa-v02.ocio.monash.edu
	muppc01.ocio.monash.edu
	online-credits.monash.edu
	www.online-credits.monash.edu
	roombooking.monash.edu
	mutts.timetable.monash.edu
	web-print.monash.edu
	www.web-print.monash.edu
	classtimetable.monash.edu.au
	aa-genoa-v02.ocio.monash.edu.au
	roombooking.monash.edu.au
	mutts.timetable.monash.edu.au
```