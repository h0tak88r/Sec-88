### API1: Broken Object Level Authorization  (BOLA)
==**Examples:**==
- Attacker authenticates as User A and then retrieves data on B, C, D...
- Attacker modifies accounts to perform transaction as another User
==**Description:**==
Most common and damaging API vulnerability. 
Involves manipulating IDs to impersonate other users and access data. 
Common issue because servers usually do not track client's state - relies on object IDs to determine authorization.
==**Risk Exposure:**==
Can lead to data loss, disclosure, data manipulation 
==Prevention==
Define data access policies and implement associated controls.
Ensure authenticated user is authorized to requested data.
Implement automated testing to identify BOLA vulnerabilities.
### API2:2023 Broken Authentication
![[Pasted image 20230911042848.png]]
### API3:2023 Broken Object Property Level Authorization
![[Pasted image 20230911043906.png]]
### API4:2023 Unrestricted Resource Consumption
![[Pasted image 20230911043940.png]]
### API5:2023 Broken Function Level Authorization
![[Pasted image 20230911050529.png]]
### API6:2023 Unrestricted Access to Sensitive Business Flows
![[Pasted image 20230911050653.png]]
### API6:2023 Unrestricted Access to Sensitive Business Flows
![[Pasted image 20230911050923.png]]
### API8:2023 Security Misconfiguration
![[Pasted image 20230911051006.png]]
### API9:2023 Improper Inventory Management
![[Pasted image 20230911051055.png]]
### API10:2023 Unsafe Consumption of APIs
![[Pasted image 20230911051140.png]]
# The 3 Pillars
![[Pasted image 20230911051524.png]]
![[Pasted image 20230911051639.png]]![[Pasted image 20230911051654.png]]
![[Pasted image 20230911051707.png]]
# Application Cybersecurity Landscape
![[Pasted image 20230911051844.png]]
