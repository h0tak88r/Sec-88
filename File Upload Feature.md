---
tags:
---
- Cheat-Sheet
    
    ```python
    -----------------------------------------------------------------
    upload.random123		   ---	To test if random file extensions can be uploaded.
    upload.php			       ---	try to upload a simple php file.
    upload.php.jpeg 		   --- 	To bypass the blacklist.
    upload.jpg.php 		     ---	To bypass the blacklist. 
    upload.php 			       ---	and Then Change the content type of the file to image or jpeg.
    upload.php*			       ---	version - 1 2 3 4 5 6 7.
    upload.PHP			       ---	To bypass The BlackList.
    upload.PhP			       ---	To bypass The BlackList.
    upload.pHp			       ---	To bypass The BlackList.
    upload.htaccess 		   --- 	By uploading this [jpg,png] files can be executed as php with milicious code within it.
    pixelFlood.jpg			   ---	To test againt the DOS.
    frameflood.gif			   ---	upload gif file with 10^10 Frames
    Malicious zTXT  		   --- 	upload UBER.jpg 
    Upload zip file			   ---	test againts Zip slip (only when file upload supports zip file)
    Check Overwrite Issue	 --- 	Upload file.txt and file.txt with different content and check if 2nd file.txt overwrites 1st file
    SVG to XSS			       ---	Check if you can upload SVG files and can turn them to cause XSS on the target app
    SQLi Via File upload	 ---	Try uploading `sleep(10)-- -.jpg` as file
    ----------------------------------------------------------------------
    ```
    
- Test Cases
    
    - [Burp File Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa)
        
    - **IDOR from File upload**
        1. upload a normal profile photo 
        2. right click and open the photo in new window 
        3. recognize paramter or any part of url that responsiple for identifying the user of photo 
        4. change it and see other's  photos
    - [EXIF_Geo_Data_Not_Stripped/exif](https://github.com/KathanP19/HowToHunt/blob/master/EXIF_Geo_Data_Not_Stripped/exif_geo.md)
        
    - [**File-Upload**](https://www.notion.so/File-Upload-e81963aa546a4ae29dc4eb4d4972c60d?pvs=21)
        
    - **[XSS Stored via Upload avatar PNG](https://hackerone.com/reports/964550)**
        
    - [Stored XSS on upload SVG files leads to ATO](https://hackerone.com/reports/765679)
	    - [XSS SVG - Ghostlulz](https://ghostlulz.com/xss-svg/)
    - [XXE ON JPEG](https://hackerone.com/reports/836877)
        
    - [SQL Injection - The File Upload Playground](https://shahjerry33.medium.com/sql-injection-the-file-upload-playground-6580b089d013)
        
    - [ZIP TO XXE](https://hackerone.com/reports/105434)
        
    - **[RFI in upload](https://hackerone.com/reports/14092)**
        
    - **[SSRF and Local File Read via video upload](https://hackerone.com/reports/1062888)**
        

        
    - **Token Hijacking Attack**
        
        ### Attack Scenario:
        
        • The application allows users to link self-hosted images in profile and the session token is being sent in URL. 
        • The attacker links an image in his account which is hosted on a self-owned system. 
        • When other users open the page to view this photo, a request is made to the attacker owned system, with session token in URL. 
        • The attacker logs these tokens and uses them to access accounts of other users.
        
    - **Create A picture that steals Data**
        
        - Focusing on image upload features.
        - Creating image links with IP logger.
        - Creating IP traps on malicious Web Server.
        - Boom ! receive IP’s of all the people who view the image.
        
        ```python
        Go to <https://iplogger.org/>
        choose invisible image 
        send the url to the victim
        ```
        
      