### **MITMweb Certificate Setup**

Now we will also import the cert for MITMweb through a very similar process.

1. Stop burpsuite (it's listening on 8080 and mitmweb needs that to work)
2. Start mitmweb from the terminal:  
    $mitmweb
3. Use FoxyProxy in Firefox to send traffic to the BurpSuite proxy (8080).
4. Using Firefox Visit mitm.it.  
    ![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/2tR5PEZbQLU0Oh8rNK7E_cert101.PNG)
5. Download the mitmproxy-ca-cert.pem for Firefox. 
6. Return to the Firefox certificates (see Burp Suite Certificate instructions).  
    ![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/94VQmADbSqCAZbaz2zKT_Capturecert2.PNG)
7. Import the MITMweb (mitmproxy-ca-cert.pem) certificate.  
    ![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/mEXrG0xJSQeDsjpAWqR5_Capturecert4.PNG)

### **Install Postman**

$ sudo wget https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz && sudo tar -xvzf postman-linux-x64.tar.gz -C /opt && sudo ln -s /opt/Postman/Postman /usr/bin/postman

### Install mitmproxy2swagger

$ sudo pip3 install mitmproxy2swagger  
  

### **Install Git**

$ sudo apt-get install git

 **Install Docker**

$ sudo apt-get install docker.io docker-compose

### **Install Go**

$ sudo apt install golang-go

### **The JSON Web Token Toolkit v2**

$ cd /opt

$ sudo git clone [https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

$ cd jwt_tool

$ python3 -m pip install termcolor cprint pycryptodomex requests

**(Optional) Make an alias for jwt_tool.py**

$ sudo chmod +x jwt_tool.py

$ sudo ln -s /opt/jwt_tool/jwt_tool.py /usr/bin/jwt_tool

### **Install Kiterunner**

$ sudo git clone  [https://github.com/assetnote/kiterunner.git](https://github.com/assetnote/kiterunner.git)

$ cd kiterunner

$ sudo make build

$ sudo ln -s /opt/kiterunner/dist/kr /usr/bin/kr

### **Install Arjun**

$ sudo git clone [https://github.com/s0md3v/Arjun.git](https://github.com/s0md3v/Arjun.git)

### **Install OWASP ZAP**

$ sudo apt install zaproxy

Once ZAP is installed, make sure to navigate to the Manage Add-Ons (CTRL+U). Make sure to apply updates for the Fuzzer and OpenAPI Support.

### **Useful Wordlists**

**SecLists ([https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists))**

$ sudo wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip \  
&& sudo unzip SecList.zip \  
&& sudo rm -f SecList.zip

**Hacking-APIs ([https://github.com/hAPI-hacker/Hacking-APIs](https://github.com/hAPI-hacker/Hacking-APIs))**

$ sudo wget -c [https://github.com/hAPI-hacker/Hacking-APIs/archive/refs/heads/main.zip](https://github.com/hAPI-hacker/Hacking-APIs/archive/refs/heads/main.zip) -O HackingAPIs.zip \  
&& sudo unzip HackingAPIs.zip \  
&& sudo rm -f HackingAPIs.zip

Once you have these tools installed and updated you should be ready to proceed to the next module.
# Your API Hacking Lab

##### [Lab Setup](https://university.apisec.ai/products/api-penetration-testing/categories/2150251486)

Throughout the course, we will be walking through two vulnerable applications, crAPI and vAPI. Both of these will be used to test out the tools and techniques that will be demonstrated throughout this course. APIsec.ai has hosted an API hacking lab that you can use to practice your skills.

crAPI can be found at crapi.apisec.ai

vAPI can be found at vapi.apisec.ai

 If you would like to set up your own lab, you can either host the vulnerable apps on your local host or on a separate system. Next is a demonstration of how to set these apps up on your local host.

# The Completely Ridiculous API (crAPI)

[https://github.com/OWASP/crAPI](https://github.com/OWASP/crAPI)

**`$mkdir ~/lab`** 

**`$cd ~/lab`**

**`#sudo curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml`**

**`$ sudo docker-compose pull`**

**`$ sudo docker-compose -f docker-compose.yml --compatibility up -d`**

If you are having issues installing this locally you can try the development version described here: [https://github.com/OWASP/crAPI](https://github.com/OWASP/crAPI) OR target the one that is hosted by APIsec.  
  
Once the installation is finished, you should be able to check to make sure crAPI is running by using a web browser and navigating to [http://127.0.0.1:8888](http://127.0.0.1:8888/) (crAPI landing page) or [http://127.0.0.1:8025](http://127.0.0.1:8025/)  (crAPI Mailhog Server). When you are done using/testing crAPI, you can stop it with docker-compose by using the following command:  
$sudo docker-compose stop

# **`vAPI`**

vAPI will be used for many of the assessments throughout this course. Although APIsec will be hosting vAPI, it may be useful to have a local version for testing.

vAPI: [https://github.com/roottusk/vapi](https://github.com/roottusk/vapi) 

$cd ~/lab  
$sudo git clone [https://github.com/roottusk/vapi.git](https://github.com/roottusk/vapi.git)  
$cd /vapi  
$sudo docker-compose up -d  
  
Once vAPI is running you can navigate to http://127.0.0.1/vapi to get to the vAPI home page. One important thing to note is that vAPI comes with a prebuilt Postman collection and environment. You can access these in the vAPI/postman folder.    
![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/H29aKnQQRDOJpNBHHGJv_postman1.png)

You can import these into Postman to be prepared for testing for future assessments. Simply open Postman, select the Import button (top right), and select the two vAPI JSON documents (see above image). Finally, confirm the import and select the Import button.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/7hfeGAPTtuy1XsdNnUqg_postman2.png)

One more thing to note about vAPI is that the Resources folder contains secrets that will be necessary to complete certain attacks. The resources folder can be found here.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/H9dTPd6TRsWCNxIAQVDX_postman3.png)

There are many labs that are available to test out the tools and techniques that you learn in this course. Check out some of these other vulnerable labs:

**Portswigger**

- [Web Security Academy](https://portswigger.net/web-security)

**TryHackMe**

- [Bookstore](https://tryhackme.com/room/bookstoreoc) (free)
- [IDOR](https://tryhackme.com/room/idor) (paid)
- [GraphQL](https://tryhackme.com/room/carpediem1) (paid)

**[HackTheBox](https://www.hackthebox.com/hacker/hacking-labs) (Retired Machines)**

- Craft
- Postman
- JSON
- Node
- Help

**Github (Vulnerable Apps)**

- [Pixi](https://github.com/DevSlop/Pixi)
- [REST API Goat](https://github.com/optiv/rest-api-goat)
- [DVWS-node](https://github.com/snoopysecurity/dvws-node)
- [Websheep](https://github.com/marmicode/websheep)

You will get the most out of this course by getting your hands on the keyboard and hacking APIs. After you've learned a new tool or technique, I highly recommend applying your skills to these other labs.