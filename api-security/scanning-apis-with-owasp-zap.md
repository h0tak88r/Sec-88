# Scanning APIs with OWASP ZAP

### Importing API Specification in OWASP ZAP

1.  Open OWASP ZAP and select the "Import" option.

    ![Import API Specification](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/3QhpAQLTQqG1Sb8MPTft\_ScanningAPIs1.PNG)
2.  Choose the relevant API specification file (e.g., specs.yml) for crAPI and provide the target URL (http://crapi.apisec.ai or http://127.0.0.1:8888).

    ![Specify File and URL](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/oEsdxfxQGiPyRW2Nxobg\_ScanningAPIs2.PNG)
3.  After adding the file path and target URL, select "Import." The Sites window will now display the target's endpoints and API requests.

    ![Sites Window](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/2APuCeXwS6S6Npz32QhO\_ScanningAPIs3.PNG)
4.  Right-click on the root (e.g., http://crapi.apisec.ai) and choose to perform an active scan. Results will be available under the Alerts tab.

    ![Perform Active Scan](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/tXyxubIySxasnFlUXUtw\_ScanningAPIs5.PNG)

### Authenticated Scanning with Manual Explore

1.  Improve scan results by performing authenticated scanning using the Manual Explore option.

    ![Manual Explore](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/FMTNLZyOSGKGoPJABPJ4\_ScanningAPIs7.PNG)
2.  Set the URL to the target, enable the HUD, and choose "Launch Browser."

    ![Launch Browser](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/Ac8Y0rHqSqile9WdaoWu\_ScanningAPIs8.PNG)
3.  The HUD will launch in a browser. Select "Continue to your target" and use the web application as an end-user.

    ![HUD Browser](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/967oh1osRLeGnyntOPWb\_ScanningAPIs9.PNG)
4.  Perform actions such as signing up, signing in, and using various features. Use the HUD to perform actions and add the target to the scope.

    ![Add to Scope](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/WkGjSKhARZKFnh8sCMho\_ScanningAPIs11.PNG)
5.  On the right side of the HUD, set Attack Mode to On. This initiates scanning and authenticated testing of the target.

    ![Attack Mode On](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/xZQvLSUcSQue7u0Gzmew\_ScanningAPIs12.PNG)
6.  The scan may take a while depending on the web application's scale. Review the results under the Alerts tab.

    ![Scan Results](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/xZQvLSUcSQue7u0Gzmew\_ScanningAPIs12.PNG)
7. Investigate the findings and differentiate between actual vulnerabilities and false positives. Note that crAPI exhibits vulnerabilities from the OWASP API Security Top 10, including Security Misconfigurations and Injection..
