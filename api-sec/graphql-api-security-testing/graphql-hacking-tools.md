# GraphQL Hacking Tools

## **Burp Suite**

Burp Suite, developed by PortSwigger, is a powerful tool for web application security testing. It acts as a proxy between your browser and the target application, allowing you to intercept, modify, and replay HTTP requests. In this GraphQL security lab, we will use Burp Suite to manually inspect and modify GraphQL queries before they are sent to the target server.

Most recent versions of Kali come with Burp Suite pre-installed. To check if it’s available, open a terminal and run the following command:

```bash
sudo apt install burpsuite -y
```

Next, launch Burp Suite by searching for it in the Kali Applications menu. When it first starts, accept the Terms and Conditions, then select **Temporary Project** and click **Next**. For the configuration file, choose **Use Burp Defaults** and click **Start Burp**.

To ensure Burp Suite can proxy HTTP traffic, click on **Proxy > Intercept > Open Browser**. In the opened browser, navigate to `http://localhost:5013/graphiql`. This will generate a GET request to DVGA, which Burp Suite should intercept.

**Note:** Burp Suite’s embedded browser automatically configures proxy settings, making it easy to intercept traffic without additional setup.

Burp Suite will highlight the **Intercept** tab (usually orange) when it intercepts a request. You’ll see the GET request from the browser, and you can modify it before it is sent to the server. Click **Intercept is On** to release the request and allow it to continue.

We’ve now verified Burp Suite is working! For a deeper dive into this tool, consult its official documentation at [PortSwigger’s Burp Suite Documentation](https://portswigger.net/burp/documentation/desktop/penetration-testing).

***

## **Clairvoyance**

Clairvoyance is a Python-based reconnaissance tool for GraphQL APIs. It helps in discovering GraphQL schema information, especially when introspection queries are disabled by the server. This is particularly useful when dealing with production environments that restrict introspection.

Install Clairvoyance by running the following commands:

```bash
cd ~
git clone https://github.com/nikitastupin/clairvoyance.git
cd clairvoyance
```

To check that Clairvoyance is installed correctly, use the following command:

```bash
python3 -m clairvoyance -h
```

Clairvoyance works by exploiting field suggestions in GraphQL, enabling it to reconstruct schemas by querying the server with a dictionary of common words. This process will be explained in detail in Chapter 6.

***

## **InQL**

InQL is another powerful tool developed by Doyensec for introspection-based GraphQL security testing. It allows for querying GraphQL schemas and exporting schema data in various formats, which is crucial for understanding how the GraphQL API operates.

To install InQL, run the following:

```bash
cd ~
git clone https://github.com/doyensec/inql.git
cd inql
sudo python3 setup.py install
```

After installation, verify the tool works by running:

```bash
inql -h
```

InQL can also be used as a Burp Suite extension called Introspection GraphQL Scanner, available on the BApp Store. We will use the command-line version for our exercises.

***

## **Graphw00f**

Graphw00f is a tool for fingerprinting GraphQL server implementations. It analyzes responses from GraphQL APIs to identify the backend technologies, which is useful when tailoring penetration tests for specific platforms.

To install Graphw00f, run the following commands:

```bash
cd ~
git clone https://github.com/dolevf/graphw00f.git
cd graphw00f
```

Check if it’s working by running:

```bash
python3 main.py --help
```

***

## **BatchQL**

BatchQL is a Python script that focuses on identifying flaws in GraphQL servers related to batching (sending multiple queries in one HTTP request), including issues like DoS, CSRF, and information disclosure vulnerabilities.

To install BatchQL, run:

```bash
cd ~
git clone https://github.com/assetnote/batchql.git
```

To verify that BatchQL works, use the following command:

```bash
cd batchql
python3 batch.py -h
```

***

## **Nmap**

Nmap is a versatile tool used for network discovery and vulnerability scanning. Kali Linux comes pre-installed with Nmap, but to ensure it’s available, run:

```bash
sudo apt install nmap -y
```

Next, download the Nmap GraphQL introspection script and place it in the Nmap scripts folder:

```bash
cd ~
git clone https://github.com/dolevf/nmap-graphql-introspection-nse.git
cd nmap-graphql-introspection-nse
sudo cp graphql-introspection.nse /usr/share/nmap/scripts
```

Verify it works with:

```bash
nmap --script-help graphql-introspection.nse
```

***

## **Commix**

Commix is an open-source tool designed for command injection exploitation. It automates finding and exploiting command injection vulnerabilities in web applications, including GraphQL APIs.

To install Commix, run:

```bash
sudo apt install commix -y
commix -h
```

***

## **graphql-path-enum**

This Rust-based tool helps find paths to specific data within a GraphQL schema, which is useful for identifying authorization flaws in GraphQL queries.

Install graphql-path-enum by running the following:

```bash
cd ~
wget "https://gitlab.com/dee-see/graphql-path-enum/-/jobs/artifacts/v1.1/raw/target/release/graphql-path-enum?job=build-linux" -O graphql-path-enum
chmod u+x graphql-path-enum
```

Check if it works with:

```bash
./graphql-path-enum -h
```

***

## **EyeWitness**

EyeWitness captures screenshots of web applications, helping penetration testers quickly visualize and understand what’s running on a server. It uses a headless browser to load dynamic content.

Install EyeWitness by running:

```bash
sudo apt install eyewitness -y
eyewitness -h
```

***

## **GraphQL Cop**

GraphQL Cop is a Python tool developed for auditing GraphQL APIs, focusing on vulnerabilities like information disclosure and DoS attacks.

To install GraphQL Cop, run:

```bash
sudo apt install python3-pip -y
git clone https://github.com/dolevf/graphql-cop.git
cd graphql-cop
pip3 install -r requirements.txt
python3 graphql-cop.py -h
```

***

## **CrackQL**

CrackQL is a brute-forcing tool that uses GraphQL language features to optimize attacks against GraphQL APIs. We will use CrackQL for dictionary-based attacks in Chapter 7.

To install CrackQL, run:

```bash
git clone https://github.com/nicholasaleks/CrackQL.git
cd CrackQL
pip3 install -r requirements.txt
python3 CrackQL.py -h
```
