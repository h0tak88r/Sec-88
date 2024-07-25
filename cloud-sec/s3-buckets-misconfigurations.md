# S3 Buckets Misconfigurations

### **Step** **1**: Create an AWS Account

* Visit the AWS website ([https://aws.amazon.com](https://aws.amazon.com/)) and create a free account

### **Step** **2**: Download and Install AWS CLI

{% embed url="https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-download" %}

### **Step** **3:** Configure AWS CLI

```sh
aws configure
```

### **Step** **4**: Interacting with S3 Buckets

```sh
List bucket contents: 
aws s3 ls s3://bucket-name

Download a file: 
aws s3 cp s3://bucket-name/file.png ./

Upload a file: 
aws s3 cp ./localfile.txt s3://bucket-name/poc.txt

Copy a File:
aws s3 cp test.txt s3://bucket_name

To move a file to a bucket:
aws s3 mv test.txt s3://bucket_name

Delete command:
aws s3 rm s3://qa-media.company/fileName.txt

To Dump Data:
aws s3 sync . s3://[bucketname]
```

### Tools

{% embed url="https://github.com/sa7mon/S3Scanner" %}

[Lazy S3](https://github.com/nahamsec/lazy-s3)

[bucket\_finder](https://github.com/michenriksen/bucket\_finder)

[AWS Cred Scanner](https://github.com/netgusto/awsbucketdump)

[sandcastle](https://github.com/0xdabbad00/sandcastle)

[Mass3](https://github.com/eth0izzle/mass3)

[Dumpster Diver](https://github.com/securing/DumpsterDiver)

[S3 Bucket Finder](https://github.com/gwen001/s3-buckets-finder)

### Checklist

* [ ] S3 Content Listing

{% embed url="https://hackerone.com/reports/1062803" %}

* [ ] User's Can upload any files without limits&#x20;

{% embed url="https://hackerone.com/reports/764243" %}

* [ ] No Authentication on S3 bucket and can be accessed by any user

{% embed url="https://hackerone.com/reports/819278" %}

* [ ] &#x20;S3 bucket misconfig of pre-signed URLs

{% embed url="https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls/" %}

[https://www.youtube.com/watch?v=MBQJJ3jfJ8k](https://www.youtube.com/watch?v=MBQJJ3jfJ8k)

[https://www.youtube.com/watch?v=G7Pre3Y46Fs](https://www.youtube.com/watch?v=G7Pre3Y46Fs)

### Another Resources

* [https://awsdocs.s3.amazonaws.com/S3/latest/s3-qrc.pdf](https://awsdocs.s3.amazonaws.com/S3/latest/s3-qrc.pdf) &#x20;

{% embed url="https://3bodymo.medium.com/how-i-earned-by-amazon-s3-bucket-misconfigurations-29d51ee510de" %}

{% embed url="https://medium.com/@janijay007/s3-bucket-misconfiguration-from-basics-to-pawn-6893776d1007" %}

* [https://www.youtube.com/watch?v=tvWLgvK3QWo\&list=PLWDPse9uXlgPBpf\_dY0M9bIE\_8f6MUO6c](https://www.youtube.com/watch?v=tvWLgvK3QWo\&list=PLWDPse9uXlgPBpf\_dY0M9bIE\_8f6MUO6c)
