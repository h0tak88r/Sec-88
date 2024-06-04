# Analyzing SQLite Storage

* It is as easy as just go to the database directory of the package in the data directory&#x20;
* Then initialize sqlite and interact with it read tables and that stuff

<figure><img src="../../.gitbook/assets/image (12) (1).png" alt=""><figcaption></figcaption></figure>

```bash
1|vbox86p:/data/data/com.android.insecurebankv2/databases # ls
mydb mydb-journal 
vbox86p:/data/data/com.android.insecurebankv2/databases # sqlite3 mydb                                                                                
SQLite version 3.22.0 2018-12-19 01:30:22
Enter ".help" for usage hints.
sqlite> .tables 
android_metadata  names           
sqlite> select * from android_metadata;
en_US
sqlite> select * from names;
1|dinesh
2|dinesh
sqlite> 

```

