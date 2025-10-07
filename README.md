# Weblogic-Decrypt

This tool decrypts Oracle's WebLogic stored hashes. And the best part about it, it's not use java weblogic libraries, you dont need to run on the target machine or dont need to install weblogic for decrypting. 

It decrypts with pycryptodome library.

***Note:*** Tested on WebLogic 14.1.1 and AES hashes only.

#### Example 

```
└─$ ls path/to/files

boot.properties		config.xml	SerializedSystemIni.dat

└─$ cat boot.properties
username={AES256}M.....1=
password={AES256}t......R=
```

```
└─$ python3 weblogic_decrypt.py -i SerializedSystemIni.dat -f config.xml
[+] Password: Password!
[+] Password: Password1
[+] Password: Password!1
[+] Password: Password1!

└─$ python3 weblogic_decrypt.py -i SerializedSystemIni.dat -s "{AES256}M.....1="
[+] Password: system

└─$ python3 weblogic_decrypt.py -i SerializedSystemIni.dat -s "{AES256}t......R="
[+] Password: Password1
```
