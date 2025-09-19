---
layout: blog
title: My used nmap arguments
tags: nmap ports ports-enumeration scanning 
comments: false
date: 2025-9-19
---

# My used nmap arguments

Nmap is a nice tool to enumerate the ports of an IP. To have better performance and bigger enumeration, I normally use these arguments in CTFs and test environments:


```bash
❯ sudo nmap -sS -sVC -p- --open --min-rate 5000 -v -n -Pn <IP> -oA <file>
```

* `-sVC`: Identifies service and version.
* `-p-`: scans the entire range of ports (1-65535).
* `--open`: shows only open ports and not filtered or closed.
* `-sS`: TCP SYN scan that improves speed because it doesn't establish the connection.
* `--min-rate 5000`: Sends 5000 packets per second to improve speed (don't do this in a real environment) because it's so noisy.
* `-n`: Disables DNS resolution protocol.
* `-v`: Enables verbose to see which ports are opened while it's scanning
* `-Pn`: Disables host discovery protocol (ping).
* `-oA <file>`: Exports the evidence to multiple files in different formats (xml, grep and normal output)
