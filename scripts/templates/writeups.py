ctfCompetitionTemplate = '''---
layout: ctf_overview
title: {0}
category: {1}
date: {2}
---
'''

ctfWriteupTemplate = '''---
layout: writeup
category: {0}
description: {1}
points: {2}
solves: {3}
tags: {4}
date: {5}
title: {6}
comments: false
---

{7}

# Enumeration

## Port scanning

I will start with a basic TCP port scanning with nmap to see which ports are open and see which services are running:

```python
❯ sudo nmap -p- --open -sS -sVC --min-rate 5000 -v -n -Pn {8}
{9}```

* -sVC: Identifies service and version.
* -p-: scans all the range of ports (1-65535).
* --open: shows only open ports and not filtered or closed.
* -sS: TCP SYN scan that improves velocity because it doesn't establish the connection.
* --min-rate 5000: Sends 5000 packets per second to improve velocity (don't do this in a 
real environment).
* -n: Disables DNS resolution protocol.
* -v: Enables verbose to see which ports are opened while it's scanning
* -Pn: Disables host discovery protocol (ping).
* -oN targeted: Exports the evidence to a file named "tcpTargeted".

{10}
'''
