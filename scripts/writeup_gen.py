from datetime import date
import re
import requests
import os, sys
from templates.writeups import *

W_DIR = '../_writeups/{0}'.format(date.today().year)

createdFileNames = []
ctfName = ''

def createDirIfNotExists(path):
    print('Creating directory: {0}'.format(path))
    if not os.path.exists(path): 
        os.makedirs(path)

def getCtfFrontMatter():
    return ctfCompetitionTemplate.format(
        ctfName, 
        ctfName.replace(" ", "-"),
        date.today()
    )

def writeCtfFrontMatter():
    createDirIfNotExists('{0}/{1}/'.format(W_DIR, ctfName.replace(" ", "-")))
    createDirIfNotExists('../assets/CTFs/{0}/'.format(ctfName.replace(" ", "-")))
    file = open('{}/{}/{}.md'.format(W_DIR, ctfName.replace(" ", "-"), "index"), 'w+')
    file.write(getCtfFrontMatter())
    file.close()

def writeWriteupFrontMatter(challName, description, points, solves, tags, title, description2, ip, nmapTCPScanContent, webEnumerationContent):
    writeupFileName = '{}/{}/{}.md'.format(
        W_DIR, 
        ctfName.replace(" ", "-"), 
        challName.replace(" ", "-")
    )
    file = open(writeupFileName, 'w+')
    file.write(ctfWriteupTemplate.format(
        ctfName, 
        description, 
        points, 
        solves, 
        tags, 
        date.today(),
        title,
        description2,
        ip,
        nmapTCPScanContent,
        webEnumerationContent
    ))
    file.close()
    createdFileNames.append(writeupFileName)

def openCreatedFiles():
    for fileName in createdFileNames:
        os.system('/opt/nvim/bin/nvim "{0}"'.format(fileName))

def main():
    global ctfName
    ctfName = input('Enter CTF Name: ')
    writeCtfFrontMatter()
    while True:
        challName = input('Enter chall name: ')
        description = input('Enter challenge description: ')
        title = input("Enter writeup title: ")
        ip = input("Enter machine's IP: ")
        points = input('Enter points: ')
        solves = input('Enter no. of solves: ')
        tags = input('Enter chall tags: ')
        nmapTCPScanPath = input('Enter path of TCP nmap scan: ')
        with open(nmapTCPScanPath, "rb") as f:
            nmapTCPScanContent = f.read().decode()
        hasWebEnumeration = True
        webEnumeration = input('The machine has web enumeration? (y/n): ')
        hasWebEnumeration = True if webEnumeration == "y" else False
        if hasWebEnumeration == True:
            webEnumerationContent = '''
## Web enumeration
            
First let's see the technologies used with whatweb:
```bash
❯ whatweb http://{0}
(WRITE MORE)
```

(WRITE MORE)
'''.format(ip)
        else:
            webEnumerationContent = ''
        writeWriteupFrontMatter(challName, description, points, solves, tags, title, description, ip, nmapTCPScanContent, webEnumerationContent)
        if input('Add another chall? (y/n): ') != 'y':
            break
    openCreatedFiles()

main()
