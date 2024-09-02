#!/usr/bin/python3
from datetime import date
import re
import requests
import os, sys
from templates.writeups import *

current_date = date.today()

# Access the year attribute to get the current year
current_year = current_date.year
writeupDir = "../_writeups"
createdFileNames = []
ctfName = ''

def createDirIfNotExists(path):
    print('Creating directory: {0}'.format(path))
    if not os.path.exists(path): 
        os.makedirs(path)

def writeWriteupFrontMatter(challName, description, points, solves, tags, title, description2, ip, nmapTCPScanContent, webEnumerationContent):
    ctfDir = f"{writeupDir}/{current_year}/{ctfName}"
    createDirIfNotExists("../assets/images/{0}".format(challName))
    createDirIfNotExists(ctfDir)
    writeupFileName = '{}/{}.md'.format(
        ctfDir,
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

def getCtfFrontMatter():
    return ctfCompetitionTemplate.format(
        ctfName, 
        ctfName.replace(" ", "-"),
        date.today()
    )

def writeCtfFrontMatter():
    ctfDir = f"{writeupDir}/{current_year}/{ctfName}"
    createDirIfNotExists(ctfDir)
    file = open(f'{ctfDir}/index.md', 'w+')
    file.write(getCtfFrontMatter())
    file.close()

def openCreatedFiles():
    for fileName in createdFileNames:
        os.system('code ..')

def main():
    global ctfName
    ctfName = "HTB"
    writeCtfFrontMatter()
    while True:
        challName = input('Enter chall name: ')
        description = input('Enter challenge description: ')
        title = ctfName + " " + challName + " writeup"
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
# Web enumeration
            
Taking a look with curl, I can see [WRITE MORE HERE]
```bash
❯ curl -i -s http://{0}
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

