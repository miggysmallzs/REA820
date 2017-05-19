#!/usr/bin/python

# XPROBE PARSER
#
#
# Below is the formatted information we are looking for. Have to keep it simple for now. Since this has one less column of information(no version info)
#
# We're gonna have to compare the xprobe scan to nmap and exclude any redundant matches.
#
#0	1	2		3		4
#[+]   Proto	Port Num.	State		Serv. Name
#[+]   TCP	21		open		ftp	
#[+]   TCP	22		open		ssh	
#[+]   TCP	23		open		telnet	
#[+]   TCP	25		open		smtp	
#[+]   TCP	53		open		domain	
#[+]   TCP	80		open		http	
#[+]   TCP	111		open		sunrpc	
#[+]   TCP	139		open		netbios-ssn	
#[+]   TCP	445		open		microsoft-ds	
#[+]   TCP	512		open		exec	
#[+]   TCP	513		open		login	
#[+]   TCP	514		open		shell

import sys, re

def extract():

	rawfile = open('xprobe_scan.txt','r')
	
	xport = []
	xservice = []

	for line in rawfile:
		
		mylist = line.split()
		
		if len(mylist) == 5:
			portmatch = re.search('[\d]{1,5}', mylist[2])
			protomatch = re.search('TCP', mylist[1])
			if portmatch:
				xport.append(mylist[2])       # Adding the Port number to our dictionary
			if protomatch:
				xservice.append(mylist[4])
				
	print xport
	print xservice		
	rawfile.close()


extract()

