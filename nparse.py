#!/usr/bin/python

# NMAP PARSER

import sys, re

def nextract():

	rawfile = open('nmapscan.txt','r')
	#dict = {'Port': [], 'Service': [], 'Version': []}
	
	nport = []
	nservice = []
	nversion = []

	for line in rawfile:
		
		mylist = line.split()
		
		if mylist:
			portmatch = re.match('\d{1,5}\/tcp', mylist[0])
			
		if portmatch:
			nport.append(mylist[0])       # Adding the Port number to our dictionary
			nservice.append(mylist[2])    # Adding the Service name to our dictionary
			
			if len(mylist) == 10 :

                                myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6] + ' ' + mylist[7] + ' ' + mylist[8] + ' ' + mylist[9]
                                nversion.append(myver)
                                #print myver
                                continue

			if len(mylist) == 9 :

                                myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6] + ' ' + mylist[7] + ' ' + mylist[8]
                                nversion.append(myver)
                                #print myver
                                continue
	
			if len(mylist) == 8 :

                                myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6] + ' ' + mylist[7]
                                nversion.append(myver)
                                #print myver
                                continue
	
				
			if len(mylist) == 7 :

				myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6]
				nversion.append(myver)
				#print myver
				continue

			if len(mylist) == 6 :

				myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5]
				nversion.append(myver)
				#print myver
				continue

			if len(mylist) == 5 :

				myver = mylist[3] + ' ' + mylist[4]
				nversion.append(myver)
				#print myver
				continue
			
			if len(mylist) == 4:

				myver = mylist[3]
				nversion.append(myver)
				#print myver

			if len(mylist) == 3:

                                myver = 'Null'
                                nversion.append(myver)
                                #print myver

	
	rawfile.close()

nextract()

def xtract():

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


xtract()
