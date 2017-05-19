#!/usr/bin/python

import sys, re

def extract():

	rawfile = open('nmapscan.txt','r')
	dict = {'Port': [], 'Service': [], 'Version': []}

	for line in rawfile:
		
		mylist = line.split()
		
		if mylist:
			portmatch = re.match('\d{1,5}\/tcp', mylist[0])
			
		if portmatch:
			dict['Port'].append(mylist[0])       # Adding the Port number to our dictionary
			dict['Service'].append(mylist[2])    # Adding the Service name to our dictionary
			
			if len(mylist) == 10 :

                                myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6] + ' ' + mylist[7] + ' ' + mylist[8] + ' ' + mylist[9]
                                dict['Version'].append(myver)
                                print myver
                                continue

			if len(mylist) == 9 :

                                myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6] + ' ' + mylist[7] + ' ' + mylist[8]
                                dict['Version'].append(myver)
                                print myver
                                continue
	
			if len(mylist) == 8 :

                                myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6] + ' ' + mylist[7]
                                dict['Version'].append(myver)
                                print myver
                                continue
	
				
			if len(mylist) == 7 :

				myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5] + ' ' + mylist[6]
				dict['Version'].append(myver)
				print myver
				continue

			if len(mylist) == 6 :

				myver = mylist[3] + ' ' + mylist[4] + ' ' + mylist[5]
				dict['Version'].append(myver)
				print myver
				continue

			if len(mylist) == 5 :

				myver = mylist[3] + ' ' + mylist[4]
				dict['Version'].append(myver)
				print myver
				continue
			
			if len(mylist) == 4:

				myver = mylist[3]
				dict['Version'].append(myver)
				print myver
	
	rawfile.close()
	#portlist = dict['Port']
	print Port.values()

extract()


