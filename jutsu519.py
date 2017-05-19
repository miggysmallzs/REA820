#!/usr/bin/python
"""Usage:
	ruleparser.py -i <file_to_parse> -s <string_to_parse>... [-c] [--dir][--vim]
	ruleparser.py -i <file_to_parse> -o <file_output> -s <string_to_parse>... [-c] [--dir][--vim] 	
	ruleparser.py -i <file_to_parse> -o <file_output> [-e <scan_option>]... [-c] [--dir] [--vim]
	ruleparser.py -i <file_to_parse> [-c] [--dir]
	
Options:
	-i <file_to_parse>		specify file containing rules to be parsed
	-o <file_output>		specify output file
	-e <scan_option>                file containing scan results, otherwise IP address to initiate nmap scan
	-s <string_to_parse>		string(s) to match inside the filename
	-c				display number of matching rules/counts number of rules in <file_to_parse> 
	--dir				display absolute path to location of <file_to_parse> 
	-a 				open <file_to_parse> for editing, no rule changes can be made without this



"""
# -*- coding: utf-8 -*-

#IMPORTS#

import os
import re
import subprocess
import tempfile
import time
from docopt import docopt
from itertools import tee, izip_longest
from libnmap.process import NmapProcess
from time import sleep, strftime
from datetime import datetime

#CUSTOM FUNCTIONS##


#function to return regex pattern 
#parameter: strings from the -s option
#return: regex pattern object
def create_regex_search(string_to_parse):
	regex_pattern = ''.join([string+"|" for string in string_to_parse])
	regex_pattern = regex_pattern[:-1]
	regex = re.compile('.*(%s).*'%regex_pattern)
	return regex

#function to check valid IP address
#parameter: IP address string
#return: boolean True/False
def check_valid_ip(ip_address):
	ip_regex = r"^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(16|24))$"
	regex = re.compile(ip_regex)
	check = bool(re.search(regex, ip_address))
	return check

#function to create list containing rules that match search conditions
#parameter: file input, string regex pattern oject
def create_matching_rules(file_input_read, string_pattern):
	#print string_pattern
	rules_match_list = []
	for i in file_input_read:
		x = i.split()
		if len(x) > 0:
			if x[0] == 'alert':
				i = i.strip('\n')
				for i2 in x:
					if re.search(string_pattern,i2):
						rules_match_list.append(i)
						break
	#print rules_match_list	
	return rules_match_list

#function to open input to vim
#parameter: string containing rules
#return: spawn vim containing rules
def edit(data):
	fdes = -1
	path = None
	fp = None
	try:
		fdes, path = tempfile.mkstemp(suffix='.txt', text=True)
		fp = os.fdopen(fdes, 'w+')
        	fdes = -1
		for i in data:
			fp.write(i+"\n")
        	fp.close()
        	fp = None

        	editor = os.environ.get('EDITOR', 'vim')
        	subprocess.check_call([editor, path])

        	fp = open(path, 'r')
        	return fp.read()
    	finally:
        	if fp is not None:
            		fp.close()
        	elif fdes >= 0:
            		os.close(fdes)
        	if path is not None:
            		try:
                		os.unlink(path)
            		except OSError:
                		pass
	
#hard coded options for nmap scan, excludes file output and target IP
#65535 ports
nmap_scan_default = "-sS -A -p1-65535 -oN nmap_default_output"
#perform nmap scan
#parameter: (target host IP/subnet), nmap options for scanning
#return: none
def nmap_scan(scan_options_param, target):
	#print "scan parameter passed", scan_options_param
	#print "IP to be used in scanning", target
	nmap_param_list = scan_options_param.split()
	file_out_default = "nmap_default_output"
	file_out_custom = nmap_param_list[-1]
	if file_out_default != file_out_custom:
		nmap_scan_default == "-sS -A -p1-100 -oN " + file_out_custom + ""
		print "Scan output will be saved in:", file_out_custom
		nmap_proc = NmapProcess(targets=target, options=nmap_scan_default, safe_mode=False)
		nmap_proc.sudo_run_background(run_as='root')	
	else:
		print "Scan output will be saved in:", file_out_default
		nmap_proc = NmapProcess(targets=target, options=nmap_scan_default, safe_mode=False)
		nmap_proc.sudo_run_background(run_as='root')
	#start = time.time()
	while nmap_proc.is_running():
		#timestamp = int(nmap_proc.etc)
		#datetime_etc = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
		print ("Running Scan")
		sleep(3)
	#end = time.time()
	#elapsed = end - start
	#elapsed = str(elapsed)
	print("rc: {0} output: {1}".format(nmap_proc.rc, nmap_proc.summary))


#parse output file from nmap scan 
#parameter: output file from nmap scan
#return: list containing port, service, version from scan result
def extract(scan_result):
	rawfile = open(scan_result,'r')
	dict = {'Port': [], 'Service': [], 'Version': []}
	#go through each line in scan result
	for line in rawfile:		
		mylist = line.split()
		if mylist:
			#regex looking for new line containing port, service, version
			portmatch = re.match('\d{1,5}\/tcp', mylist[0])
		if portmatch:
			#add values for keys 'Port' and 'Service'
			dict['Port'].append(mylist[0])       
			dict['Service'].append(mylist[2])    
			list_len = len(mylist)
			#starting index for parsing version string
			index = 3
			version = ""
			ver = []
			#parse version string until end of line
			if (list_len >= 4) and (index < list_len):
				#while end of line is not reached
				while index < list_len:
					#append each word to version string 
					version += mylist[index]
					if index < list_len:
						ver.append(version)
					index += 1
				#when end of line is reached
				#add each final version string to key 'Version'
				version_result = dict['Version']
			#append version list as final value for key 'Version'	
			dict['Version'].append(version)
	port_result = dict['Port']	
	service_result = dict['Service']
	version_result = dict['Version']
	scan_list = port_result + service_result + version_result
	#print scan_list
	return scan_list


#MAIN FUNCTION##

#docopt's output is a dictionary:
#{'option':'argument(s)',...}
if __name__ == '__main__':
	arguments = docopt(__doc__, version='0.0.1')
	#PRINT DICTIONARY CONTAINING OPTIONS & ARGS FOR TESTING PURPOSES
	#print(arguments)

#assign dictionary result to result_dict 
result_dict = docopt(__doc__, version='0.0.1')

#create and initialize variables
#variables to check if option is used
input_check = result_dict['-i']
search_check = result_dict['-s']
output_check = result_dict['-o']
count_check = result_dict['-c']
directory_check = result_dict['--dir']
vim_check = result_dict['--vim']
scan_check = result_dict['-e']
scan_option = result_dict['<scan_option>']
string_to_parse = result_dict['<string_to_parse>']
file_input = result_dict['<file_to_parse>']
file_output = result_dict['<file_output>']
rules_list = []
nmap_options = ""
ip_addr = ""
scan_str = ""
scan_rlist = []	
#create regex pattern based on string input


if input_check:
	file_input_read = open(file_input, "r")
	if (search_check == True) or (string_to_parse != []):		
		string_pattern = create_regex_search(string_to_parse)
		rules_list = create_matching_rules(file_input_read, string_pattern)
		rule_count = len(rules_list)
		rule_count = str(rule_count)
		display = raw_input("Display all " + rule_count + " matching rule(s)?[y/n]") 
		grep_list = ''.join([string+"|" for string in string_to_parse])
		if len(string_to_parse) == 1:
			grep_list = grep_list[:-1]
		elif len(string_to_parse) > 1:
			grep_list = grep_list[:-1]
		if display == 'y':
			#subprocess.Popen(['grep -E --color=always '+'"'+''+grep_list+''+'"'+' '+file_input+''], shell=True)
			disp = subprocess.check_output(['grep -E --color=always '+'"'+''+grep_list+''+'"'+' '+file_input+''], shell=True)
			print disp
		overwrite_rules = raw_input("Overwrite " + file_input + " with matching rule(s)?[y/n]")	
		if overwrite_rules == 'y':
			file_copy = file_input+'-copy'
			file_input_copy = file_input
			print file_input
			print file_copy
			subprocess.call(['cp '+file_input+' '+file_copy+''], shell=True)
			new_file = open(file_input, "w+")
			for rules in rules_list:
				new_file.write(rules+"\n")
			new_file.close()
			
			
			
	file_input_read.close()
	
	if count_check:
		rule_count = len(rules_list)
		print ("Number of matching rule(s): " + str(rule_count) + " ")
	
	if output_check and scan_check == 0:
		new_file = open(file_output, "w+")
		for rules in rules_list:
			new_file.write(rules+"\n")
		new_file.close()
		
	if vim_check == True and scan_check == 0:
		vim_list = []
		vim_str = ""
		vim_read = open(file_output, "r")
		for line in vim_read:
			line = line.strip('\n')
			vim_list.append(line)
		#print vim_list
		edit(vim_list)
		
	#check if -e (scanning) is used
	#requires -o for outputting results
	if (output_check == True) and (scan_check != 0):
		#print "scan option list",scan_option
		ip_address_in = scan_option[0]
		len_scan_option = len(scan_option)
		if len_scan_option == 1:
			#if '-e X.X.X.X' option is specified, IP address
			if check_valid_ip(ip_address_in) == True:
				scan_input_str = ''.join(scan_option)
				#scan using IP address, output to default file
				nmap_scan(nmap_scan_default, ip_address_in)
				string_to_parse = extract("nmap_default_output")
				#print "list containing str to parse", string_to_parse
				#print "PARSED RESULT FROM nmap_default_output:", string_to_parse
				string_pattern = create_regex_search(string_to_parse)
				file_input_read = open(file_input, "r")
				rules_list = create_matching_rules(file_input_read, string_pattern)
				new_file = open(file_output, "w+")
				for rules in rules_list:
					new_file.write(rules+"\n")
				
				rule_count = len(rules_list)
				rule_count = str(rule_count)					
				display = raw_input("Display all " + rule_count + " matching rule(s)?[y/n]")
				grep_list = ''.join([string+"|" for string in string_to_parse])
				if len(string_to_parse) == 1:
					grep_list = grep_list[:-1]
				elif len(string_to_parse) > 1:
					grep_list = grep_list[:-1]
				
				overwrite_rules = raw_input("Overwrite " + file_input + "? (Will be backed up as " + file_input + "-copy) [y/n]")
				if overwrite_rules == 'y':
					file_copy = file_input+'-copy'
					print(type(file_copy))
					file_input_copy = file_input
					print file_input
					print file_copy
					subprocess.call(['cp '+file_input+' '+file_copy+''], shell=True)
					new_file_write = open(file_input, "w+")
					for rules in rules_list:
						new_file_write.write(rules+"\n")
					new_file_write.close()
				if display == 'y':
					disp = subprocess.check_output(['grep -E --color=always '+'"'+''+grep_list+''+'"'+' '+file_input+''], shell=True)
					print disp				
				new_file.close()
				file_input_read.close()
			#if '-e file_containing_scan_result', use file output
			if check_valid_ip(ip_address_in) == False:
				#print scan_option
				scan_input_str = ''.join(scan_option)
				#print scan_input_str
				string_to_parse = extract(scan_input_str)
				string_pattern = create_regex_search(string_to_parse)
				file_input_read = open(file_input, "r")
				rules_list = create_matching_rules(file_input_read, string_pattern)
				new_file = open(file_output, "w+")
				for rules in rules_list:
					new_file.write(rules+"\n")
				rule_count = len(rules_list)
				rule_count = str(rule_count)				
				display = raw_input("Display all " + rule_count + " matching rule(s)?[y/n]")

				grep_list = ''.join([string+"|" for string in string_to_parse])
				if len(string_to_parse) == 1:
					grep_list = grep_list[:-1]
				elif len(string_to_parse) > 1:
					grep_list = grep_list[:-1]
	
				overwrite_rules = raw_input("Overwrite " + file_input + "? (Will be backed up as " + file_input + "-copy) [y/n]")
				if overwrite_rules == 'y':
					file_copy = file_input+'-copy'
					print(type(file_copy))
					file_input_copy = file_input
					print file_input
					print file_copy
					subprocess.call(['cp '+file_input+' '+file_copy+''], shell=True)
					new_file_write = open(file_input, "w+")
					for rules in rules_list:
						new_file_write.write(rules+"\n")
					new_file_write.close()	
				
				if display == 'y':
					disp = subprocess.Popen(['grep -E --color=always '+'"'+''+grep_list+''+'"'+' '+file_output+''], shell=True)
					print disp
				new_file.close()				
				file_input_read.close()
			
		elif (len_scan_option == 2):
			ip_address_in = scan_option[1]
			custom_file_output = scan_option[0]
			nmap_scan_default = "-sS -A -p1-1000 -oN " + custom_file_output + ""
			if check_valid_ip(ip_address_in) == True:
				#nmap_scan_default - defined fixed options for nmap scan
				nmap_scan(nmap_scan_default,ip_address_in)

if directory_check == True and input_check == True:
	print "ABSOLUTE PATH LOCATION of "+file_input+":",os.path.abspath(""+file_input+"")
