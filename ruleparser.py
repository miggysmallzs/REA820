#!/usr/bin/python
"""Usage:
	ruleparser.py -i <file_to_parse> -s <string_to_parse>... [-c] [--dir][--vim][--scan <target>]
	ruleparser.py -i <file_to_parse> [-o <file_output>] -s <string_to_parse>... [-c] [--dir][--vim] 	
	ruleparser.py -i <file_to_parse> -s <string_to_parse>... [-c][--dir][--vim]
	ruleparser.py -i <file_to_parse> --dir
	ruleparser.py --scan <nmap_option>...
	ruleparser.py -h
	
Options:
	-i <file_to_parse>		specify file containing rules to be parsed
	-s <string_to_parse>		string(s) to match inside the filename
	-c				display number of matching rules based on input string
	-o <file_output>		specify output file   
	--dir				display directory location of <file_to_parse>
	-h

"""
#The same structure will be used for the main script to provide command-line interface
#Options to be added:
# --scan -> enable scan using Nmap and Xprobe
# --target -> remote IP address/range to be scanned
import os,re,subprocess
from docopt import docopt

if __name__ == '__main__':
	arguments = docopt(__doc__, version='0.0.1')
	print(arguments)
	
result_dict = docopt(__doc__, version='0.0.1')


try:
	string_to_parse = result_dict['<string_to_parse>']
	rules_list = []
	string_array = result_dict['<string_to_parse>']
	regex_pattern = ''.join([string+"|" for string in string_array]) 
	regex_pattern = regex_pattern[:-1]
	string_pattern = re.compile('.*(%s).*'%regex_pattern)
	if result_dict['-i'] == True:
		file_input = result_dict['<file_to_parse>']
		file_input_read = open(file_input, "r")
		if (result_dict['-s'] is not None) or (result_dict['<string_to_parse>'] != []):
			for line in file_input_read:
				if re.search(string_pattern,line) and (line.startswith("alert", 0, 5)):
					line = line.strip('\n')
					rules_list.append(line)
		#for line in rules_list:
		#	print line
		print rules_list
		if result_dict['-c'] == True:
			rule_count = len(rules_list)
			print ("Number of matching rule(s): " + str(rule_count) + " ")
		if result_dict['--dir'] == True:
			print os.path.abspath(""+file_input+"")
		if result_dict['-o'] == True:
			output = result_dict['<file_output>']
			new_file = open(output, "w+")
			for rules in rules_list:
				new_file.write(rules+"\n")
			print new_file
			new_file.close()
		if result_dict['--vim'] == True:
			proc = subprocess.Popen("vim " + result_dict['<file_to_parse>'] + "", shell=True)
		#parse nmap options from cmd line
		#add "-" to all --scan arguments since it accepts it without "-" 
		#e.g. ss A -> -ss -A
		if result_dict['--scan'] == True:
			proc = subprocess.Popen("nmap -sS -A -p1-65535 -oN nmap_scan 127.0.0.1 > /dev/null", shell=True)
		file_input_read.close()
except IOError:
	print "Invalid filename"
