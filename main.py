#!/usr/bin/env python

import os
import sys
import json
import re
from copy import deepcopy
from hashlib import md5


'''

This moudle is used to:
	1. substract the functions and their positions in the given C source files
	2. establish the indexes for the backdoor-like function calls and their mother function
	3. return some information of the specific backdoor-like function calls:
		a. the filename
		b. the line number
		c. its mother function
		d. the lines nearby the function call

'''

#######   This  is  config  #######


indexes = {}
filenames = []
debug = False
content_offset = 5
indexes_2 = {}
str_rule_cfg = 'str_rules'
func_rule_cfg = 'func_rules'
str_rules = []
func_rules = []
scores = {}
global_func_def = {}
record_file = 'res'

a = open('runtime/res_2.txt').readlines()
a = map(lambda x:x[2].strip() + '@' + './' + x[1] if x[1] else '', [x.split(',') for x in a])
while '' in a:
	a.remove('')
malicious_funcs = a

#######    config  ends     #######

def Cacu_value(func_state,strs_state):
	score = 0
	score += (func_state[0]&func_state[3]&(strs_state[0]|strs_state[1]))*1000
	score += (func_state[2]&func_state[1]&strs_state[2])*600
	score += (func_state[0]&func_state[1]&(strs_state[0]|strs_state[1])&strs_state[2])*800
	score += (func_state[0]&strs_state[1])*600
	score += (func_state[1]&(strs_state[0]|strs_state[1]))*800
	score += (func_state[4]&(strs_state[4]|func_state[3]))*800
	score += (func_state[4]&func_state[1])*400
	score += (func_state[1]&strs_state[6])*1000
	score += (func_state[4]&(strs_state[0]|strs_state[1])&strs_state[4])*800
	score += ((func_state[3]|strs_state[4])&(func_state[1]))*200
	score += (func_state[5]&(strs_state[0]|strs_state[1]))*600
	score += (strs_state[9]&(strs_state[0]|strs_state[1]))*500

	score += func_state[0]*10+func_state[1]*10+func_state[2]*50+func_state[3]*30+func_state[4]*30+func_state[5]*30
	score += strs_state[0]*10+strs_state[1]*30+strs_state[3]*80+strs_state[4]*20
	score += strs_state[5]*10+strs_state[6]*80+strs_state[7]*50+strs_state[8]*20
	score += strs_state[9]*10
	return score

def Deal_funcs(sub_funcs):

	global func_rules
	func_rules = [["read", "fread", "fgetc", "fgets","open","fopen"],
	["write","fwrite", "fputc", "fputs", "fprintf","fscanf","sprintf"],
	["tcgetattr"],
	["send", "recv","connect","bind","socket","gethostbyname","recvfrom","inet_addr"],
	["popen","system","exec","execl","execv","execve","execlp","execle","execvp"],
	["ftruncate", "chmod"],
	["ptrace","get_nprocs","opendir","readdir","lstat","getifaddrs","getlogin","getpwent","getuid","rename","getcwd","getenv"],
	["ioctl"]
	]

	func_state=[0 for i in xrange(0,len(func_rules))]

	for i in xrange(0,len(func_rules)):
		if len(set(func_rules[i])&set(sub_funcs))>0:
			func_state[i] = 1

	return func_state

def Main_deal(funcs_list, sub_funcs, strs_dict):
	func_state={}
	F={}
	for i in xrange(0,len(funcs_list)):
		funcs = funcs_list[i]
		#print funcs
		if (sub_funcs.has_key(funcs)):
			func_state[funcs] = Deal_funcs(sub_funcs[funcs])
		else:
			func_state[funcs] = [0 for i in xrange(0,len(func_rules))]

		if (strs_dict.has_key(funcs)):
			F[funcs] = Cacu_value(func_state[funcs],strs_dict[funcs])
		else:
			F[funcs] = Cacu_value(func_state[funcs],[0 for i in xrange(len(str_rules))])

	result = sorted(F.items(),key=lambda x:int(x[1]),reverse=True)[0:3]

	# record the highest func to the submit
	highest_func = result[0][0]
	highest_file_name = find_filename_by_func(highest_func)
	highest_project_name = highest_file_name.split('/')[1]

	tmp_res = highest_project_name + ':' + 'yes' + ',' + highest_file_name[2:] + ',' + highest_func.split('@')[0] + "\n"
	open('submit_tmp.txt','a').write(tmp_res)

	# print func_state
	# print 'closedir@./p_058/src/readdir.c' in sub_funcs
	# print 'closedir@./p_058/src/readdir.c' in funcs_list 
	# print sub_funcs


	for func in funcs_list:
		# to prevent the func_state from being modified while 
		# we modify my_state
		my_state = deepcopy(func_state[func])
		if strs_dict.has_key(func):
			my_state += strs_dict[func]
		else:
			# no malicious string detected
			my_state += [0 for i in range(len(str_rules))]

		my_state = map(str,my_state)
		file_name = find_filename_by_func(func)
		project_name = file_name.split('/')[1]
		tmp_res = project_name + ',' + func.split('@')[1][2:] + ',' + func.split('@')[0] + ',' + ','.join(my_state)
		open('func_status.txt','a').write(tmp_res + "\n")

		if func in malicious_funcs:
			open('malicious.txt','a').write(tmp_res + "\n")

	for func in result:
		file_name = find_filename_by_func(func[0])
		res = ''
		res += "File_name :%s\n" % file_name
		res += "Func name :%s\n" % func[0].split('@')[0]
		res += "Score:%s\n" % func[1]
		if func_state.has_key(func[0]):
			res += "Func state :%s\n" % func_state[func[0]]
		if strs_dict.has_key(func[0]):
			res += "Strs state :%s\n" % strs_dict[func[0]]

		res += "#############################\n"
		print res
		open(record_file,'a').write(res)

	# elegant record
	# func = result[0]
	# file_name = find_filename_by_func(func[0])
	# elegant_res = ''
	# seq = filename.split('/')[1]
	# elegant_res += 
	# open('my_result.txt','a').write()


def debug_print(msg):
	if debug:
		print msg

def write_rules():
	'''
	write the test rules to files
	'''
	global str_rules,func_rules
	str_rules = [r"/(etc|usr|var|proc|dev|home|root)",
r"(\.bash_history|\.bashrc|\.bash_profile|\.ssh|authorized_keys|rc\.d|cron\.d|\.conf|passwd)",
r"/tmp",
r"((void|int|long)\s*\(\*\))",
r"(( |\"|\'|\/|;)(wget|curl|mail)( |\"|\'))",
r"([0-9]{1,3}\.){3}[0-9]{1,3}",
r"((((?:_POST|_GET|_REQUEST|GLOBALS)\[(?:.*?)\]\(\$(?:_POST|_GET|_REQUEST|GLOBALS)))|(((?:exec|base64_decode|edoced_46esab|eval|eval_r|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source|assert)\s*?\(\$(?:_POST|_GET|_REQUEST|GLOBALS)))|(((?:eval|eval_r|execute|ExecuteGlobal)\s*?\(?request))|((write|exec)\(request\.getParameter)|(((?:eval|eval_r|execute|ExecuteGlobal).*?request))|(SaveAs\(\s*?Server\.MapPath\(\s*?Request))",
r"(disable_dynamic|AddType|x-httpd-php)",
r"(( |\"|\'|\/)evil|( |\"|\'|\/|@)eval|shellcode|HTTP/1\.[1|0]|\* \* \*|( |\"|\'|\/)grep)",
r"(#define\s*.*\s*(popen|system|exec|execl|execv|execve|execlp|execle|execvp))",
r"(( |\"|\'|\/|\.|;|\|)(chmod|chown|bash|cat|export|useradd)( |\"|\'))",
r"htons\((\d){2,5}\)|(\{((0x)?[0-9a-fA-F]{1,3},(\s)*){3}((0x)?[0-9a-fA-]{1,3})(\s)*\})",
r"((\\x[0-9a-fA-F]{2}){3})|(\{((0x)?[0-9a-fA-F]{1,3},(\s)*){4,}((0x)?[0-9a-fA-]{1,3})(\s)*\})|(#define _[0-9a-fA-F]{32})",
]
	func_rules = []
	open(str_rule_cfg,'w').write(json.dumps(str_rules))
	open(func_rule_cfg,'w').write(json.dumps(func_rules))


def load_rules():
	'''
	load the rules from file
	'''
	global func_rules,str_rules
	str_rules = json.loads(open(str_rule_cfg).read())
	func_rules = json.loads(open(func_rule_cfg).read())


def str_regex(filename,regex_pattern):
	match_lines = []
	content = open(filename).readlines()
	for i in range(len(content)):
		line_content = content[i]
		r = re.search(regex_pattern,line_content,re.IGNORECASE)
		if r:
			# line number starts from 1
			# tmp = "\n"
			tmp = ""
			tmp += "#"*15 +"\n"
			tmp +=  str(regex_pattern) +"\n"
			tmp += "#"*15 +"\n"
			tmp += filename + "\n"
			tmp += "#"*15 + "\n"
			tmp += str(i) + "\n"
			tmp += "#"*15 + "\n"
			tmp += search_m_func_api(i,filename) + "\n"
			tmp += "#"*15 + "\n"
			tmp += str(line_content) + "\n"
			tmp +=  "#"*15 + "\n\n"
			print tmp
			open('log.txt','a').write(tmp)
			match_lines.append(i+1)

	return match_lines


def handle_rules_string():
	'''
	handle function rules
	'''

	global str_rules,global_func_def

	str_regex_status = {}

	for i in range(len(str_rules)):
		rule = str_rules[i]
		for filename in global_func_def:
			match_lines = str_regex(filename,rule)
			for line in match_lines:
				function_name = search_m_func_api(line,filename)
				real_func_name = function_name + '@' + filename

				if not str_regex_status.has_key(real_func_name):
					str_regex_status[real_func_name] = [0] * len(str_rules)
				str_regex_status[real_func_name][i] = 1
	# print "#"*15
	# print str_regex_status
	# print "#"*15
	open('log.txt','a').write('\n')
	return str_regex_status


def substract_all_func():
	'''
	substract all functions from the global variable global_func_def
	'''
	global global_func_def
	all_func = []
	for filename in global_func_def:
		for i in range(len(global_func_def[filename])):
			func = global_func_def[filename][i]
			# if func[1] in all_func:
			# 	print '[!] ' + func[1] + " is duplicated"
			# 	# if a function name is dumplicated, add append the filename to that function
			# 	all_func.append(func[1] + '@' + filename[2:])
			# 	# update the function name in the global_func_def as well
			# 	#print global_func_def[filename][i]
			# 	global_func_def[filename][i][1] = func[1] + '@' + filename[2:]
			# else:
			all_func.append(func[1] + '@' + filename)

	all_func = list(set(all_func))
	return all_func
	

def list_c_files(file_directory):
	global filenames
	cmd = 'find ' + file_directory + ' -name "*.c" '
	res = os.popen(cmd).read()
	filenames = res.strip().split('\n')
	debug_print(filenames)
	return filenames

def search_m_func(function_def,line):
	'''
	try to find the mother function with the given line number of function/string
	'''
	#print function_def
	if not function_def:
		'''
		it seems that cflow cannot recognize the static function, so the funciton_def 
		may be null, in this case, we just ignore this situation
		'''
		return 'static_function_detected'

	last_function_name = 'this_is_error'
	for func in function_def:
		function_position,function_name = func
		function_position = function_position.split('@')[0]
		function_position = int(function_position)
		line = int(line)
		if function_position == line:
			# for most of the situation, it cann't be equal
			# sometimes it can
			# sys.exit('[!] are u kidding me?')
			return function_name
		elif function_position > line:
			# result find!
			debug_print(last_function_name)
			if last_function_name == 'this_is_error':
				pass
				#print function_def
				#print function_position,line
			return last_function_name
		else:
			# result not find, update last_function_name
			last_function_name = function_name
	debug_print(function_name)
	return function_name

def search_m_func_api(line,filename):
	'''
	we use global_func_def here, with the filename, we can call the function search_m_func
	with the right function_def
	'''
	global global_func_def
	function_def = global_func_def[filename]
	return search_m_func(function_def,line)

def find_filename_by_func(function_name):
	real_func_name,real_file_name = function_name.split('@')
	#for filename in global_func_def:
	for data in global_func_def[real_file_name]:
		if data[1] == real_func_name:
			return real_file_name
	return "no_such_function"

def reverse_indexes():
	'''
	indexes_2 = {'func_name@file_name':['popen','system']}
	'''
	indexes_2 = {}
	global indexes
	for index in indexes:
		for record in indexes[index]:
			final_func_name = record['m_func'] + '@' + record['filename']
			if not indexes_2.has_key(final_func_name):
				indexes_2[final_func_name] = []
			indexes_2[final_func_name].append(index)

	# remove the duplicate function
	for index in indexes_2:
		indexes_2[index] = list(set(indexes_2[index]))


	debug_print(indexes_2)
	return indexes_2

def replace_static(filename):
	'''
	this function is used to fix somebug in cflow, when it try to parse the static function,
	just replace the 'static ' to null
	'''
	content = open(filename).read().replace('static ','').replace("static\n",'')
	open(filename,'w').write(content)


def run_with_cflow(filename):
	'''
	The data structure to generated:
	function_call = [(1,main),(2,hello)]
	function_def = [(1,main),(2,hello)]
	indexes = {'popen':[{'filename':'1.c','line':'100','m_func':'main','content':'popen(xxxx)'}]}

	'''
	global indexes,indexes_2,global_func_def
	function_def = {}
	function_call = {}
	replace_static(filename)

	# clean old redefined record
	open('/tmp/redefined','w').write('')

	cmd = 'cflow --include _ -x ' + filename + ' 2>/tmp/redefined'
	res = os.popen(cmd).read()

	my_redefined = open('/tmp/redefined').read().split('\n')
	
	res = res.strip().split('\n')
	res += my_redefined

	i = -1
	for record in res:
		i += 1
		if '*' in record:
			tmp = record.split(' ')
			function_name,function_position = tmp[0],tmp[2].split(':')[1]
			function_position = str(function_position) + '@' + md5(function_name).hexdigest()[8:24]
			function_def[function_position]= function_name
			function_call[function_position]= function_name

		elif ' redefined' not in record and 'cflow:' not in record and  'missing ' not in record and record:

			tmp = record.split(' ')
			function_name,function_position = tmp[0],tmp[3].split(':')[1]

			# different function could be called in one line, so use function hash here
			function_position = str(function_position) + '@' + md5(function_name).hexdigest()[8:24] 

			function_call[function_position]= function_name
		elif 'redefined' in record:
			'''
				redefined function detected, update the position of the 
				function definition to the original one( this is boiled
				down to the usage of #if #else)
			'''
		
			tmp =  record.split(' ')
			tmp_2 = res[i+1].split(':')

			# the next data should not be handled again
			del res[i]

			old_function_position = tmp[0].split(':')[2]
			function_name,function_position = tmp[1].split('/')[0],tmp_2[2]
			

			function_position = str(function_position) + '@' + md5(function_name).hexdigest()[8:24]
			old_function_position = str(old_function_position) + '@' + md5(function_name).hexdigest()[8:24]

			'''
				delete the duplicate definition of one function
			'''
			if function_call.has_key(old_function_position):
				del function_call[old_function_position]
				del function_def[old_function_position]
				function_call[function_position] = function_name
				function_def[function_position]= function_name

			# if 'names' in filename:
			# 	print function_call
			#  	sys.exit()
			print 'redefined detected'
		elif record:
			print "unknown error: " + record
	
		
	
	function_def = sorted(function_def.items(),key = lambda x:int(x[0].split('@')[0]))
	function_call = sorted(function_call.items(),key = lambda x:int(x[0].split('@')[0]))

	
	# transform the tuples to lists
	function_def = map(list,function_def)
	function_call = map(list,function_call)
	debug_print(function_def)
	debug_print(function_call)

	# if 'pstree' in filename:
	# 		print function_def
	# 		sys.exit()
	for func in function_call:
		function_position,function_name = func
		function_position = function_position.split('@')[0]
		file_content = open(filename).readlines()
		offset_1 = (int(function_position) - int(content_offset)) if (int(function_position) - int(content_offset)) > 0  else 0
		offset_2 = int(function_position) + int(content_offset)
		content = file_content[offset_1:offset_2]
		# if function_name == 'getlogin' and 'pstree.c' in filename:
		# 	print 'ok'
		# 	sys.exit()

		m_func = search_m_func(function_def,function_position)
		function_info = {'filename':filename,'line':int(function_position),'m_func':m_func,}

		if not indexes.has_key(function_name):
			indexes[function_name] = []

		indexes[function_name].append(function_info)


	global_func_def[filename] = function_def



def run(folder_name):
	'''
	the argv[1] should be the folder to be scaned

	'''
	global indexes,indexes_2,scores,global_func_def

	# clear the global variables
	scores = {}
	indexes = {}
	indexes_2 = {}
	global_func_def = {}

	if not os.path.exists('cache'):
		os.system('mkdir cache')

	cache_path = 'cache/%s' % folder_name.replace('.','').replace('/','')
	cache_path_reverse =  cache_path + '_re'
	global_def_path = cache_path + '_func_def' 

	'''
		the records of all the functions, including fuction name/ mother function/function position
	'''

	if not os.path.exists(cache_path):
		filenames = list_c_files(folder_name)
		for filename in filenames:
			run_with_cflow(filename)
		open(cache_path,'w').write(json.dumps(indexes))
		open(global_def_path,'w').write(json.dumps(global_func_def))
	else:
		debug_print('[*] loading from old cache')
		indexes = json.loads(open(cache_path).read())
		global_func_def = json.loads(open(global_def_path).read())	
		debug_print(indexes)


	'''
		the records of subfunctions for each function, if exists already,
		then load from file
	'''

	if not os.path.exists(cache_path_reverse):
		indexes_2 = reverse_indexes()
		open(cache_path_reverse,'w').write(json.dumps(indexes_2))
	else:
		debug_print('[*] loading from old reverse cache')
		indexes_2 = json.loads(open(cache_path_reverse).read())
		debug_print(indexes_2)

	# print indexes
	# print 'closedir@./p_058/src/readdir.c' in indexes_2
	# sys.exit()

	'''
	real handle here
	'''
	str_regex_status = handle_rules_string()
	Main_deal(substract_all_func(),indexes_2,str_regex_status)


if __name__ == '__main__':
	os.chdir('./runtime')
	write_rules()
	load_rules()
	#test()
	for i in range(0,300):
		if os.path.exists('./p_%s'%(str(i).rjust(3,'0'))):
			run('./p_%s'%(str(i).rjust(3,'0')))
			print "\n\n"
		if os.path.exists('./mp_%s'%(str(i).rjust(3,'0'))):
			run('./p_%s'%(str(i).rjust(3,'0')))
			print "\n\n"
			







