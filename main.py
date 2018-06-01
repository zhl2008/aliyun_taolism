#!/usr/bin/env python

import os
import sys
import json
import re


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

	Mod_funcs = [["read", "fread", "fgetc", "fgets"],
	["write","fwrite", "fputc", "fputs", "fprintf"],
	["tcgetattr"],
	["send", "recv"],
	["popen","system","exec","execl","execv","execve","execlp","execle","execvp"],
	["ftruncate", "chmod"]]

	func_state=[0 for i in xrange(0,len(Mod_funcs))]

	for i in xrange(0,len(Mod_funcs)):
		if len(set(Mod_funcs[i])&set(sub_funcs))>0:
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
			if (strs_dict.has_key(funcs)):
				F[funcs] = Cacu_value(func_state[funcs],strs_dict[funcs])
			else:
				F[funcs] = Cacu_value(func_state[funcs],[0 for i in xrange(11)])

	result = sorted(F.items(),key=lambda x:int(x[1]),reverse=True)[0:3]

	for func in result:
		file_name = find_filename_by_func(func[0])
		res = ''
		res += "File_name :%s\n" % file_name
		res += "Func name :%s\n" % func[0]
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
	str_rules = ["(.*/(etc|usr|var|proc|dev).*)",
"(.*(\.bash_history|\.bashrc|\.ssh|authorized_keys|rc\.d|cron\.d|\.conf|passwd).*)",
"/tmp",
"void\(\*\)\(\)",
"(.*( |\"|\'|\/)(wget|curl|mail)( |\"|\').*)",
"((.*([0-9]{1,3}\.){3}[0-9]{1,3}.*)|(.*[\"].*([\w]+\.)+[\w]{2,3}[\"| .*\"|;.*\"].*)|(.*[\'].*([\w]+\.)+[\w]{2,3}[\'| .*\'|;.*\'].*))",
"((((?:_POST|_GET|_REQUEST|GLOBALS)\[(?:.*?)\]\(\$(?:_POST|_GET|_REQUEST|GLOBALS)))|(((?:exec|base64_decode|edoced_46esab|eval|eval_r|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source|assert)\s*?\(\$(?:_POST|_GET|_REQUEST|GLOBALS)))|(((?:eval|eval_r|execute|ExecuteGlobal)\s*?\(?request))|((write|exec)\(request\.getParameter)|(((?:eval|eval_r|execute|ExecuteGlobal).*?request))|(SaveAs\(\s*?Server\.MapPath\(\s*?Request))",
"(.*(disable_dynamic|AddType|x-httpd-php).*)",
"(.*(( |\"|\'|\/)evil|( |\"|\'|\/|@)eval|shellcode|HTTP/1\.[1|0]|\* \* \*|( |\"|\'|\/)grep).*)",
"(#define\s*.*\s*(popen|system|exec|execl|execv|execve|execlp|execle|execvp))",
"(.*( |\"|\'|\/)(chmod|chown|bash|cat)( |\"|\').*)"]
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
		r = re.search(regex_pattern,line_content)
		if r:
			# line number starts from 1
			tmp = "\n"
			tmp += "#"*15 +"\n"
			tmp +=  str(regex_pattern) +"\n"
			tmp += "#"*15 +"\n"
			tmp += filename + "\n"
			tmp += "#"*15 + "\n"
			tmp += str(r.group()) + "\n"
			tmp +=  "#"*15 + "\n"
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
				#print filename,line,function_name
				if not str_regex_status.has_key(function_name):
					str_regex_status[function_name] = [0] * len(str_rules)
				str_regex_status[function_name][i] = 1
	# print "#"*15
	# print str_regex_status
	# print "#"*15
	return str_regex_status


def return_to_core():
	pass

def substract_all_func():
	'''
	substract all functions from the global variable global_func_def, to be compatible 
	to the code written by leecraso
	'''
	global global_func_def
	all_func = []
	for filename in global_func_def:
		for func in global_func_def[filename]:
			all_func.append(func[1])
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
	for filename in global_func_def:
		for data in global_func_def[filename]:
			if data[1] == function_name:
				return filename
	return "no_such_function"

def reverse_indexes():
	'''
	indexes_2 = {'_aa':['popen','system']}
	'''
	indexes_2 = {}
	global indexes
	for index in indexes:
		for record in indexes[index]:
			if not indexes_2.has_key(record['m_func']):
				indexes_2[record['m_func']] = []
			indexes_2[record['m_func']].append(index)

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
	content = open(filename).read().replace('static ','')
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

	cmd = 'cflow --include _ -x ' + filename
	res = os.popen(cmd).read()
	res = res.strip().split('\n')

	for record in res:
		if '*' in record:
			tmp = record.split(' ')
			function_name,function_position = tmp[0],tmp[2].split(':')[1]
			function_def[function_position]= function_name
			function_call[function_position]= function_name
		elif record:
			tmp = record.split(' ')
			function_name,function_position = tmp[0],tmp[3].split(':')[1]
			function_call[function_position]= function_name

	function_def = sorted(function_def.items(),key = lambda x:int(x[0]))
	function_call = sorted(function_call.items(),key = lambda x:int(x[0]))	
	debug_print(function_def)
	debug_print(function_call)



	for func in function_call:
		function_position,function_name = func
		file_content = open(filename).readlines()
		offset_1 = (int(function_position) - int(content_offset)) if (int(function_position) - int(content_offset)) > 0  else 0
		offset_2 = int(function_position) + int(content_offset)
		content = file_content[offset_1:offset_2]

		m_func = search_m_func(function_def,function_position)
		function_info = {'filename':filename,'line':int(function_position),'m_func':m_func,}#'content':content}
		if not indexes.has_key(function_name):
			indexes[function_name] = []
		indexes[function_name].append(function_info)

	#print '############'
	#print indexes
	#print '############'

	global_func_def[filename] = function_def
	#debug_print(indexes)
	#debug_print(res)


def test():

	list_c_files('../p_56')
	run_with_cflow('../p_56/example.c')
	run('../p_56')
	find_filename_by_func('_ddc88cd9fb57f544dde77d08bd39e6ee')
	print substract_all_func()
	print str_regex('../p_56/example.c','include')
	exit()



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

	# print indexes
	if not os.path.exists(cache_path_reverse):
		indexes_2 = reverse_indexes()
		open(cache_path_reverse,'w').write(json.dumps(indexes_2))
	else:
		debug_print('[*] loading from old reverse cache')
		indexes_2 = json.loads(open(cache_path_reverse).read())
		debug_print(indexes_2)

	str_regex_status = handle_rules_string()
	# print '##########################'
	# print substract_all_func()
	# print '##########################'
	# print indexes_2
	# print '##########################'
	# print str_regex_status
	# print '##########################'
	Main_deal(substract_all_func(),indexes_2,str_regex_status)


if __name__ == '__main__':
	os.chdir('./runtime')
	write_rules()
	load_rules()
	#test()
	for i in range(1,229):
		if os.path.exists('./p_%s'%(str(i).rjust(3,'0'))):
			run('./p_%s'%(str(i).rjust(3,'0')))
			print "\n\n"
			







