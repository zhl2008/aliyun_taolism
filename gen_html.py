# -*- coding: utf-8 -*
import re

INPUT_FILE = './runtime/log.txt'

strs_file = open(INPUT_FILE,'rb')
html_file = open('./out.html','wb')
headers = '''
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Read Text</title>
	<link href="./css/bootstrap.min.css" rel="stylesheet">
	<script src="./js/jquery.min.js"></script>
	<script src="./js/bootstrap.min.js"></script>
	<script src="./js/clipboard.min.js"></script>
	
</head>
<body>
	<script type="text/javascript">
		var clipboard = new ClipboardJS('.btn');
		clipboard.on('success', function(e) {
			console.log(e);
		});
		clipboard.on('error', function(e) {
			console.log(e);
		});
	</script>
	<div class="panel panel-info">

'''
html_file.write(headers)

strs_rd = strs_file.read()
strs_rd = strs_rd.split('\n\n\n')
counts = -1

MIN_P = 0
MAX_P = len(strs_rd)

for i in xrange(MIN_P,MAX_P):
	if i==95:
		continue
		
	tmp = '''<div class="panel-heading">
			<h3 class="panel-title">工程 : P_'''+re.findall('\./p_(.*?)/',strs_rd[i])[0]+'''</h3>

			</div>
			<div class="panel-body">
			'''
	html_file.write(tmp)
	func = strs_rd[i].split('\n\n')
	for j in xrange(0,len(func)):
		contents = func[j].split('###############')
		if len(contents)>=6:
			counts += 1
			tmp = '''<div>
				<p>字符串："'''+contents[5].strip()+'''<a data-toggle="collapse" data-parent="#accordion" href="#collapse'''+str(counts)+'''" aria-expanded="false" class="collapsed">查看详情</a>
				<button class="btn" data-clipboard-text="yes	'''+contents[2].strip()[2:]+'	'+contents[4].strip()
			tmp += '''">
					复制结果
				</button>
				<div id="collapse'''+str(counts)+'''" class="panel-collapse collapse" aria-expanded="false" style="height: 0px;">
					<div class="alert alert-info">文件路径 : <a href="http://10.138.66.217/f.php?f=runtime/'''+contents[2].strip()[2:]+'" target="_blank" >'+contents[2].strip()+'</a>'
			tmp +='''<br>
						匹配规则 : '''+contents[1].strip()
			tmp +='''<br>
						匹配行数 : '''+contents[3].strip()
			tmp +='''<br>
						函数名 : '''+contents[4].strip()
			tmp +='''<br>
						匹配内容 : '''+contents[5].strip()+'''<br>
					</div>
				</div>
			</div>'''
			html_file.write(tmp)
			#print contents[1].strip()
		else:
			pass
	tmp = '''
	</div>
	'''
	html_file.write(tmp)


tails = '''
</div>
	
</body>
</html>

'''
html_file.write(tails)
