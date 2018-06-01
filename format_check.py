# -*- coding: utf-8 -*-
''' format_check: 检查提交的答案是否符合格式要求.
    usage: python format_check.py <answer_file_path> （python 2.7）
    答案的格式要求：
        1. 每一场比赛，每支参赛队伍的所有题目都在一个压缩包内，压缩包的格式为<比赛类型>-<队伍token>-<题目压缩包md5>.zip
        2. 将上述压缩包解压后会得到多个文件夹，每个文件夹为一个源码包，也就是一道赛题。
        3. 提交答案时，所有赛题的答案需要统一在同一个txt文件内提交，注意：直接将答案的txt文件上传，不要进行压缩。
        4. 答案文件中每一行代表一道赛题的答案，格式为：<赛题名称>:<是否存在恶意行为>,<恶意行为所在文件的相对路径>,<恶意行为所在的函数名>
           <赛题名称>: 赛题文件夹的名称
           <是否存在恶意行为>: YES表示存在恶意行为，NO表示不存在恶意行为，不区分大小写。
           <恶意行为所在文件的相对路径>: 恶意行为所在文件的相对路径，相对于赛题文件夹的路径。如果不存在恶意行为，这一项不填。
                例如：赛题文件夹的绝对路径为 /home/user1/case1/
                     恶意行为所在文件的绝对路径为 /home/user1/case1/src/utils/utility.c
                     则这一项需要填写：case1/src/utils/utility.c 注意：不以 '/' 开头
           <恶意行为所在函数名>: 恶意行为所在的函数名，不包含函数返回类型和参数；如果不存在恶意行为，这一项不填。
                例如：函数为 static void function1(int a, int b, char *) const
                     则这一项需要填：function1 即可
        5. 例：
            下载得到的压缩包为 test-token-MD5.zip，解压后得到四个赛题文件夹：case1, case2, case3和case4
            提交的答案文件为answer.txt，格式如下（答案中无需包含下面的注释部分）：
            case1:YES,case1/src/utils/utility.c,function1  // 有恶意行为
            case2:NO,,                                      // 无恶意行为
            case3:YES,case3/src/main.c,convert             // 有恶意行为
            case4:NO,,                                      // 无恶意行为

        6. 注：比赛过程中允许提交多次结果，最多20次，比赛结束后将统一计算得分，以最后一次提交答案为准

'''
import os
import sys

if len(sys.argv) != 2:
    print 'ERROR: please specify one answer file'
    print 'usage: python format_check.py <answer_file_path>'
    exit(1)

answer_path = os.path.abspath(sys.argv[1])
if not os.path.exists(answer_path):
    print '%s(%s) does not exist.'%(sys.argv[1], answer_path)
    exit(1)

success = True
answer_file = open(answer_path, 'r')
for line in answer_file:
    line = line.strip()
    try:
        case_name, answers = line.split(':')
        answer, code_path, function = answers.split(',')
    except Exception:
        success = False
        print '[ERROR] illegal format: %s'%line
        print '每一行的答案格式为：<赛题名称>:<是否存在恶意行为>,<恶意行为所在文件的相对路径>,<恶意行为所在的函数名>'
        print ''
        continue

    if answer.lower() not in ['yes', 'no']:
        success = False
        print '[ERROR] illegal format: %s'%line
        print '<是否存在恶意行为>字段需要填YES或NO，不区分大小写'
        print ''
        continue

    if answer.lower() == 'yes' and not code_path.startswith('%s/'%case_name):
        success = False
        print '[ERROR] illegal format: %s'%line
        print '<恶意行为所在文件的相对路径>字段需要时恶意文件相对于代码包的相对路径。'
        print '     例如：赛题文件夹的绝对路径为 /home/user1/case1/'
        print '     恶意行为所在文件的绝对路径为 /home/user1/case1/src/utils/utility.c'
        print '     则这一项需要填写：case1/src/utils/utility.c'
        print ''
        continue

if success is False:
    print '答案不符合格式要求，请按照上述描述修改后上传。详细的格式要求见官网或者format_check.py中注释。'
    exit(1)
else:
    print '答案满足格式要求，可以上传。多次上传以最后一次上传结果为准。'
    exit(0)
