#!/usr/bin/env python

real_res = open('./runtime/res_2.txt').readlines()
my_res = open('./runtime/submit_tmp.txt').readlines()

assert len(real_res) == len(my_res)

count = 0
for i in range(len(real_res)):
    if real_res[i].strip().replace(':',',') != my_res[i].strip():
        count += 1

print count,len(real_res)
