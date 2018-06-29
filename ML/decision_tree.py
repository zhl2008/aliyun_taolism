
# coding: utf-8

# In[1]:


import numpy as np
import matplotlib.pyplot as plt
from sklearn import linear_model
from random import randint
from sklearn.utils import shuffle
from sklearn.externals import joblib
from sklearn import tree
from IPython.display import Image  
import pydotplus 


# In[2]:


a = open('malicious.txt').readlines()


# In[3]:


b = open('func_status.txt').readlines()


# In[4]:


tmp = []
for entry in b:
    if entry in a:
        tmp.append(entry.strip() + ",1")
    else:
        tmp.append(entry.strip() + ",0")
        


# In[5]:


record_x = []
record_y = []
malicious_x = []
for entry in tmp:
    if '0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0' not in entry:
        t = [int(i) for i in entry.split(',')[3:-1]]
        record_x.append(t)
        if int(entry.split(',')[-1]) == 1:
            record_y.append(1)
            malicious_x.append([int(i) for i in entry.split(',')[3:-1]])
        else:
            record_y.append(0)


# In[6]:


# expand the original record with malicious data
for i in range(10):
    record_x += malicious_x
    record_y += [1 for i in range(len(malicious_x))]


# In[7]:


'''
    we try to generate some of the malicious data, to ensure that: the amount of  positive 
    instances and that of negative instance should be equivalent; 
    
    
  
'''
def random_data(rows,score):
    my_score = 30
    tmp = [0 for i in range(len(record_x[0]))]
    for row in rows:
        tmp[row] = randint(1,5)
    
    
    # if score=0, do not genrate the 1 in other row
    if score==1:
        for i in range(len(record_x[0])):
            # add some extra random features
            if tmp[i] == 0 and randint(1,5)%5==0:
                tmp[i] = 1
    
    
    return tmp + [score]

def record_append(rows,score,number):
    global record_x,record_y
    for i in range(number):
        data = random_data(rows,score)
        record_x.append(data[:-1])
        record_y.append(data[-1])

def get_rand(array):
    return array[randint(0,len(array)-1)]
        
def generate_data(my_type):

    read = [0,4]                                   # read file / get sensetive info
    sensetive_info = [2,6,7,8,9,13,14,18]          # sensetive dir/file/systeminfo
    write = [1,4,15]                               # write file/system config/webshell
    out = [3,4,11,12,15,17,18]                     # output to socket/ip/network/webshell/tmp file
    other = [4,5,15,16,18,19]                      # pick it by random
    
    my_choice = []
    
    # malicious
    if my_type == 1:
        my_choice = map(get_rand,[read,sensetive_info,write])   #read sensetive info and write
    elif my_type == 2:
        my_choice = map(get_rand,[read,sensetive_info,out])     #read sensetive info and sendout
    elif my_type == 3:
        my_choice = map(get_rand,[write,sensetive_info])        # write sensetive info 
    elif my_type == 4:
        my_choice = map(get_rand,[write,sensetive_info,out])    # recv the info and write to sensetive 
    elif my_type == 5:
        my_choice = map(get_rand,[read,out])                    #read sensetive and out
    
    # not malicious
    elif my_type == 6:                                          
        my_choice = map(get_rand,[read,sensetive_info])
    elif my_type == 7:
        my_choice = map(get_rand,[write])
    elif my_type == 8:
        my_choice = map(get_rand,[out])
    elif my_type == 9:
        my_choice = map(get_rand,[read])
    elif my_type == 10:
        my_choice = map(get_rand,[sensetive_info])
        
        
        
    my_choice = set(my_choice)
    if my_type<=5 and len(my_choice) == 1 and 18 not in my_choice:
        # do it again
        generate_data(my_type)
        return
    if my_type > 5:
        for i in range(20):
            record_append(my_choice,1,10) 
    else:
        for i in range(10):
            record_append(my_choice,0,10)
    

# generate 2000 entries of malicious
generate_data(1)
generate_data(1)
generate_data(2)
generate_data(2)
generate_data(3)
generate_data(3)
generate_data(4)
generate_data(4)
generate_data(5)
generate_data(5)

# generate 500 entries of non-malicious
generate_data(6)
generate_data(7)
generate_data(8)
generate_data(9)
generate_data(10)         


# In[8]:


record_x = np.array(record_x)
record_y = np.array([int(i) for i in record_y])
malicious_x = np.array(malicious_x)
record_x,record_y = shuffle(record_x,record_y)


# In[9]:


open('record.txt','w').write('')
for i in range(len(record_x)):
    record = ','.join([str(j) for j in record_x[i]]) + ',' + str(record_y[i])
    open('record.txt','a').write(record+"\n")


# In[10]:


# test data set
train_x = record_x[:7000]
train_y = record_y[:7000]

# train data set
test_x = record_x[7000:]
test_y = record_y[7000:]


# In[11]:


clt = tree.DecisionTreeClassifier(splitter='best',max_depth=7,min_samples_leaf=5,class_weight={0:0.18,1:0.82})
clt.fit(train_x,train_y)
predict_y= clt.predict(test_x)


# In[12]:


true_accept = 0
true_reject = 0
false_accept = 0
false_reject = 0

true_total = len([y for y in test_y if y==1])
false_total = len([y for y in test_y if y==0])

total = len(predict_y)
for i in range(total):
    if predict_y[i] == 1 and test_y[i] == 1:
        true_accept += 1
    if predict_y[i] == 1 and test_y[i] == 0:
        false_accept += 1
    if predict_y[i] == 0 and test_y[i] == 0:
        true_reject += 1
    if predict_y[i] == 0 and test_y[i] == 1:
        false_reject += 1
        
print('TAR: %f' %(true_accept*100/true_total))
print('FRR: %f' %(false_reject*100/true_total))
print('TRR: %f' %(true_reject*100/false_total))
print('FAR: %f' %(false_accept*100/false_total))
        


# In[13]:


a = open('malicious_3.txt').readlines()
b = open('func_status_3.txt').readlines()
tmp = []
for entry in b:
    if entry in a:
        tmp.append(entry.strip() + ",1")
    else:
        tmp.append(entry.strip() + ",0")
new_x = []
new_y = []
new_malicious_x = []
for entry in tmp:
    if '0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0' not in entry:
        t = [int(i) for i in entry.split(',')[3:-1]]
        new_x.append(t)
        if int(entry.split(',')[-1]) == 1:
            new_y.append(1)
            new_malicious_x.append([int(i) for i in entry.split(',')[3:-1]])
        else:
            new_y.append(0)
            
new_x = np.array(new_x)
new_y = np.array([int(i) for i in new_y])
new_malicious_x = np.array(new_malicious_x)
new_x,new_y = shuffle(new_x,new_y)
open('record_predict.txt','w').write('')
for i in range(len(new_x)):
    record = ','.join([str(j) for j in new_x[i]]) + ',' + str(new_y[i])
    open('record_predict.txt','a').write(record+"\n")


# In[14]:


new_predict_y = clt.predict(new_x)


# In[15]:


true_accept = 0
true_reject = 0
false_accept = 0
false_reject = 0

true_total = len([y for y in new_y if y==1])
false_total = len([y for y in new_y if y==0])

total = len(new_predict_y)
for i in range(total):
    if new_predict_y[i] == 1 and new_y[i] == 1:
        true_accept += 1
    if new_predict_y[i] == 1 and new_y[i] == 0:
        false_accept += 1
    if new_predict_y[i] == 0 and new_y[i] == 0:
        true_reject += 1
    if new_predict_y[i] == 0 and new_y[i] == 1:
        false_reject += 1

print('TAR: %f' %(true_accept*100/true_total))
print('FRR: %f' %(false_reject*100/true_total))
print('TRR: %f' %(true_reject*100/false_total))
print('FAR: %f' %(false_accept*100/false_total))


        


# In[16]:


dot_data = tree.export_graphviz(clt, out_file=None, 
                         feature_names=['read func','write func','keyboard func','socket func','cmd func','file&env mani func','info func','directory str','file str','tmp str','func call str','network str','ip/port str','webshell str', 'ad webshell str','cmd str','system mani str','confused IP str','confused data str','evil str'],  
                         class_names=['good','bad'],  
                         filled=True, rounded=True,  
                         special_characters=True)  
graph = pydotplus.graph_from_dot_data(dot_data)  
Image(graph.create_png())


# In[ ]:


joblib.dump(clt,'model.txt')


