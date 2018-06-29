
# coding: utf-8

# In[180]:


import numpy as np
import matplotlib.pyplot as plt
from sklearn import linear_model
from random import randint
from sklearn.utils import shuffle
from sklearn.externals import joblib


# In[181]:


a = open('malicious.txt').readlines()


# In[182]:


b = open('func_status.txt').readlines()


# In[183]:


tmp = []
for entry in b:
    if entry in a:
        tmp.append(entry.strip() + ",1")
    else:
        tmp.append(entry.strip() + ",0")
        


# In[184]:


np.sum([1,2,3])


# In[185]:


record_x = []
record_y = []
malicious_x = []
for entry in tmp:
    if '0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0' not in entry:
        t = [int(i) for i in entry.split(',')[3:-1]]
        record_x.append(t)
        if int(entry.split(',')[-1]) == 1:
            record_y.append(100)
        else:
            record_y.append(int(np.sum(t) * 5))
            
        if int(entry.split(',')[-1]) == 1:
            malicious_x.append([int(i) for i in entry.split(',')[3:-1]])
    
    


# In[186]:


# expand the original record with malicious data
for i in range(10):
    record_x += malicious_x
    record_y += [100 for i in range(len(malicious_x))]


# In[187]:


'''
    we try to generate some of the malicious data, to ensure that: the amount of  positive 
    instances and that of negative instance should be equivalent; 
    the rules for each row are: 
    
    0-file-read/1-file-write/2-keyboard-record/3-socket/4-linux-shell/5-system-modify/
    6-system-info/7-system-modify-2
    
    8-sensetive-dir/9-sensetive-file/10-tmp-file/11-function-call/12-network-transfer/13-ip-address/14-web-shell/
    15-web-shell-2/16-evil-string/17-linux-shell/18-linux-sensetive-cmd/19-ip-and-port/20-confused/
'''
def random_data(rows,score):
    my_score = 30
    tmp = [0 for i in range(len(record_x[0]))]
    for row in rows:
        tmp[row] = randint(1,5)
        my_score += tmp[row] * 2
    
    # if score=0, do not genrate the 1 in other row
    if score==1:
        for i in range(len(record_x[0])):
            # add some extra random features
            if tmp[i] == 0 and randint(1,5)%5==0:
                tmp[i] = 1
                my_score += 1 * 2
    
    return tmp + [my_score]

def record_append(rows,score,number):
    global record_x,record_y
    for i in range(number):
        data = random_data(rows,score)
        record_x.append(data[:-1])
        record_y.append(data[-1])

def get_rand(array):
    return array[randint(0,len(array)-1)]
        
def generate_data(my_type):

    read = [0,4,11,20]                     # read file / get sensetive info
    sensetive_info = [2,6,8,9,20]          # sensetive dir/file/systeminfo
    write = [1,4,5,7,11,18,20]             # write file/system config/webshell
    out = [3,4,10,12,13,14,15,17,19,20]    # output to socket/ip/network/webshell/tmp file
    other = [5,7,16]                       # pick it by random
    
    my_choice = []
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
        
    my_choice = set(my_choice)
    if len(my_choice) == 1 and 20 not in my_choice:
        # do it again
        generate_data(my_type)
        return
    for i in range(20):
        record_append(my_choice,1,10) 
    


generate_data(1)
generate_data(1)
generate_data(2)
generate_data(2)
generate_data(3)
generate_data(4)
generate_data(5)
generate_data(5)
        
        
    


            


# In[188]:


record_x = np.array(record_x)
record_y = np.array([int(i) for i in record_y])
malicious_x = np.array(malicious_x)
record_x,record_y = shuffle(record_x,record_y)


# In[189]:


open('record.txt','w').write('')
for i in range(len(record_x)):
    record = ','.join([str(j) for j in record_x[i]]) + ',' + str(record_y[i])
    open('record.txt','a').write(record+"\n")


# In[190]:


len(malicious_x)


# In[191]:


print(len(record_y))


# In[192]:


logreg = linear_model.LogisticRegression()


# In[193]:


logreg.fit(record_x, record_y)


# In[194]:


logreg.predict([[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]])


# In[195]:


logreg.predict([[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]])


# In[196]:


logreg.predict([[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2]])


# In[197]:


logreg.predict([[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,4]])


# In[198]:


logreg.predict(record_x)


# In[199]:


res = logreg.predict(malicious_x)


# In[200]:


match = 0
for i in range(len(res)):
    if res[i] > 70:
        match += 1
    


# In[201]:


match


# In[202]:


logreg.predict(record_x)


# In[203]:


res =logreg.predict(record_x) 
print(res[0])


# In[204]:


match = 0
for i in range(len(record_x)):
    if (res[i]>0 and record_y[i]>0) or (res[i]<30 and record_y[i]==0):
        match += 1 


# In[205]:


match


# In[179]:


print(list(res))


# In[206]:


joblib.dump(logreg,'model.txt')

