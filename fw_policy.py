import sys, os, copy




class Error_Message:
    def __init__(self, x, y):
        self.counter=x
        self.message=y

class Rule:
    """
    number starts with ZERO
    0->deny
    1->permit
    """
    number=0
    action="deny"
    protocol="tcp"
    src_addr=[0,0,0,0]
    src_port=0
    src_port_operator=""
    dst_addr=[0,0,0,0]
    dst_port=0
    dst_port_operator=""
    dynamic=""
    time_out=0
    established=False
    precedence=0
    tos=0
    log=False
    log_input=False
    time_range=""
    state="undetermined"
    
    def set_number(self, num):
        self.number=num
        return True

    def set_dynamic(self, dyn, index):
        if (dyn=="dynamic"):
            self.dunamic = dyn
            index[0]+=2
            return True
        return False

    def set_time_out(set, time, index):
        if (time=="timeout"):
            if time.isdigit():
                self.time_out=int(time)
                index[0]+=2;
            else:
                return False
        return True

    def set_action(self, act, index):
        #print "act=", act
        if ((act=="permit")|(act=="deny")):
            self.action=act
            index[0]+=1
            print "index=", index
            return True
        else:
            return False
        
    def set_protocol(self, proto, index):
        #print "protocol=", proto
        if ((proto=="tcp")|(proto=="udp")|(proto=="icmp")|(proto=="ip")):
            self.protocol=proto
            index[0]+=1
            return True
        else:
            return False

    def set_src_addr(self, addr, index):
        #print "address=", addr
        if (len(addr)==4):
            for n in xrange(0,4):
                if (addr[n].isdigit()):
                    #rule.src_addr[n]=temp_addr[n]
                    pass
                else:
                    return False
            index[0]+=1
            self.src_addr=list(addr)
            for x in xrange(len(self.src_addr)):
                self.src_addr[x]=int(self.src_addr[x])
        else:
            return False
        return True

    def set_src_mask(self, mask, index):
        #print "mask=", mask
        if (len(mask)==4):
            index[0]+=1
            for n in xrange (0,4):
                if (mask[n].isdigit()):
                    self.src_addr[n]=self.src_addr[n]&(255-int(mask[n]))
                else:
                    return False
        else:
            return False
        return True

    def set_src_port(self, port, index):
        #print "src_port=", port[index[0]]
        verif=set(["any", "eq", "gt", "host", "lt", "neq", "range"] ) #definition between eq and host
        print "set=", verif
        i=index[0]
        self.src_port_operator=0
        if not (port[i].isdigit()):
            if (port[i] in verif):
                self.src_port_operator=port[i]
                index[0]+=1
                if (self.src_port_operator=="range"):# zdes' dolghen byt massiv
                    if ((port[i].isdigit())&(int(port[i])>=0)&(int(port[i])<65536)&(port[i+1].isdigit())&(int(port[i+1])>=0)&(int(port[i+1])<65536)):
                        self.src_port=list(port[i],port[i+1])
                        index[0]+=2
                    else:
                        return False    
                elif (not (self.src_port_operator=="any"))&(port[i].isdigit()):    
                    if (int(port[i])>=0)&(int(port[i])<65536):
                        self.src_port=int(port[i])
                        index[0]+=1
                    else:
                        return False
            else:
                return False
        else:
            self.src_port=int(port[i])
            index[0]+=1
            return True
        return True

    def set_dst_addr(self, addr, index):
        #print "dst_addr=", addr, index
        if (len(addr)==4):
            for n in xrange(0,4):
                if (addr[n].isdigit()):
                    #rule.src_addr[n]=temp_addr[n]
                    pass
                else:
                    return False
            index[0]+=1
            self.dst_addr=list(addr)
            for x in xrange(len(self.dst_addr)):
                self.dst_addr[x]=int(self.dst_addr[x])
        else:
            return False
        return True

    def set_dst_mask(self, mask, index):
        if (len(mask)==4):
            index[0]+=1
            for n in xrange (0,4):
                if (mask[n].isdigit()):
                    self.dst_addr[n]=self.dst_addr[n]&(255-int(mask[n]))
                else:
                    return False
        else:
            return False
        return True

    def set_dst_port(self, port, index):
        i=index[0]
        verif=set(["any", "eq", "gt", "host", "lt", "neq", "range"])
        if not (port[i].isdigit()):
            if (port[i] in verif):
                
                self.dst_port_operator=port[i]
                index[0]+=1
                if (self.dst_port_operator=="range"):# zdes' dolghen byt massiv
                    if ((port[i].isdigit())&(int(port[i])>=0)&(int(port[i])<65536)&(port[i+1].isdigit())&(int(port[i+1])>=0)&(int(port[i+1])<65536)):
                        self.dst_port=list(port[i],port[i+1])
                        index[0]+=2
                    else:
                        return False    
                elif (not (self.dst_port_operator=="any"))&(port[i].isdigit()):    
                    if (int(port[i])>=0)&(int(port[i])<65536):
                        self.dst_port=int(port[i])
                        index[0]+=1
                    else:
                        return False
            else:
                return False
        else:
            self.dst_port=int(port[i])
            index[0]+=1
        return True

    def set_precedence(self, prec, index):
        if(prec=="precedence"):
            self.precedence=int(prec[index]+1)
            index[0]+=2

    def set_tos(self, tos, index):
        i=index[0]
        if(tos[i]=="tos"):
            self.tos=int(tos[i]+1)
            index[0]+=2

    def set_log(self, log, index):
        if(log=="log"):
            self.log=True
            index[0]+=1
        elif(log=="log-input"):
            rule.log_input=True
            index[0]+=1

    def set_time_range(self, time, index):
        i=index[0]
        if(time[i]=="time-range"):
            self.time_range=copy.deepcopy(time[i+1]) #need deep copy!!!
            index[0]+=2

            
def addr_subset(addr_1, addr_2): #addr1 is subset of addr2
    """
    returns 1 if addr_1 is subset of addr_2
            2 if addr_1==addr_2
            0 else
    """
    if (addr_1==addr_2):
        return 2
    else:
        for i in xrange(4):
            if not ((addr_2[i]&addr_1[i])==addr_2[i]):
                return 0
        return 1

def src_port_subset(rule1, rule2): #rule1 is subset of rule2
    """
    returns 1 if rule1 is subset of rule2
            2 if rule1==rule2
            3 if Needs to be split ??????
            0 else
    """
    min_port_1=0
    min_port_2=0
    max_port_1=0
    max_port_2=0
    if (rule1.src_port_operator=="")&(rule2.src_port_operator==""):
        if (rule1.src_port==rule2.src_port):
            return 2
        else:
            return 0
    if (rule1.src_port_operator!=""):
        if (rule1.src_port_operator=="any"):
            min_port_1=0
            max_port_1=65535
        elif (rule1.src_port_operator=="eq"):
            min_port_1=rule1.src_port
            max_port_1=rule1.src_port
        elif (rule1.src_port_operator=="gt"):
            min_port_1=rule1.src_port
            max_port_1=65535
        elif (rule1.src_port_operator=="host"):
            min_port_1=rule1.src_port
            max_port_1=rule1.src_port
        elif (rule1.src_port_operator=="lt"):
            min_port_1=0
            max_port_1=rule1.src_port
        elif (rule1.src_port_operator=="neq"):
            pass
        elif (rule1.src_port_operator=="range"):
            min_port_1=rule1.src_port[0]
            max_port_1=rule1.src_port[1]
    else:
        min_port_1=rule1.src_port
        max_port_1=rule1.src_port
        

    if (rule2.src_port_operator!=""):
        if (rule2.src_port_operator=="any"):
            min_port_2=0
            max_port_2=65535
        elif (rule2.src_port_operator=="eq"):
            min_port_2=rule2.src_port
            max_port_2=rule1.src_port
        elif (rule2.src_port_operator=="gt"):
            min_port_2=rule2.src_port
            max_port_2=65535
        elif (rule2.src_port_operator=="host"):
            min_port_2=rule2.src_port
            max_port_2=rule1.src_port
        elif (rule2.src_port_operator=="lt"):
            min_port_2=0
            max_port_2=rule2.src_port
        elif (rule2.src_port_operator=="neq"):
            pass
        elif (rule2.src_port_operator=="range"):
            min_port_2=rule2.src_port[0]
            max_port_2=rule2.src_port[1]
    else:
        min_port_2=rule2.src_port
        max_port_2=rule2.src_port
    
    if (min_port_1==min_port_2)&(max_port_1==max_port_2):
        return 2
    if (min_port_2<=min_port_1):
        if(max_port_1<=max_port_2):
            return 1
        else:
            return 3
    return 0
    

def dst_port_subset(rule1, rule2):
    """
    returns 1 if rule1 is subset of rule2
            2 if rule1==rule2
            0 else
    """
    min_port_1=0
    min_port_2=0
    max_port_1=0
    max_port_2=0
    if (rule1.dst_port_operator=="")&(rule2.dst_port_operator==""):
        if (rule1.dst_port==rule2.dst_port):
            return 2
        else:
            return 0
    if (rule1.dst_port_operator!=""):
        if (rule1.dst_port_operator=="any"):
            min_port_1=0
            max_port_1=65535
        elif (rule1.dst_port_operator=="eq"):
            min_port_1=rule1.dst_port
            max_port_1=rule1.dst_port
        elif (rule1.dst_port_operator=="gt"):
            min_port_1=rule1.dst_port
            max_port_1=65535
        elif (rule1.dst_port_operator=="host"):
            min_port_1=rule1.dst_port
            max_port_1=rule1.dst_port
        elif (rule1.dst_port_operator=="lt"):
            min_port_1=0
            max_port_1=rule1.dst_port
        elif (rule1.dst_port_operator=="neq"):
            pass
        elif (rule1.dst_port_operator=="range"):
            min_port_1=rule1.dst_port[0]
            max_port_1=rule1.dst_port[1]
    else:
        min_port_1=rule1.dst_port
        max_port_1=rule1.dst_port
        

    if (rule2.dst_port_operator!=""):
        if (rule2.dst_port_operator=="any"):
            min_port_2=0
            max_port_2=65535
        elif (rule2.dst_port_operator=="eq"):
            min_port_2=rule2.dst_port
            max_port_2=rule1.dst_port
        elif (rule2.dst_port_operator=="gt"):
            min_port_2=rule2.dst_port
            max_port_2=65535
        elif (rule2.dst_port_operator=="host"):
            min_port_2=rule2.dst_port
            max_port_2=rule1.dst_port
        elif (rule2.dst_port_operator=="lt"):
            min_port_2=0
            max_port_2=rule2.dst_port
        elif (rule2.dst_port_operator=="neq"):
            pass
        elif (rule2.dst_port_operator=="range"):
            min_port_2=rule2.dst_port[0]
            max_port_2=rule2.dst_port[1]
    else:
        min_port_2=rule2.dst_port
        max_port_2=rule2.dst_port

    

    if (min_port_1==min_port_2)&(max_port_1==max_port_2):
        return 2
    if (min_port_2<=min_port_1):
        if(max_port_1<=max_port_2):
            return 1
        else:
            return 3
    return 0

class Firewall_Manager:
    
    def parse(self, filename, rule_list,):
        try:
            counter=0    
            #rule=Rule()
            f=open(filename, "r").readlines()
            for i in f:
                rule=Rule()
                rule.set_number(counter)
                counter+=1
                index=[0]
                protocol=""
                i=i.strip()
                j=i.split()
                length=len(j)
                print j

                #dynamic
                if (rule.set_dynamic(j[index[0]], index)):
                    if not (rule.set_time_out(j[index[0]], index)):
                        raise Error_Message(counter, "Error in time-out field, rule")
                    
                #action
                if not (rule.set_action(j[index[0]], index)):
                   raise Error_Message(counter, "Error in action type, rule")

                #protocol
                protocol=j[index[0]]
                if not (rule.set_protocol(j[index[0]], index)):
                    raise Error_Message(counter, "Error in protocol type, rule")

                #src_addr
                if not (rule.set_src_addr(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in src address, rule")     
                    
                #src_mask    
                if not (rule.set_src_mask(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in src mask, rule")

                #src_port
                if (protocol=="tcp")|(protocol=="udp"):
                    if not (rule.set_src_port(j, index)):
                        raise Error_Message(counter, "Error in src port, rule")
                    
                #dst_addr
                if not (rule.set_dst_addr(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in dst address, rule")
                    
                #dst_mask
                if not (rule.set_dst_mask(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in src mask, rule")

                #dst_port
                if (protocol=="tcp")|(protocol=="udp"):
                    if not (rule.set_dst_port(j, index)):
                        raise Error_Message(counter, "Error in dst port, rule")

                if (protocol=="icmp"):
                    pass # there need be [icmp-type [icmp-code] |icmp-message]

                if (index<length):
                    if (protocol=="tcp")&(j[index[0]]=="established"):
                        rule.established=True
                        index[0]+=1

                if (index<length):
                    rule.set_precendence(j, index)

                if (index<length):
                    rule.set_tos(j, index)

                if (index<length):
                    rule.set_log(j, index)
                        
                if (index<length):
                    rule.set_time_range(j, index)
                    
                #add_rule
                rule_list.append(rule)

        except(Error_Message), err:
            print err.message, err.counter
            #exit()
        print "Done!"
        print "============================="
        for i in xrange(len(rule_list)):
            print rule_list[i].src_port_operator
        print "============================="


    def check_for_intra_anomaly(self, x, y):

        src_addr_temp1=addr_subset(x.src_addr, y.src_addr)
        src_addr_temp2=addr_subset(y.src_addr, x.src_addr)
        dst_addr_temp1=addr_subset(x.dst_addr, y.dst_addr)
        dst_addr_temp2=addr_subset(y.dst_addr, x.dst_addr)
        src_port_temp1=src_port_subset(x, y)
        src_port_temp2=src_port_subset(y, x)
        dst_port_temp1=dst_port_subset(x, y)
        dst_port_temp2=dst_port_subset(y, x)
        if (src_addr_temp1==2):
            if (src_port_temp1==2):
                if (dst_addr_temp1==2):
                    if (dst_port_temp1==2):# ->exact
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="shadowing"
                    elif (dst_port_temp1==1): # ->subset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="shadowing"
                    elif (dst_port_temp2==1): # ->superset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="generalisation"
                    else:
                        x.state="none"
                        
                elif (dst_addr_temp1==1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="shadowing"
                    elif (dst_port_temp2==1):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"

                elif (dst_addr_temp2==1): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="generalisation"
                    else:
                        x.state="none"
                else:
                    x.state="none"
                    
            elif (src_port_temp1==1):# ->subset
                if (dst_addr_temp1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="shadowing"
                    elif (dst_port_temp2==1):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                elif (dst_addr_temp2): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                else:
                    x.state="none"
            elif (src_port_temp2==1):# ->superset
                if (dst_addr_temp1==1): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="generalisation"
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                none
                
#################################################################################
        elif (src_addr_temp1==2)|(src_addr_temp1==1): # ->subset
            if (src_port_temp1==1)|(src_port_temp1==2): # -> subset
                if (dst_addr_temp1): #  ->subset
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->subset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="shadowing"
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"         
                elif (dst_addr_temp2): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)):#->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                else:
                    x.state="none"
        #########################################################################################        
            elif ((src_port_temp2==1)): # ->correlated 
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            x.state="none" 
                        else:
                            x.state="correlation" 
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                x.state="none"
################################################################################################# 
        elif (src_addr_temp2==2)|(src_addr_temp2==1): # ->superset
            
            if ((src_port_temp1==1)): # ->correlated
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): #  ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            x.state="none" 
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"         
                elif (dst_addr_temp2==1): # -> correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif ((dst_port_temp2==1)):#-> correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                else:
                    x.state="none"
############################################################################################       
            elif ((src_port_temp2==1)|(src_port_temp2==2)): # -> superset
                if (dst_addr_temp1==1): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            x.state="none" 
                        else:
                            x.state="correlation" 
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): # ->superset
                    if ((dst_port_temp1==1)): # ->correlated
                        if (x.action==y.action):
                            x.state="none"
                        else:
                            x.state="correlation"
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)): #->superset
                        if (x.action==y.action):
                            x.state="redundancy"
                        else:
                            x.state="generalisation"
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                x.state="none"
        else:
            x.state="none"
        

    def tree_build(self, rule_list, rule_tree):
        #for i in xrange(len(rule_list)):
        #    print rule_list[i].src_addr
        print rule_list
        list_length=len(rule_list)
        i=0
        while (i<list_length):
            proto=-1
            src_addr_index=-1
            src_port_index=-1
            dst_addr_index=-1
            dst_port_index=-1
            number_index=-1
            no_src_addr=False
            no_dst_addr=False
            no_src_port=False
            no_dst_port=False
            done=False
            redundancy=False

            if (rule_list[i].protocol=="tcp"):
                proto=0
            elif (rule_list[i].protocol=="udp"):
                proto=1
            elif (rule_list[i].protocol=="icmp"):
                proto=2
                print "Proto=udp"
            else:
                proto=3
                print "Proto=ip"

            if (len(rule_tree[proto])==0):
                rule_list[i].state="none"
                rule_tree[proto].append([[[[rule_list[i]]]]])
                continue;
                
            for j in xrange(len(rule_tree[proto])): # perebor po src_addr 
                for k in xrange(len(rule_tree[proto][j])): # perebor po src_port
                    for l in xrange(len(rule_tree[proto][j][k])): # perebor po dsr_addr
                        for m in xrange(len(rule_tree[proto][j][k][l])): # perebor po dst_port 
                            for n in xrange(len(rule_tree[proto][j][k][l][m])): # perebor po number
                                x=rule_list[i]
                                y=rule_tree[proto][j][k][l][m][n]
                                self.check_for_intra_anomaly(x,y)
                                if ((redundancy)&(x.state=="correlation")):
                                    redundancy=False
                                    red_proto=0
                                    red_j=0
                                    red_k=0
                                    red_l=0
                                    red_m=0
                                    red_n=0
                                if (x.state=="redundancy"):
                                    print "Check was",x.number+1, y.number+1
                                    print "Rule was deleted", rule_tree[proto][j][k][l][m][n].number+1
                                    if not (redundancy):
                                        redundancy=True
                                        red_proto=proto
                                        red_j=j
                                        red_k=k
                                        red_l=l
                                        red_m=m
                                        red_n=n
                                    else:
                                        redundancy=False
                                        red_proto=0
                                        red_j=0
                                        red_k=0
                                        red_l=0
                                        red_m=0
                                        red_n=0
                                elif (x.state=="shadowing"):
                                    print "Check was",x.number+1, y.number+1
                                    print "Rule was deleted", rule_list[i].number+1
                                    list_length-=1
                                    del rule_list[i] #delete x
                                    done=True
                                elif (x.src_addr==y.src_addr):
                                    src_addr_index=j
                                    print "   Sovpadenie src_addr"
                                    if (x.src_port==y.src_port):
                                        src_port_index=k
                                        print "   Sovpadenie src_port"
                                        if (x.dst_addr==y.dst_addr):
                                            dst_addr_index=l
                                            print "   Sovpadenie dst_addr"
                                            if (x.dst_port==y.dst_port):
                                                dst_port_index=m
                                                done=True
                                                print "   Sovpadenie dst_port"
                                                print "Exact Match"
                                                break
                             
                                        else:
                                            no_dst_port=True
                                    else:
                                        no_dst_addr=True
                                        no_dst_port=True
                                else:
                                    no_src_port=True
                                    no_dst_addr=True
                                    no_dst_port=True
                                    
                            if (no_dst_port)|(done):
                                no_dst_port=False #Unsure
                                break
                        if (no_dst_addr)|(done):
                            no_dst_addr=False #Unsure
                            break
                    if (no_src_port)|(done):
                        no_src_addr=False #Unsure
                        break   
                if (done):
                    break


                
            if (redundancy):
                del rule_tree[red_proto][red_j][red_k][red_l][red_m][red_n]#delete y
            if (src_addr_index!=-1):
                if (src_port_index!=-1):
                    if (dst_addr_index!=-1):
                        if(dst_port_index!=-1):
                            print "Full insert"
                            rule_tree[proto][src_addr_index][src_port_index][dst_addr_index][dst_port_index].append(rule_list[i])
                        else:
                            print "insert [proto][src_addr_index][src_port_index][dst_addr_index]"
                            rule_tree[proto][src_addr_index][src_port_index][dst_addr_index].append([rule_list[i]])
                    else:
                        print "insert [proto][src_addr_index][src_port_index]"
                        rule_tree[proto][src_addr_index][src_port_index].append([[rule_list[i]]])
                else:
                    print "insert [proto][src_addr_index]"
                    rule_tree[proto][src_addr_index].append([[[rule_list[i]]]])
                    
            else:
                print "insert [proto]"
                rule_tree[proto].append([[[[rule_list[i]]]]])
            i+=1
        print "Konec"


    def check_for_inter_anomaly(self, x, y):
        def exact(act1, act2):
            if (x.action=="accept")&(y.action=="deny"):
                anomaly="shadowing"
            elif (x.action=="deny")&(y.action=="accept"):
                anomaly="spuriousness"
            return anomaly
            
        def subset(act1, act2):
            if (x.action=="accept")&(y.action=="deny"):
                anomaly="shadowing"
            elif(y.action=="accept"):
                anomaly="spuriousness"
            else:
                anomaly="redundancy"
            return anomaly

        def superset(act1, act2):
            if (x.action=="accept"):
                anomaly="shadowing"
            else:
                anomaly="spuriousness"

        def correlation(act1, act2):
            anomaly="correlation"
            return anomaly

        
        src_addr_temp1=addr_subset(x.src_addr, y.src_addr)
        src_addr_temp2=addr_subset(y.src_addr, x.src_addr)
        dst_addr_temp1=addr_subset(x.dst_addr, y.dst_addr)
        dst_addr_temp2=addr_subset(y.dst_addr, x.dst_addr)
        src_port_temp1=src_port_subset(x, y)
        src_port_temp2=src_port_subset(y, x)
        dst_port_temp1=dst_port_subset(x, y)
        dst_port_temp2=dst_port_subset(y, x)

        if (src_addr_temp1==2):
            if (src_port_temp1==2):
                if (dst_addr_temp1==2):
                    if (dst_port_temp1==2):# ->exact
                        anomaly=exact(x.action, y.action)
                    elif (dst_port_temp1==1): # ->subset
                        anomaly=subset(x.action, y.action)
                    elif (dst_port_temp2==1): # ->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                        
                elif (dst_addr_temp1==1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        anomaly=subset(x.action, y.action)
                    elif (dst_port_temp2==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"

                elif (dst_addr_temp2==1): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
                    
            elif (src_port_temp1==1):# ->subset
                if (dst_addr_temp1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        anomaly=subset(x.action, y.action)
                    elif (dst_port_temp2==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            elif (src_port_temp2==1):# ->superset
                if (dst_addr_temp1==1): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                none
                
#################################################################################
        elif (src_addr_temp1==2)|(src_addr_temp1==1): # ->subset
            if (src_port_temp1==1)|(src_port_temp1==2): # -> subset
                if (dst_addr_temp1): #  ->subset
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->subset
                        anomaly=subset(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"         
                elif (dst_addr_temp2): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)):#->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
        #########################################################################################        
            elif ((src_port_temp2==1)): # ->correlated 
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                x.state="none"
################################################################################################# 
        elif (src_addr_temp2==2)|(src_addr_temp2==1): # ->superset
            
            if ((src_port_temp1==1)): # ->correlated
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): #  ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"         
                elif (dst_addr_temp2==1): # -> correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)):#-> correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
############################################################################################       
            elif ((src_port_temp2==1)|(src_port_temp2==2)): # -> superset
                if (dst_addr_temp1==1): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action) 
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): # ->superset
                    if ((dst_port_temp1==1)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)): #->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                x.state="none"
        else:
            x.state="none"













        

    


    def append_tree(self, rule_tree_ups, rule_tree_downs):
        no_src_addr=False
        no_dst_addr=False
        no_src_port=False
        no_dst_port=False        

        for u in xrange(len(rule_tree_downs)): #protocol
            for v in xrange(len(rule_tree_downs[u])): #src_addr
                for w in xrange(len(rule_tree_downs[u][v])): #src_port
                    for x in xrange(len(rule_tree_downs[u][v][w])): #dst_addr
                        for y in xrange(len(rule_tree_downs[u][v][w][x])): #dst_port
                            for z in xrange(len(rule_tree_downs[u][v][w][x][y])): #number    
                    
                                for proto in xrange(len(rule_tree_ups)): #protocol
                                    for i in xrange(len(rule_tree_ups[proto])): #src_addr
                                        for j in xrange(len(rule_tree_ups[proto][i])): #src_port
                                            for k in xrange(len(rule_tree_ups[proto][i][j])): #dst_addr
                                                for l in xrange(len(rule_tree_ups[proto][i][j][k])): #dst_port
                                                    for m in xrange(len(rule_tree_ups[proto][i][j][k][l])): #number
                                                        x=rule_tree_ups[proto][i][j][k][l][m]
                                                        y=rule_tree_downs[u][v][w][x][y][z]
                                                        if (x.protocol==y.protocol):
                                                            self.check_for_inter_anomaly(x,y)            
                                                        
                                                        else:
                                                            no_src_addr=True
                                                            no_dst_addr=True
                                                            no_src_port=True
                                                            no_dst_port=True
                                                    if (no_dst_port):
                                                        no_src_port=False
                                                        break
                                                if (no_dst_addr):
                                                    no_dst_addr=False
                                                    break
                                            if (no_src_port):
                                                no_src_port=False
                                                break
                                        if (no_src_addr):
                                            no_src_addr=False
                                            break
                                                        
                                                        
                                

  

















    def Check(self, rule_tree):
        for i in rule_tree:
            for j in i: 
                for k in j:
                    for l in k:
                        for m in l: 
                            for n in m:
                                for u in rule_tree:
                                    for v in u: # perebor po src_addr 
                                        for w in v:
                                            for x in w:
                                                for y in x: 
                                                    for z in y:
                                                        #print "type=", type(z)
                                                        if (n.number==11)&(z.number==9):
                                                            z.state="fuck"
                                                            n.state="shit"
                                                            self.Check_For_Anomaly(n,z)
                                                            print "========================================="
                                                            print "CHECK"    
                                                            print "x=", n.number+1, n.action, n.src_addr, n.state
                                                            print "y=", z.number+1, z.action, z.src_addr, z.state
                                                        




                                    



    def Tree_Print(self, rule_tree):
        u=0
        v=0
        w=0
        x=0
        y=0
        z=0
        for i in rule_tree:
            print " Proto Layer", u
            u+=1
            v=0
            w=0
            x=0
            y=0
            z=0
            for j in i:
                print "   Src_addr layer", v
                v+=1
                w=0
                x=0
                y=0
                z=0
                for k in j:
                    print "      Src_port Layer", w
                    w+=1
                    x=0
                    y=0
                    z=0
                    for l in k:
                        print "         Dst_addr Layer", x
                        x+=1
                        y=0
                        z=0
                        for m in l:
                            print "            Dst_Port Layer", y
                            y+=1
                            z=0
                            for n in m: 
                                print "               number Layer", z
                                print "src_ip=", n.src_addr
                                print "src_port=", n.src_port
                                print "dst_addr=", n.dst_addr
                                print "dst_port=", n.dst_port
                                print "number=", n.number
                                print "state=", n.state
                                z+=1    
            
            



            
"""
rule_list=[]
rule_tree=[[],[],[],[]]
a=Firewall_Manager()
filename="rules"
a.parse(rule_list,filename)

#print rule_tree
#print rule_list
a.tree_build(rule_list, rule_tree)
#print "FUCK"
#print "+++++++++++++++++++++++++++++++++++++++"
a.Tree_Print(rule_tree)
a.Check(rule_tree)
print "Exit!"
#print rule_tree
"""















