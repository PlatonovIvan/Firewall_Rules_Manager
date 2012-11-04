from collections import defaultdict
import copy
import fw_policy
import graph

class Switch (object): #switch
    
    _next_num = 0
    def __init__ (self):
        self._label=1
        self.mac_addr=[0,0,0,0]
        self._num = self.__class__._next_num
        self.__class__._next_num += 1

    def __repr__ (self):
        return "Node1 #" + str(self._num)

    def __eq__(self,y):
        if (self._label==y._label)&(self._num==y._num):
            return True
        return False

    def __ne__(self,y):
        if (self._label!=y._label)|(self._num!=y._num):
            return True
        return False


class Host (object): #host
    _next_num = 0
    def __init__ (self):
        self._label=2
        self._ip_addr=[0,0,0,0]
        self._num = self.__class__._next_num
        self.__class__._next_num += 1
  
    def __repr__ (self):
        return "Node2 #" + str(self._num)

    def __eq__(self, y):
        if (self._label==y._label)&(self._num==y._num):
            return True
        return False

    def __ne__(self,y):
        if (self._label!=y._label)|(self._num!=y._num):
            return True
        return False


class Firewall (object): #Firewall
    _next_num = 0
    
    def __init__ (self, filename):
        self._label=3
        self._rule_tree=[[],[],[],[]]
        self._fw_Manager=fw_policy.Firewall_Manager()
        self._num = self.__class__._next_num
        self.__class__._next_num += 1
        rule_list=[]
        self._fw_Manager.parse(filename, rule_list)
        self._fw_Manager.tree_build(rule_list, self._rule_tree)
        print "***********************************************"
        print self._rule_tree
        print "***********************************************"
      
  
    def __repr__ (self):
        return "Node3 #" + str(self._num)

    def __eq__(self, y):
        if (self._label==y._label)&(self._num==y._num):
            return True
        return False

    def __ne__(self,y):
        if (self._label!=y._label)|(self._num!=y._num):
            return True
        return False


class Topology:
    _g=graph.Graph()
    _host_nodes=[]
    _switch_nodes=[]
    _firewall_nodes=[]
    def __init__(self):
        print "Hello"
        # Our Topology
        """
        n0=Switch(); self._g.add(n0); self._switch_nodes.append(n0)#switch
        n1=Switch(); self._g.add(n1); self._switch_nodes.append(n1)#switch
        n2=Switch(); self._g.add(n2); self._switch_nodes.append(n2)#switch
        n3=Switch(); self._g.add(n3); self._switch_nodes.append(n3)#switch
        n4=Switch(); self._g.add(n4); self._switch_nodes.append(n4)#switch
        n5=Switch(); self._g.add(n5); self._switch_nodes.append(n5)#switch
        n6=Firewall("right_fw_rules"); self._g.add(n6); self._firewall_nodes.append(n6)#firewall
        n7=Switch(); self._g.add(n7); self._switch_nodes.append(n7)#switch
        n8=Switch(); self._g.add(n8); self._switch_nodes.append(n8)#switch
        n9=Switch(); self._g.add(n9); self._switch_nodes.append(n9)#switch
        n10=Switch(); self._g.add(n10); self._switch_nodes.append(n10)#switch
        n11=Switch(); self._g.add(n11); self._switch_nodes.append(n11)#switch

        n100=Host(); self._g.add(n100); self._host_nodes.append(n100)#host
        n101=Host(); self._g.add(n101); self._host_nodes.append(n101)#host
        n102=Host(); self._g.add(n102); self._host_nodes.append(n102)#host
        n103=Host(); self._g.add(n103); self._host_nodes.append(n103)#host
        n104=Host(); self._g.add(n104); self._host_nodes.append(n104)#host
        n105=Host(); self._g.add(n105); self._host_nodes.append(n105)#host
        n106=Host(); self._g.add(n106); self._host_nodes.append(n106)#host
        n107=Host(); self._g.add(n107); self._host_nodes.append(n107)#host
        n108=Host(); self._g.add(n108); self._host_nodes.append(n108)#host
        n109=Host(); self._g.add(n109); self._host_nodes.append(n109)#host
        n110=Host(); self._g.add(n110); self._host_nodes.append(n110)#host
        n111=Host(); self._g.add(n111); self._host_nodes.append(n111)#host
        n112=Host(); self._g.add(n112); self._host_nodes.append(n112)#host
        n113=Host(); self._g.add(n113); self._host_nodes.append(n113)#host
        n114=Host(); self._g.add(n114); self._host_nodes.append(n114)#host
        n115=Host(); self._g.add(n115); self._host_nodes.append(n115)#host
        n116=Host(); self._g.add(n116); self._host_nodes.append(n116)#host

        self._g.link((n100,0),(n0,0))
        self._g.link((n101,0),(n0,1))
        self._g.link((n0,2),(n1,0))

        self._g.link((n102,0),(n3,0))
        self._g.link((n103,0),(n3,1))
        self._g.link((n104,0),(n5,0))
        self._g.link((n105,0),(n5,1))
        self._g.link((n3,2),(n5,2))
        self._g.link((n3,3),(n2,0))
        self._g.link((n5,3),(n2,1))
        self._g.link((n2,2),(n1,1))

        self._g.link((n106,0),(n7,0))
        self._g.link((n107,0),(n7,1))
        self._g.link((n7,2),(n6,0))

        self._g.link((n110,0),(n10,0))
        self._g.link((n111,0),(n10,1))
        self._g.link((n112,0),(n11,0))
        self._g.link((n113,0),(n11,1))
        self._g.link((n114,0),(n11,2))
        self._g.link((n115,0),(n11,3))
        self._g.link((n10,2),(n11,4))
        self._g.link((n10,3),(n9,0))
        self._g.link((n11,5),(n9,1))

        self._g.link((n116,0),(n9,2))

        self._g.link((n6,3),(n9,4))
        self._g.link((n1,2),(n6,2))
        self._g.link((n1,3),(n9,3))
        """
        
        n0=Host(); self._g.add(n0); self._host_nodes.append(n0)#host
        n1=Firewall("up_fw_rules"); self._g.add(n1); self._firewall_nodes.append(n1)#firewall
        n2=Firewall("left_fw_rules"); self._g.add(n2); self._firewall_nodes.append(n2)#firewall
        n3=Firewall("right_fw_rules"); self._g.add(n3); self._firewall_nodes.append(n3)#firewall        
        n4=Host(); self._g.add(n4); self._host_nodes.append(n4)#host
        n5=Host(); self._g.add(n5); self._host_nodes.append(n5)#host

        self._g.link((n0,0),(n1,0))
        self._g.link((n1,1),(n2,0))
        self._g.link((n1,2),(n3,0))
        self._g.link((n2,1),(n4,0))
        self._g.link((n3,1),(n5,0))
        
        return


    def add_node_to_path(self, current_path, n):
        if (len(current_path)!=0):
            n2=current_path.pop()
            ports=self._g.find_port(n2[0], n)
            current_path.append([n2[0],ports[0]])

        current_path.append([n,0])
        return True


    def contains (self, current_path, n):
        for i in xrange(len(current_path)):
            if (n==current_path[i][0]):
                return True
        return False


    def delete_node_from_path(self, current_path):
        current_path.pop()
        return


    def find_all_paths (self, n1, n2, nodes_from_A_to_B, current_path=[], TTL=[0], done=[False], depth=[0]):
        self.add_node_to_path(current_path, n1)
        if (n1==n2):
            done[0]=True
            return 
        elif ((n1._label==2)&(TTL[0]!=0))|(TTL[0]==33):
            #print "Nu i cho?!"
            return
        elif (not done[0]):
            next_nodes=self._g.neighbors(n1)
            for i in next_nodes:
                if ((not self.contains(current_path, i))): # for all paths except previous -> split horizon
                    depth[0]+=1
                    TTL[0]+=1
                    self.find_all_paths( i, n2, nodes_from_A_to_B, current_path, TTL, done, depth)
                    TTL[0]-=1
                    depth[0]-=1
                    if (done[0]):
                        tmp=copy.deepcopy(current_path)
                        nodes_from_A_to_B.append(tmp)
                        done[0]=False
                    self.delete_node_from_path(current_path)
        return


    def test(self):
        nodes_from_A_to_B=[]
        prev_node=Node3()
        #current_path=None
        matched_nodes=[]
        print self._host_nodes
        current_path=[]
        self.find_all_paths(self._host_nodes[2], self._host_nodes[10], nodes_from_A_to_B, current_path)
        print "This is our path"
        for i in nodes_from_A_to_B:
            print i
            print "++++++++++++++++++++++++++++"

      
    def check_connection(self):
        print self._host_nodes
        print self._firewall_nodes
        print "Enter"
        for i in xrange(0, len(self._host_nodes), 1):
            for j in xrange(i+1, len(self._host_nodes), 1):
                current_path=[]
                nodes_from_A_to_B=[]
                print "i,j=", i, j
                self.find_all_paths(self._host_nodes[i], self._host_nodes[j], nodes_from_A_to_B, current_path)
                print "This is our path",
                for z in nodes_from_A_to_B:
                    print z
                firewall_nodes=[]
                rule_list=[]
                for k in nodes_from_A_to_B:
                    for l in k:
                        if (l[0]._label==3):
                            print "FireWall"
                            firewall_nodes.append(l[0])
                            #self.append_policy_tree(rule_tree,l[0]._rule_tree)
                
                            
                        
                
reload(graph)
reload(fw_policy)
Topo=Topology()
#Topo.test()
Topo.check_connection()





