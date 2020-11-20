'''
Please add your name:
Please add your matric number: 
'''

import os
import sys
import atexit
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.link import Link, TCLink
from mininet.node import RemoteController
from collections import defaultdict

net = None
link_store = defaultdict(dict)

class TreeTopo(Topo):
			
	def __init__(self, f):
		# Initialize topology
		Topo.__init__(self)        
	
	# You can write other functions as you need.

    		cmdline = f.readline()
    		cmd_arr = cmdline.split()
    		n_hosts = cmd_arr[0]
    		m_switches = cmd_arr[1]
    		l_links = cmd_arr[2]
    		
    		print cmdline
    		print cmdline.split()

		store = {}
		global link_store
		
		# Add hosts
    		# > self.addHost('h%d' % [HOST NUMBER])
		for i in range(int(n_hosts)):
			h = i + 1
			name = 'h%d' % h
			ip = '10.0.0.%d/8' % h
			print ip
			host = self.addHost(name, ip=ip)
			store[name] = host

		for i in range(int(m_switches)):
			s = i + 1
			name = 's%d' % s
			print name
    			sconfig = {'dpid': "%016x" % s}
			print sconfig
    			switch = self.addSwitch(name, **sconfig)
			store[name] = switch

		print store

		for i in range(int(l_links)):
			line = f.readline()
			line = line.strip()
			line_arr = line.split(",")
			print line_arr

			link_store[line_arr[0]][line_arr[1]] = {'bw': int(line_arr[2])}
			link_store[line_arr[1]][line_arr[0]] = {'bw': int(line_arr[2])}

    			#linkconfig = {'bw': int(line_arr[2]), 'loss': 0}
    			#linkconfig = {'bw': 100, 'loss': 0}
			#self.addLink(line_arr[0], line_arr[1], bw=int(line_arr[2]), loss=0)

    			#linkconfig = {'bw': int(line_arr[2])}
			#self.addLink(line_arr[0], line_arr[1], **linkconfig)
			self.addLink(line_arr[0], line_arr[1])

		print store
		print link_store
		print "######## end topo ##########"

	# Add hosts
    # > self.addHost('h%d' % [HOST NUMBER])

	# Add switches
    # > sconfig = {'dpid': "%016x" % [SWITCH NUMBER]}
    # > self.addSwitch('s%d' % [SWITCH NUMBER], **sconfig)

	# Add links
	# > self.addLink([HOST1], [HOST2])

def startNetwork(f):
    info('** Creating the tree network\n')
    topo = TreeTopo(f)

    global net
    #net = Mininet(topo=topo, link = Link,
    #              controller=lambda name: RemoteController(name, ip='SERVER IP'),
    #              listenPort=6633, autoSetMacs=True)
    #net = Mininet(topo=topo, link = TCLink,
    net = Mininet(topo=topo, link = Link,
                  controller=lambda name: RemoteController(name, ip='192.168.56.1'),
                  listenPort=6633, autoSetMacs=True)

    info('** Starting the network\n')
    net.start()

    info('** CHECK QOS\n')
    print net.topo.g.edge
#    for link in net.links:
#    	print link
#
    for switch in net.switches:
	print switch.name
	#print switch.intfs
	#print ".. next .."
    switchLinks = {}
    for switch in net.switches:
	switchLinks[switch.name] = net.topo.g.edge[switch.name]
	#[net.topo.g.edge[switch.name] for switch in net.switches]
    print switchLinks
    flat1 = [v for (k,v) in switchLinks.items()]
    print flat1
    flat2 = [v for ele in flat1 for (k,v) in ele.items()]
    flat3 = [v for ele in flat2 for (k,v) in ele.items()]
    """
    node1: dst
    node2: src
    port1: dst_port
    port2: src_port
    bw: 100Mbps
    """
    print flat3
    print len(flat3)


    print "ADDING QoS QUEUES"
    #c_f = "sudo ovs-vsctl -- set Port s3-eth1 qos=@newqos -- set Port s3-eth2 qos=@newqos -- set Port s3-eth3 qos=@newqos -- set Port s3-eth4 qos=@newqos -- set Port s1-eth1 qos=@newqos -- set Port s1-eth2 qos=@newqos -- set Port s1-eth3 qos=@newqos -- set Port s1-eth4 qos=@newqos -- set Port s1-eth5 qos=@newqos -- set Port s2-eth1 qos=@newqos -- set Port s2-eth2 qos=@newqos -- set Port s2-eth3 qos=@newqos -- set Port s2-eth4 qos=@newqos -- set Port s4-eth1 qos=@newqos -- set Port s4-eth2 qos=@newqos -- set Port s4-eth3 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1 -- --id=@q0 create Queue other-config:min-rate=1000000 other-config:max-rate=1000000 -- --id=@q1 create Queue other-config:min-rate=1000000000 other-config:max-rate=1000000000"
    #print c_f
    #os.system(c_f)
    #os.system("sudo ovs-vsctl -- set Port s1-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1 -- --id=@q0 create Queue other-config:min-rate=1000000 other-config:max-rate=1000000 -- --id=@q1 create Queue other-config:min-rate=1000000000 other-config:max-rate=1000000000")
    for link in flat3:
    # 16 links src are all switches
    # only doing for switches, so src only
	print link
	src_name = str(link["node2"])
	dst_name = str(link["node1"])
	port_no = str(link["port2"])
	intf = src_name + "-eth" + port_no
	#bw = link["bw"] * 1000000
	global link_store
	print link_store
	#bw = 10000000
	bw = link_store[src_name][dst_name]["bw"] * 1000000
	bw_str = str(bw)
	premium_bw = str(int(0.8 * bw))
	normal_bw = str(int(0.5 * bw))
    	#cmd_format = 'sudo ovs-vsctl -- set Port %s qos=@newqos \
    	#         -- --id=@newqos create QoS type=linux-htb other-config:max-rate=%s queues=0=@q0,1=@q1,2=@q2 \
    	#         -- --id=@q0 create queue other-config:max-rate=%s other-config:min-rate=%s \
    	#         -- --id=@q1 create queue other-config:min-rate=%s \
    	#         -- --id=@q2 create queue other-config:max-rate=%s'
    	#cmd_format = 'sudo ovs-vsctl -- set Port %s qos=@newqos \
    	#         -- --id=@newqos create QoS type=linux-htb other-config:max-rate=%s queues=0=@q0,1=@q1,2=@q2 \
    	#         -- --id=@q0 create queue other-config:max-rate=%s other-config:min-rate=%s \
    	#         -- --id=@q1 create queue other-config:min-rate=%s \
    	#         -- --id=@q2 create queue other-config:max-rate=%s'
    	cmd_format = 'sudo ovs-vsctl -- set Port %s qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=%s queues=0=@q0,1=@q1,2=@q2 -- --id=@q0 create queue other-config:max-rate=%s other-config:min-rate=%s -- --id=@q1 create queue other-config:min-rate=%s -- --id=@q2 create queue other-config:max-rate=%s'
	str_info = (intf, bw_str, bw_str, bw_str, premium_bw, normal_bw)
	#ppp = str(3000)
	#str_info = (intf, ppp, ppp, ppp, ppp, ppp)
	cmd = cmd_format % str_info
	print(cmd)
	os.system(cmd)
	
	
    info('** END QOS\n')

    # Create QoS Queues
    # > os.system('sudo ovs-vsctl -- set Port [INTERFACE] qos=@newqos \
    #            -- --id=@newqos create QoS type=linux-htb other-config:max-rate=[LINK SPEED] queues=0=@q0,1=@q1,2=@q2 \
    #            -- --id=@q0 create queue other-config:max-rate=[LINK SPEED] other-config:min-rate=[LINK SPEED] \
    #            -- --id=@q1 create queue other-config:min-rate=[X] \
    #            -- --id=@q2 create queue other-config:max-rate=[Y]')

    info('** Running CLI\n')
    CLI(net)

def stopNetwork():
    if net is not None:
        net.stop()
        # Remove QoS and Queues
        os.system('sudo ovs-vsctl --all destroy Qos')
        os.system('sudo ovs-vsctl --all destroy Queue')


if __name__ == '__main__':

    input_path = "topology.in"

    if len(sys.argv) >= 2:
        print sys.argv[1]
	input_path = sys.argv[1]
    f = open(input_path, "r")


    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork(f)
