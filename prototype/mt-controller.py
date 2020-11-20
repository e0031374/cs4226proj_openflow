from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr

import json

import sys

log = core.getLogger()

REGULAR_PRIORITY = 1000 # of.OFP_DEFAULT_PRIORITY
FIREWALL_PRIORITY = 2000 # of.OFP_DEFAULT_PRIORITY + 100


class Policy:
    def __init__(self):
        self.firewall = []
        self.premium = set()

    def parse(self):
        #input_path = input("Input policy path: ")
        #input_path = input_path.split()

        #if not len(input_path):
        #    print "no policy found"
        #    return

        #print "policy found: " + str(input_path)

        #hasPolicy = input("Does policy.in exist in the same level: [y/n]: ")
        #hasPolicy = hasPolicy.strip()
        #hasPolicy = hasPolicy.lower()
        #if hasPolicy[0] != 'y':
        #    return
            
        input_path = "policy.in"

        f = open(input_path, "r")

        cmdline = f.readline()
        cmdline = cmdline.strip()
        cmd_arr = cmdline.split()
        firewall_lines = int(cmd_arr[0])
        premium_lines = int(cmd_arr[1])

        for i in range(firewall_lines):
            line = f.readline()
            line = line.strip()
            line_arr = line.split(",")
            if len(line_arr) == 2:
                dst_ip_address = line_arr[0]
                dst_port = line_arr[1]
                self.firewall.append({ 
                    "dst_ip_address": dst_ip_address, 
                    "dst_port": dst_port 
                })
            elif len(line_arr) == 3:
                src_ip_address = line_arr[0]
                dst_ip_address = line_arr[1]
                dst_port = line_arr[2]
                self.firewall.append({ 
                    "src_ip_address": src_ip_address, 
                    "dst_ip_address": dst_ip_address, 
                    "dst_port": dst_port 
                })
            else:
                log.info("\n !!! ERROR !!! \n")

        log.info("\n" + str(self.firewall) + "\n")

        for i in range(premium_lines):
            line = f.readline()
            line = line.strip()
            self.premium.add(line)



        


class SimpleController(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

        # https://gist.github.com/devvesa/5332005
        self.mac_to_port = {}
        #self.mac_to_port = MacStore()

        # placeholder change this to 5s on actual
        self.DEFAULT_TTL = 60


    def learning_switch(self, event):

        log.info(self.mac_to_port)


        # packet_in is actual packet
        packet = event.parsed
        packet_in = event.ofp
        inport = event.port

        switch_dpid = event.dpid
        src_mac = packet.src        # source MAC address
        dst_mac = packet.dst

        # construct key
        src = (switch_dpid, src_mac)
        dst = (switch_dpid, dst_mac)
        
        ip_packet = packet.next

        if packet.type == packet.ARP_TYPE:
            src_ip = ip_packet.protosrc
            dst_ip = ip_packet.protodst
        else:
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip



        if not self.mac_to_port:
            pox.openflow.spanning_tree._update_tree()

        if src not in self.mac_to_port:
            """
            # add port to mac mapping to database
            # we cannot install flow here because then we wont get the reply
            # all the info we need is in self.mac_to_port
            """
            #self.mac_to_port.put(switch_dpid, src_mac, port)
            self.mac_to_port[src] = packet_in.in_port
            print "Learning that " + str(packet.src) + " is attached to switch: " + str(switch_dpid) + " at port: " + str(packet_in.in_port)

        else:
            # if source is already is store, we can update port perhaps?
            # dst is mac
            #dst_port = self.mac_to_port[dst]
            #self.insert_mac_flow(event, dst, dst_port)

            self.mac_to_port[src] = packet_in.in_port
            print "Updating that " + str(packet.src) + " is attached to switch: " + str(switch_dpid) + " at port: " + str(packet_in.in_port)

            """
            # delete destination record, await update
            # this prevents a reply to this req from causing another FLOOD
            # and only one flood out this time
            """
            #print self.mac_to_port
            #self.mac_to_port.pop(dst, None)
            #print self.mac_to_port

            ## update spanning tree since it could be possible that a link is down 
            #pox.openflow.spanning_tree._update_tree()


        # this will only run in the ARP reply not req
        if dst in self.mac_to_port:
            dst_port = self.mac_to_port[dst]

            # install 2-way flow
            log.info("Installing Flow for Switch: " + str(switch_dpid))
            qid_alpha = 1 if str(src_ip) in policy.premium else 2
            self.insert_mac_flow(event, src_mac, dst_mac, dst_port, qid_alpha)
            #self.insert_mac_flow(event, src_mac, dst_mac, dst_port)

            # install other way flow
            qid_beta = 1 if str(dst_ip) in policy.premium else 2
            print dst_ip
            reverse_dst = (switch_dpid, src_mac)
            self.insert_mac_flow(event, dst_mac, src_mac, self.mac_to_port[reverse_dst], qid_beta)
            

            print str(packet.dst) + " destination known. only send message to it"

            # lets send the packet and assumes installing the flow eats up the pkt
            self.send_to_port(event, dst_port)


            """
            # delete destination and source record after flow installd,
            # this prevents stale data should link go down
            """
            #print self.mac_to_port
            #self.mac_to_port.pop(dst, None)
            #self.mac_to_port.pop(src, None)
            #print self.mac_to_port


        else:
            """
            # destination unknown
            # instructs switch flood all ports with the packet
            # does not install entry to flow table, we need 2-way connection
            """
            self.send_to_port(event, of.OFPP_FLOOD)

            print str(packet.dst) + " not known, resend to everybody"


    def insert_mac_flow(self, event, src_mac, dst_mac, dst_port, qid):
        # install flow rather than send
        msg_flow = of.ofp_flow_mod()
        msg_flow.idle_timeout = self.DEFAULT_TTL
        msg_flow.priority = REGULAR_PRIORITY
        msg_flow.match = of.ofp_match()
        msg_flow.match.dl_dst = dst_mac
        msg_flow.match.dl_src = src_mac
        #msg_flow.actions.append(of.ofp_action_output(port = dst_port))
        msg_flow.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = qid))
        ## TODO ADD QUEUID NEED FIND IP ADDR OF PKT
        log.info("#### msg_flow start ###")
        log.info(msg_flow)
        log.info("port: " + str(dst_port))
        log.info("qid: " + str(qid))
        log.info("#### msg_flow end ###")
        event.connection.send(msg_flow)
    
        print str(dst_mac) + " destination mac added to flow table."
        ## end here

    def send_to_port(self, event, outgoing_port):
        packet_in = event.ofp

        msg = of.ofp_packet_out()
        msg.data = packet_in

        # add action to send packet out all ports
        action = of.ofp_action_output(port = outgoing_port)
        msg.actions.append(action)

        # send message to switch
        event.connection.send(msg)


    # return false if no firewall rule was activated
    # this may NOT mean that the packet send falls under the rule
    # since it could just be a h5 ping h2, 
    def firewall_protocol(self, event):
        packet = event.parsed
        src_mac = packet.src        # source MAC address
        dst_mac = packet.dst

        if src_mac == EthAddr("ff:ff:ff:ff:ff:ff") or dst_mac == EthAddr("ff:ff:ff:ff:ff:ff"):
            log.info("### src or dst is broadcast ###")
            return False

        #ip_packet = packet.payload
        ip_packet = packet.next

        if packet.type == packet.ARP_TYPE:
            src_ip = ip_packet.protosrc
            dst_ip = ip_packet.protodst
        else:
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip

        log.info("\n\n###### Firewall begin")
        log.info(ip_packet)
        log.info(src_ip)
        log.info(dst_ip)

        r1 = self.insert_firewall_flow(dst_ip, src_ip, dst_mac, src_mac, packet)
        r2 = self.insert_firewall_flow(src_ip, dst_ip, src_mac, dst_mac, packet)

        log.info("###### Firewall end\n")

        return r1 or r2

    ## TODO problem with second set of tests
    ##      also what if ARP was already established before?
    ##      Eg a ping was sent before, and a flow was installed, subsequent ones will bypass
    def insert_firewall_flow(self, dst_ip, src_ip, dst_mac, src_mac, packet):
        #all_block = [ s for s in policy.firewall if len(s.items()) == 2]
        #target_block = [ s for s in policy.firewall if len(s.items()) == 3]
        potential_rules = [ s for s in policy.firewall if s["dst_ip_address"] ==  dst_ip ]
        log.info(potential_rules)
        potential_rules = [ s for s in potential_rules if (s["src_ip_address"] == src_ip if "src_ip_address" in s else True) ]

        log.info(potential_rules)
        if len(potential_rules) <= 0:
            log.info("### No Potential Rules ###")
            return False

        for rule in potential_rules:
            log.info("Insert Firewall Rule")
            log.info(rule)
            msg_flow = of.ofp_flow_mod()
            msg_flow.match = of.ofp_match()
            #msg_flow.command = of.OFPFC_DELETE
            #msg_flow.match.dl_dst = EthAddr(dst_mac)
            #msg_flow.match.dl_src = EthAddr(src_mac)

            # IP Protocol set to TCP
            msg_flow.priority = FIREWALL_PRIORITY
            msg_flow.match.nw_proto = 6
            msg_flow.match.dl_type = 0x800

            if "src_ip_address" in rule:
                msg_flow.match.nw_src = (IPAddr(rule["src_ip_address"]), 32)
                msg_flow.match.dl_src = EthAddr(src_mac)
            else:
                log.info("!!! WILDCARD FIREWALL RULE ADDED !!!")
            if "dst_ip_address" in rule:
                msg_flow.match.nw_dst = (IPAddr(rule["dst_ip_address"]), 32)
                msg_flow.match.dl_dst = EthAddr(dst_mac)
            if "dst_port" in rule:
                msg_flow.match.tp_dst = int(rule["dst_port"])

            msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            log.info(msg_flow)

            log.info("begin iter all switches?")
            for connection in core.openflow._connections.values():
                log.info(connection)
                connection.send(msg_flow)


        # check if we need to drop the packet
        src_mac = packet.src        # source MAC address
        dst_mac = packet.dst
        if packet.type != packet.IP_TYPE:
            log.info("#### Packet not IP TYPE ####")
            return False
        ip_packet = packet.next

        if ip_packet.protocol != ip_packet.TCP_PROTOCOL:
            log.info("#### Packet not TCP TYPE ####")
            return False
        tcp_packet = ip_packet.next

        def firewall_match(rule):
            if "src_ip_address" in rule and ip_packet.srcip != rule["src_ip_address"]:
                return False
            if "dst_ip_address" in rule and ip_packet.dstip != rule["dst_ip_address"]:
                return False
            if "dst_port" in rule and tcp_packet.dstport != rule["dst_port"]:
                return False
            log.info("#### Packet Rule Match ####")
            return True

        return any([firewall_match(rule) for rule in potential_rules])
        #return True
        
        

    def apply_firewall(self):

        for rule in policy.firewall:
            msg_flow = of.ofp_flow_mod()
            msg_flow.match = of.ofp_match()
            #msg_flow.command = of.OFPFC_DELETE

            # IP Protocol set to TCP
            msg_flow.match.nw_proto = 6

            if "src_ip_address" in rule:
                msg_flow.match.nw_src = rule["src_ip_address"]
            if "dst_ip_address" in rule:
                msg_flow.match.nw_dst = rule["dst_ip_address"]
            if "dst_port" in rule:
                msg_flow.match.tp_dst = rule["dst_port"]

            msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_NONE))

            log.info("begin iter all switches?")
            for connection in core.openflow._connections.values():
                log.info(connection)
                connection.send(msg_flow)
        


    def _handle_PacketIn(self, event):
        packet = event.parsed
        packet_in = event.ofp
        dpid = event.dpid
        src = packet.src        # source MAC address
        dst = packet.dst
        inport = event.port

        ## added
        log.info("###### Segment begin")
        log.info("Packet")
        log.info(packet)
        log.info("switch dpid: " + str(dpid))

        log.info("IP")
        arp_packet = packet.payload

        log.info(arp_packet)
        #log.info(arp_packet.hwsrc)
        #log.info(arp_packet.hwdst)
        #log.info(arp_packet.protosrc)
        #log.info(arp_packet.protodst)
        
        #if packet.type == packet.ARP_TYPE:
        #    log.info("ARP Packet")
        #    
        #    arp_msg = of.ofp_flow_mod()
        #    arp_msg.match = of.ofp_match()
        #    arp_msg.match.dl_type = 0x800
        #    # match incoming IP destination
        #    #arp_msg.match.nw_dst = arp_packet.protosrc
        #    arp_msg.match.nw_dst = IPAddr(arp_packet.protosrc)
        #    #arp_msg.actions.append(ofp_action_dl_addr(dl_addr=src))

        #    # set output port of undetected 
        # https://noxrepo.github.io/pox-doc/html/#set-ethernet-source-or-destination-address
        #    arp_msg.actions.append(of.ofp_action_output(port = inport))
        #    event.connection.send(arp_msg)


        #log.info("### packet ofp: " + str(packet_in))
        #self.firewall_protocol(event)
        #self.learning_switch(event)
        if not self.firewall_protocol(event):
            log.info("no firewall rule detected")
            self.learning_switch(event)
        else:
            log.info("firewall rule should have activated")
        


        #### hold for a bit
        # ofp_flow_mod: flow table modification
        ##msg = of.ofp_flow_mod()
        ##msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        ##event.connection.send(msg)
        #########

        #log.info("# S%i: Message sent: Outport %i\n", dpid, of.OFPP_FLOOD)
        log.info("###### Segment End\n")


    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has come up.", dpid_to_str(event.dpid))

    def _handle_ConnectionDown(self, event):
        log.info("Switch %s has come down.", dpid_to_str(event.dpid))

    def _handle_FlowRemoved(self, event):
        log.info("###### Segment begin")
        log.info("Packet")
        packet = event.parsed
        log.info(packet)
        log.info("Switch %s has flow removed.", dpid_to_str(event.dpid))
        log.info("###### Segment end\n")

    def _handle_PortStatus(self, event):
        log.info("###### Port Status begin")
        log.info("PortStatus")

        if event.added:
          action = "added"
        elif event.deleted:
          action = "removed"
        else:
          action = "modified"
        print "Port %s on Switch %s has been %s." % (event.port, event.dpid, action)
        #log.info(packet)

        # update spanning tree since it could be possible that a link is down 
        pox.openflow.spanning_tree._update_tree()
        self.mac_to_port.clear()
        self.mac_to_port = {}

        # remove all flows
        self.delete_flows()

        log.info("###### Port Status end\n")

    def delete_flows(self):
        msg_flow = of.ofp_flow_mod()
        msg_flow.match = of.ofp_match()
        msg_flow.command = of.OFPFC_DELETE

        log.info("begin iter all switches?")
        for connection in core.openflow._connections.values():
            log.info(connection)
            connection.send(msg_flow)


        
        

policy = Policy()

def launch ():

    policy.parse()


    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    # Starting the controller module
    core.registerNew(SimpleController)
