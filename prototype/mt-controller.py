from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr

import json

log = core.getLogger()

class MacStore:
    def __init__(self, default_ttl=None):
        self.mac_to_port = {}
        self.DEFAULT_TTL = default_ttl

    def put(self, switch_dpid, mac_address, port):
        key = (switch_dpid, mac_address)
        val = (port, self.DEFAULT_TTL)
        if key in self.mac_to_port:
            # update
            old_val = self.get(switch_dpid, mac_address)
        else:
            self.mac_to_port[key] = val

    def get(self, switch_dpid, mac_address):
        key = (switch_dpid, mac_address)
        val = self.mac_to_port[key]
        port = val[0]
        return port

    def contains(self, switch_dpid, mac_address):
        key = (switch_dpid, mac_address)
        return self.__contains__(key)

    def __contains__(self, key):
        return key in self.mac_to_port

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
        
        ip_packet = packet.payload

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
            self.insert_mac_flow(event, src_mac, dst_mac, dst_port)

            # install other way flow
            reverse_dst = (switch_dpid, src_mac)
            self.insert_mac_flow(event, dst_mac, src_mac, self.mac_to_port[reverse_dst])
            

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


    def insert_mac_flow(self, event, src_mac, dst_mac, dst_port):
        # install flow rather than send
        msg_flow = of.ofp_flow_mod()
        msg_flow.idle_timeout = self.DEFAULT_TTL
        msg_flow.match = of.ofp_match()
        msg_flow.match.dl_dst = dst_mac
        msg_flow.match.dl_src = src_mac
        msg_flow.actions.append(of.ofp_action_output(port = dst_port))
        log.info("#### msg_flow start ###")
        #log.info(msg_flow)
        log.info("port: " + str(dst_port))
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
        self.learning_switch(event)

            
                

        


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
        
        msg_flow = of.ofp_flow_mod()
        msg_flow.match = of.ofp_match()
        msg_flow.command = of.OFPFC_DELETE

        #msg_flow.match.dl_dst = dst_mac
        #msg_flow.match.dl_src = src_mac
        #msg_flow.actions.append(of.ofp_action_output(port = dst_port))
        #event.connection.send(msg_flow)

        log.info("begin iter all switches?")
        for connection in core.openflow._connections.values():
            log.info(connection)
            connection.send(msg_flow)

        log.info("###### Port Status end\n")
        


def launch ():
    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    # Starting the controller module
    core.registerNew(SimpleController)
