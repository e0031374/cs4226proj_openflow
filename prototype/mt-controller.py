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

class SimpleController(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

        # https://gist.github.com/devvesa/5332005
        self.mac_to_port = {}


    def learning_switch(self, packet, packet_in, event):
        # packet_in is actual packet
        src = packet.src        # source MAC address
        dst = packet.dst
        inport = event.port

        ip_packet = packet.payload

        if src not in self.mac_to_port:
            # add port to mac mapping to database
            self.mac_to_port[src] = packet_in.in_port
            print "Learning that " + str(packet.src) + " is attached at port " + str(packet_in.in_port)

            # install flow
            # we cannot install flow here because then we wont get the reply
            # all the info we need is in self.mac_to_port
            """
            msg_flow = of.ofp_flow_mod()
            msg_flow.match = of.ofp_match()
            msg_flow.match.dl_dst = src
            msg_flow.actions.append(of.ofp_action_output(port = inport))
            log.info("#### msg_flow start ###")
            log.info(msg_flow)
            log.info("#### msg_flow end ###")
            event.connection.send(msg_flow)
            """
        else:
            # if source is already is store, we can update port perhaps?
            # dst is mac
            print "placeholder"
            #dst_port = self.mac_to_port[dst]
            #self.insert_mac_flow(event, dst, dst_port)

        # this will only run in the ARP reply not req
        if dst in self.mac_to_port:
            dst_port = self.mac_to_port[dst]

            """
            # send it out the specific port
            msg = of.ofp_packet_out()
            msg.data = packet_in

            dst_port = self.mac_to_port[dst]

            # add action to send packet out specified port
            action = of.ofp_action_output(port = dst_port)
            msg.actions.append(action)

            # send message to switch
            event.connection.send(msg)
            """


            # install flow rather than send
            """
            msg_flow = of.ofp_flow_mod()
            #msg_flow.match = of.ofp_match.from_packet(packet)
            msg_flow.match = of.ofp_match()
            #msg_flow.match.dl_type = 0x800
            msg_flow.match.dl_dst = dst
            #msg_flow.match.nw_dst = IPAddr(ip_packet.protosrc)
            msg_flow.actions.append(of.ofp_action_output(port = dst_port))
            log.info("#### msg_flow start ###")
            log.info(msg_flow)
            log.info("#### msg_flow end ###")
            event.connection.send(msg_flow)
            """
            self.insert_mac_flow(event, src, dst, dst_port)

            print str(packet.dst) + " destination known. only send message to it"

            # lets send the packet and assumes installing the flow eats up the pkt
            # TODO meeting now, wait who are we sending to?
            self.send_to_port(event, dst_port)


        else:
            # instructs switch flood all ports with the packet
            # does not instal entry to flow table
            self.send_to_port(event, of.OFPP_ALL)

            #msg = of.ofp_packet_out()
            #msg.data = packet_in

            ## add action to send packet out all ports
            #action = of.ofp_action_output(port = of.OFPP_ALL)
            #msg.actions.append(action)

            ## send message to switch
            #event.connection.send(msg)

            print str(packet.dst) + " not known, resend to everybody"

            # modify flow table to flood all ports, subseq packets will not be
            # sent to controller
            # https://pox-dev.noxrepo.narkive.com/yqy9JuDC/usage-ofp-flow-mod-and-ofp-packet-out-messages
            ## ofp_flow_mod: flow table modification
            #msg = of.ofp_flow_mod()
            #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            #event.connection.send(msg)

    def insert_mac_flow(self, event, src_mac, dst_mac, dst_port):
        # install flow rather than send
        msg_flow = of.ofp_flow_mod()
        msg_flow.match = of.ofp_match()
        msg_flow.match.dl_dst = dst_mac
        msg_flow.match.dl_src = src_mac
        msg_flow.actions.append(of.ofp_action_output(port = dst_port))
        log.info("#### msg_flow start ###")
        log.info(msg_flow)
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
        dpid = event.dpid
        src = packet.src        # source MAC address
        dst = packet.dst
        inport = event.port

        ## added
        log.info("Packet\n")
        log.info(packet)

        log.info("IP\n")
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


        packet_in = event.ofp
        #log.info("### packet ofp: " + str(packet_in))
        self.learning_switch(packet, packet_in, event)

            
                

        


        #### hold for a bit
        # ofp_flow_mod: flow table modification
        ##msg = of.ofp_flow_mod()
        ##msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        ##event.connection.send(msg)
        #########

        log.info("# S%i: Message sent: Outport %i\n", dpid, of.OFPP_FLOOD)


    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has come up.", dpid_to_str(event.dpid))

def launch ():
    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    # Starting the controller module
    core.registerNew(SimpleController)
