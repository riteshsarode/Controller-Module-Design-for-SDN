#!/usr/bin/python

from collections import defaultdict
from heapq import heapify, heappop, heappush

# POX dependencies
from pox.openflow.discovery import Discovery
from pox.core import core
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from pox.lib.packet.igmp import *   # Required for various IGMP variable constants
from pox.lib.packet.ethernet import *
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.recoco import Timer
import time
import random
from sets import Set

log = core.getLogger()


class Switch(EventMixin):
    """
    Class representing an OpenFlow switch controlled by the CastFlow manager
    """
    def __init__(self, manager):
        self.connection = None
        self.ports = None             # Complete list of all ports on the switch, contains complete port object provided by connection objects
        self.igmp_ports = []          # List of ports over which IGMP service should be provided, contains only integer indexes
        self.dpid = None
        self._listeners = None
 
    def __repr__(self):
        return dpid_to_str(self.dpid)

    def disconnect(self):
        if self.connection is not None:
            log.debug('Disconnect %s' % (self.connection, ))
            self.connection.removeListeners(self._listeners)
            self.connection = None
            self._listeners = None

    def connect(self, connection):
        if self.dpid is None:
            self.dpid = connection.dpid
        assert self.dpid == connection.dpid
        if self.ports is None:
            self.ports = connection.features.ports
            for port in self.ports:
                if port.port_no ==  of.OFPP_CONTROLLER or port.port_no == of.OFPP_LOCAL:
                    continue
                self.igmp_ports.append(port.port_no)
        self.disconnect()                   

        log.debug('Connect %s' % (connection, ))
        self.connection = connection
        self._listeners = self.listenTo(connection)

class CastflowManager(EventMixin):
    # _eventMixin_events = set([MulticastGroupEvent])

    def __init__(self):
        # Listen to dependencies
        def startup():
            core.openflow.addListeners(self)
            core.openflow_discovery.addListeners(self)
            self.topology_graph = []
            self.node_set = Set()
            self.weighted_topo_graph = []
            self.path_tree_map = defaultdict(lambda : None)     # self.path_tree_map[switch_dpid] = Complete path from receiver switch_dpid to src
            self.active_hosts = []
            self.installed_node_list = []       # List of all switch dpids with rules currently installed
            self.receivers = []                 # Tuples of (switch_dpid, port)
            self.flag_raise = 0


        # switchs for which we have records in form  [dpid] points to Switch
        self.switchs = {}
        # adjacency is -----  [switch1][switch2] gives port from switch1 to switch2
        self.adjacency = defaultdict(lambda : defaultdict(lambda : None))
        # Setup listeners in discovery module
        core.call_when_ready(startup, ('openflow', 'openflow_discovery'))

    def drop_packet(self, packet_in_event):
        """Drops the packet represented by the PacketInEvent without any flow table modification"""
        msg = of.ofp_packet_out()
        msg.data = packet_in_event.ofp
        msg.buffer_id = packet_in_event.ofp.buffer_id
        msg.in_port = packet_in_event.port
        msg.actions = []    # No actions = drop packet
        packet_in_event.connection.send(msg)

    def _handle_LinkEvent(self, event):
        """Handler for LinkEvents from the discovery module, which are used to learn the network topology."""

        def flip(link):
            return Discovery.Link(link[2], link[3], link[0], link[1])
        
        org_link = event.link
        switch1 = self.switchs[org_link.dpid1]
        switch2 = self.switchs[org_link.dpid2]

        # If Link is removed -------
        if event.removed:
            # This link no longer up
            if switch2 in self.adjacency[switch1]:
                del self.adjacency[switch1][switch2]
            if switch1 in self.adjacency[switch2]:
                del self.adjacency[switch2][switch1]
            switch1.igmp_ports.append(org_link.port1)
            switch2.igmp_ports.append(org_link.port2)
                
            log.info('Removed Adjacency: Switch ' + str(switch1) + ' Port: ' + str(org_link.port1) + ' <----> Switch ' + str(switch2) + ' Port: ' + str(org_link.port2))

            # switchs can be adjacent via other links
            for alt_link in core.openflow_discovery.adjacency:
                if alt_link.dpid1 == org_link.dpid1 and alt_link.dpid2 == org_link.dpid2:
                    if flip(alt_link) in core.openflow_discovery.adjacency:
                        # link goes in both directions
                        log.info('Found parallel adjacency');
                        self.adjacency[switch1][switch2] = alt_link.port1
                        if alt_link.port1 in switch1.igmp_ports:
                            switch1.igmp_ports.remove(alt_link.port1)
                        else:
                            log.warn(str(alt_link.port1) + ' not found in ports of switch: ' + dpid_to_str(switch1.dpid))
                        self.adjacency[switch2][switch1] = alt_link.port2
                        if alt_link.port2 in switch2.igmp_ports:
                            switch2.igmp_ports.remove(alt_link.port2)
                        else:
                            log.warn(str(alt_link.port2) + ' not found in ports of switch: ' + dpid_to_str(switch2.dpid))
                        # New link found, so break
                        break
        else:
        	#if not removed
            if self.adjacency[switch1][switch2] is None:
                # These previously weren't connected.  If the link exists in both directions, we consider them connected now.
                if flip(org_link) in core.openflow_discovery.adjacency:
                    # Link goes both ways -- connected!
                    # way 1
                    self.adjacency[switch1][switch2] = org_link.port1
                    if org_link.port1 in switch1.igmp_ports:
                        switch1.igmp_ports.remove(org_link.port1)
                    else:
                        log.warn(str(org_link.port1) + ' not found in ports of switch: ' + dpid_to_str(switch1.dpid))
                    
                    # way 2
                    self.adjacency[switch2][switch1] = org_link.port2
                    if org_link.port2 in switch2.igmp_ports:
                        switch2.igmp_ports.remove(org_link.port2)
                    else:
                        log.warn(str(org_link.port2) + ' not found in ports of switch: ' + dpid_to_str(switch2.dpid))
            
                    # got both links. Adding Adjacency from switch 1 to switch 2
                    log.info('Added Adjacency: Switch ' + str(switch1) + ' Port: ' + str(org_link.port1) + ' <----> Switch ' + str(switch2) + ' Port: ' + str(org_link.port2))

    def _handle_ConnectionUp(self, event):
        """Handling function for connectionUP * new switchs joining the network."""
        switch = self.switchs.get(event.dpid)
        if switch is None:
            # New switch
            switch = Switch(self)
            switch.dpid = event.dpid
            self.switchs[event.dpid] = switch
            log.info('Learned New Switch: ' + str(switch))
            switch.connect(event.connection)

    def _handle_ConnectionDown (self, event):
        """Handling function for ConnectionDOWN from the discovery module, switch leaving the network."""
        switch = self.switchs.get(event.dpid)
        if switch is None:
            log.warn(' ConnectionDown - No switch switch exist')
        else:
            log.info('Switch Down: ' + str(self.switchs[event.dpid]))
            del self.switchs[event.dpid]



    """
		This function handles IGMP packets as well as IPv4 packets. 
		It calculates Diajkstra's shortest paths to nodes from server
		It installs flows only for the path to the hosts
		For new addition of host during communication - flushes all flows and recalculates Diajkstras and inistalls flows for only those who neeed the stream
    """
    def _handle_PacketIn(self, event):

        if not event.connection.dpid in self.switchs:
            log.debug('Got packet from unrecognized switch: ' + str(event.connection.dpid))
            return
        packetInSwitch = self.switchs[event.connection.dpid]     # gives switch dpid from which we got packetin
        
        # If we have an IGMP PacketIn
        igmp_pkt = event.parsed.find(pkt.igmpv3)
        if not igmp_pkt is None:
            # Source IP of IGMP packet
            if (packetInSwitch,event.port) not in self.active_hosts:
                self.active_hosts.append((packetInSwitch,event.port))
                self.flag_raise = 1

            # igmp_pkt.parse(self)
            # Removing a host form active list of hosts and setting flag to flush existing flows
            if 'CHANGE_TO_INCLUDE_MODE' in str(igmp_pkt):
                self.flag_raise = 1
                self.active_hosts.remove((packetInSwitch,event.port))

            log.debug('Active host are: ' + str(self.active_hosts))

            log.debug(str(packetInSwitch) + ':' + str(event.port) + '| Received IGMP packet')
            ipv4_pkt = event.parsed.find(pkt.ipv4)
            log.debug(str(packetInSwitch) + ':' + str(event.port) + '| ' + str(igmp_pkt) + ' from Host: ' + str(ipv4_pkt.srcip))
            log.debug('')

            # see if this IGMP message was received from a neighbouring switch, drop additional IGMP packets on this port
            for neighbour in self.adjacency[packetInSwitch]:
                if self.adjacency[packetInSwitch][neighbour] == event.port:
                    log.debug(str(packetInSwitch) + ':' + str(event.port) + '| IGMP packet from neighbouring switch.')  
                    self.drop_packet(event)
                    return
            
            #Flushing (Deleting) Flows in case of a new igmp request so that new shortest path can be calcualated and then new flows can be installed
            self.node_list = list(self.node_set)
            if self.flag_raise == 1:
                for switch_dpid in self.node_list:
                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x800   # IPV4
                    msg.match.nw_dst = self.dst_mcast_address
                    msg.match.nw_src = self.src_ip
                    msg.match.in_port = None
                    msg.command = of.OFPFC_DELETE
                    connection = core.openflow.getConnection(int((str(switch_dpid))[-2:],16))
                    if connection is not None:
                        connection.send(msg)
                    else:
                        log.warn('Can not connect to switch: ' + dpid_to_str(switch_dpid))
                self.installed_node_list = []
                self.flag_raise=0

            # Drop the IGMP packet to prevent it from being uneccesarily forwarded to neighbours (switches)
            self.drop_packet(event)
            return
            
        # if we have a ipv4 packetIn fromthe switch 
        ipv4_pkt = event.parsed.find(pkt.ipv4)
        if not ipv4_pkt is None:
        	# Data packet. IPv4 Packets 
            self.dst_mcast_address = ipv4_pkt.dstip                           
            self.src_ip = ipv4_pkt.srcip

            if not self.active_hosts:    # Correct proceed - If we dont have active hosts move ahead and donot do unnecessary processing
                return

            if ipv4_pkt.dstip.inNetwork('224.0.0.0/4'):
                
                log.debug('Report:')
                log.debug('Active hosts : ' + str(self.active_hosts))
                log.debug('')
                         

                if not self.active_hosts is None: 

                    # Extracting node set and edge lists from  topology obtained from discovery.py
                    new_topo_graph = []
                    new_node_list = []
                    for switch1 in self.adjacency:
                        for switch2 in self.adjacency[switch1]:
                            if (switch1,switch2) not in new_topo_graph:
                                new_topo_graph.append((switch1, switch2))
                            if not switch2 in new_node_list:
                                new_node_list.append(switch2)
                        if not switch1 in new_node_list:
                            new_node_list.append(switch1)
                    self.topology_graph = new_topo_graph
                    self.node_set = Set(new_node_list)
                
                    curr_topo_graph = self.topology_graph
                    # log.debug(str(curr_topo_graph))                   #correct  - Uncomment to observe current graph

                    self.node_list = list(self.node_set)				#correct  - Uncomment to observe that all nodes from graph are fetched by discovery.py 
                    # log.debug(str(self.node_list))
                    

                    # Calculating weights for edges randomly
                    weighted_topo_graph = []
                    link_weight = 1   # default weight
                    random.seed(1)    									# To generate same weight and graph always for one session since we will call this function for every ipv4 packeetIN

                    while(curr_topo_graph):
                        edge=curr_topo_graph[0]                    
                        link_weight = random.randint(1,50)
                        # log.debug('Switch DPID: ' + str(edge[0]) + ' Port: ' + str(output_port) + ' Weight is : ' + str(link_weight))         # uncomment to reint weight of each edge
                        weighted_topo_graph.append([edge[0], edge[1], link_weight])               # weight of one link for transmission from both direction should be same
                        weighted_topo_graph.append([edge[1], edge[0], link_weight])
                        revedge = (edge[1], edge[0])
                        curr_topo_graph.remove(revedge)                                           
                        curr_topo_graph.remove(edge)
                    self.weighted_topo_graph = weighted_topo_graph

                    # log.debug('Weighted Graph is : ' + str(weighted_topo_graph))                 # Uncomment to observe weighted topology of the graph
                    # log.debug('')

                    # Calculating Dijkstras path for all modes.   path_tree_map has elements which are sources. Path form each source to all other nodes are stored in path_tree_map.
                    nodes = set(self.node_list)
                    edges = self.weighted_topo_graph
                    graph = defaultdict(list)

                    for src,dst,cost in edges:
                        graph[src].append((cost, dst))
                    path_tree_map = defaultdict(lambda : None)
                    queue, seen = [(0,packetInSwitch,())], set()
                    while queue:
                        (cost,N1,path) = heappop(queue)
                        if N1 not in seen:
                            seen.add(N1)
                            path = (N1, path)
                            path_tree_map[N1] = path
                 
                            for next_cost, N2 in graph.get(N1, ()):
                                if N2 not in seen:
                                    new_path_cost = cost + next_cost
                                    heappush(queue, (new_path_cost, N2, path))
                    self.path_tree_map = path_tree_map                   

                    # Below three lines will print path form a particular source to all nodes in the MAP
                    # log.debug('Calculated shortest path tree for source at switch_dpid: ' + str(packetInSwitch))
                    # for node in self.path_tree_map:
                        # log.debug('Path to Node ' + str(node) + ': ' + str(self.path_tree_map[node]))
                    
                    

                    # Installing Flows for those paths whoch connect source to our active hosts
                    outgoing_flow_rules = defaultdict(lambda : None)    # rules to be added
                    
                    # Calculate the paths for the specific receivers that are currently active from the previously calculated MST
                    edges_to_install = []
                    calculated_path_switch_dpids = []

                    for receiver in self.active_hosts:
                        if receiver[0] in calculated_path_switch_dpids:   									# if we already have flow for the switch
                            continue

                        receiver_path = self.path_tree_map[receiver[0]]   								    # getting tree for a particular receiver switch  
                        
                        log.debug('Path for '+ str(receiver[0]) +' receiver is :' + str(receiver_path))     # Prints path for clients

                        # Extracting edge tuples form the datastructure
                        while receiver_path[1]:
                            if (receiver_path[1][0], receiver_path[0]) not in edges_to_install:
                                edges_to_install.append((receiver_path[1][0], receiver_path[0]))
                            receiver_path = receiver_path[1]
                        calculated_path_switch_dpids.append(receiver[0])
                    
                    log.debug('')
                    log.debug('Edges installed: ' + str(edges_to_install))
                    log.debug('')
 
                    for edge in edges_to_install:
                        if edge[0] in outgoing_flow_rules:
                            
                            # Add the output action to an existing rule if it has already been generated
                            output_port = self.adjacency[edge[0]][edge[1]]            # adjacency = reouter , next reouter and port to next switch
                            outgoing_flow_rules[edge[0]].actions.append(of.ofp_action_output(port = output_port))
                            
                        else:
                            # Otherwise, generate a new flow mod
                            msg = of.ofp_flow_mod()
                            msg.hard_timeout = 0
                            msg.idle_timeout = 0
                            
                            if edge[0] in self.installed_node_list:
                                msg.command = of.OFPFC_MODIFY
                            else:
                                msg.command = of.OFPFC_ADD

                            msg.match.dl_type = 0x800   # IPV4
                            msg.match.nw_dst = self.dst_mcast_address
                            msg.match.nw_src = self.src_ip                          
                            output_port = self.adjacency[edge[0]][edge[1]]
                            msg.actions.append(of.ofp_action_output(port = output_port))
                            outgoing_flow_rules[edge[0]] = msg
                                   
                    for receiver in self.active_hosts:
                        
                        if receiver[0] in outgoing_flow_rules:
                            # Add the output action to an existing rule if it has already been generated
                            output_port = receiver[1]
                            outgoing_flow_rules[receiver[0]].actions.append(of.ofp_action_output(port = output_port))
                           
                        else:
                            # Otherwise, generate a new flow mod
                            msg = of.ofp_flow_mod()
                            msg.hard_timeout = 0
                            msg.idle_timeout = 0
                            if receiver[0] in self.installed_node_list:
                                msg.command = of.OFPFC_MODIFY
                            else:
                                msg.command = of.OFPFC_ADD
                            msg.match.dl_type = 0x800   # IPV4
                            msg.match.nw_dst = self.dst_mcast_address
                            msg.match.nw_src = self.src_ip
                            output_port = receiver[1]
                            msg.actions.append(of.ofp_action_output(port = output_port))
                            outgoing_flow_rules[receiver[0]] = msg
                           
                    # Setup empty rules for any switch not involved in this path
                    for switch_dpid in self.node_list:
                        if not switch_dpid in outgoing_flow_rules and switch_dpid in self.installed_node_list:
                            msg = of.ofp_flow_mod()
                            msg.match.dl_type = 0x800   # IPV4
                            msg.match.nw_dst = self.dst_mcast_address
                            msg.match.nw_src = self.src_ip
                            msg.command = of.OFPFC_DELETE
                            outgoing_flow_rules[switch_dpid] = msg
                    
                    # Installing Flows on each switch one by one
                    for key in outgoing_flow_rules.keys():
                    	# AS OF NOW THIS PROGRAM WORKS ONLY FOR 16 SWITCHES MAX. IMPROVE INFURTURE WITH A FUNCTION TO CONVERT MAC ADDRESS TO INTEGER : int((str(key))[-2:],16)
                        connection = core.openflow.getConnection(int((str(key))[-2:],16))
                        if connection is not None:
                            connection.send(outgoing_flow_rules[key]) 
                            if not outgoing_flow_rules[key].command == of.OFPFC_DELETE:         
                                self.installed_node_list.append(key)
                            else:
                                self.installed_node_list.remove(key)
                        else:
                            log.warn('Can not connect to switch switch: ' + str(key))

                    self.flag_raise = 1
                 
def launch():
    core.registerNew(CastflowManager)


