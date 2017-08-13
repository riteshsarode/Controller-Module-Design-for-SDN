# Controller-Module-Design-for-SDN

This is an implementation of IGMP handler module to allow dynamic client multicast proposals to be deployed in a OpenFlow SDN network.

Requirements: 
Mininet Machine up and running over Virtual platform with POX Controller installation

Follow the steps to Run the Demo for Multicast streaming in a SDN Network:

Prerequisite:
1. Place file ‘multicast.py’ in /home/mininet/pox/pox/openflow/

2. Place file ‘igmpv3.py’ in /home/mininet/pox/pox/lib/packet/

Steps:
1. Run MiniEdit. Make your own SDN Network or use the final_network.mn file. 

2. Run the POX controller using command :
	sudo ~/pox/pox.py samples.pretty_log openflow.discovery openflow.multicast forwarding.l3_learning 	log.level  --WARNING –openflow.multicast=DEBUG

3. Run the clients first and then the server
	
	Choose your Server and Clients. Use the following commands to run them
	
	On Clients :   route add –host <Multicast_address> <server_host>-Ethernet
	(First)	      iperf –s –B <Multicast_address> -u –f m –i 5
		      
		      e.g. route add –host 224.10.10.10 h9-eth0
		             iperf –s –B 224.10.10.10 –u –f m –i 5

	On Server :    route add –host <Multicast_address> <server_host>-Ethernet
	(Next)	      iperf –c <Multicast_address> -u –b 0.5m –f m –i 5 –t 60
		      
		      e.g. route add –host 224.10.10.10 h1-eth0
		              iperf –c 224.10.10.10 –u –b 0.5m –f m –i 5 –t 60

4. In POX and Wireshark, look for the following:
	i. Reception of IGMP packets
	ii. Dijkstra’s shortest path map
	iii. Installed paths from server to active clients

5. If new hosts want to join the multicast group in the existing network, run the command
	On Clients :   route add –host <Multicast_address> <server_host>-Ethernet
		      iperf –s –B <Multicast_address> -u –f m –i 5

6. In POX and Wireshark, look for the updated installed paths from serve to all clients




