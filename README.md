# Controller-Module-Design-for-SDN
Designed an IGMP handler to allow client multicast proposals to be deployed in a live OpenFlow SDN network. Confirmed multicast operation using VLC server and dynamic recalculation of Dijkstra’s least cost path

Requirements: 
Mininet Machine up and running over Virtual platform with POX installation

Follow the steps to Run the Project:

Prerequisite:
Place file ‘multicast.py’ in /home/mininet/pox/pox/openflow/

Place file ‘igmpv3.py’ in /home/mininet/pox/pox/lib/packet/

Steps:
1. Run the MiniEdit network

2. Run the POX controller using command :
	sudo ~/pox/pox.py samples.pretty_log openflow.discovery openflow.multicast forwarding.l3_learning 	log.level  --WARNING –openflow.multicast=DEBUG

3. Run the clients first and then the server
	
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




