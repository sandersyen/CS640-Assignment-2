package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

import java.nio.ByteBuffer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/** ARP queue **/
	private ConcurrentHashMap<Integer, List<Ethernet>> arpQueue;
	
	private final boolean DEBUG_ARP = true;  // debug enable

	private Timer sendTimer;
	private Timer cleanTimer;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpQueue = new ConcurrentHashMap<Integer, List<Ethernet>>();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */
		switch (etherPacket.getEtherType())
		{
			case Ethernet.TYPE_IPv4:
			{
				this.handleIpPacket(etherPacket, inIface);
				break;
			}
			case Ethernet.TYPE_ARP:
			{
				this.handleArpPacket(etherPacket, inIface);
				break;
			}
			default:
			{
				System.out.println("----------------------------------");
				System.out.println("Packet type is wrong, drop the packet!");
				System.out.println("----------------------------------");
				break;
			}

		}
		/********************************************************************/
	}
	
	/*******************************************************************/
	/******************************IPv4*********************************/
	/*******************************************************************/
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		
		// packet is not IPv4, should drop the packet.
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("----------------------------------");
			System.out.println("The packet is not IPv4, drop the packet!");
			System.out.println("----------------------------------");
			return;
		}

		// use getPayload() method of the Ethernet class to get the header, and cast the result to IPv4
		IPv4 p = (IPv4) etherPacket.getPayload();

		// If the checksum is incorrect, drop the packet.
		if (!verifyChecksum(p)) {
			System.out.println("----------------------------------");
			System.out.println("The checksum is incorrect, drop the packet!");
			System.out.println("----------------------------------");
			return;
		}

		// decrement the IPv4 packet TTL by 1.
		p.setTtl((byte)(p.getTtl() - 1));

		// Drop the packet if TTL is less than 1
		if ((int)p.getTtl() <= 0) {
			generateIcmpMessage(p, inIface, (byte)11, (byte)0);
			System.out.println("----------------------------------");
			System.out.println("TTL is 0, drop the packet!");
			System.out.println("----------------------------------");
			return;
		}

		if (p.getProtocol() == IPv4.PROTOCOL_UDP) {
			UDP udpPacket = (UDP)p.getPayload();
			if (udpPacket.getDestinationPort() == UDP.RIP_PORT && p.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9")) {
				RouteEntry inEntry = routeTable.lookup(p.getSourceAddress());
				//Packets that match this criteria are RIP requests or responses. 
				RIPv2 rip = (RIPv2) udpPacket.getPayload();
				if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
					for (RIPv2Entry entry : rip.getEntries()) {
						RouteEntry routeEntry = routeTable.lookup(entry.getAddress());
						//If the term in RIP is not in the table
						if (routeEntry==null) {
							routeTable.insert(entry.getAddress() & entry.getSubnetMask(), p.getSourceAddress(), entry.getSubnetMask(), inIface, entry.getMetric() + 1);
						} else {
							if (routeEntry.getDistance() > (entry.getMetric() + inEntry.getDistance() + 1)) {
								routeTable.update(entry.getAddress() & entry.getSubnetMask(), entry.getSubnetMask(), p.getSourceAddress(), inIface, (entry.getMetric() + inEntry.getDistance()));
								this.sendUnsolicitedRIP();
							}
						}
						routeTable.update_time(entry.getAddress() & entry.getSubnetMask(), entry.getSubnetMask());
					}
				} else if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
					sendPacket(this.generateRipPacket(etherPacket, inIface, true, RIPv2.COMMAND_RESPONSE), inIface);
				}
				System.out.println("----------------------------------");
				System.out.println("The packet is RIP packet!");
				System.out.println("----------------------------------");
				return;
			}
		}

		// Update checksum. Call the serialize() function, since it will recompute the checksum once the checksum is 0.
     	p.resetChecksum();
     	p.serialize();
     	
		// If the packet destination IP address exactly matches one of the interfaces IP addresses, drop the packet.
		Map<String,Iface> tempInterfaces = this.getInterfaces();
		for (String key : tempInterfaces.keySet())
		{
			if (tempInterfaces.get(key).getIpAddress() == p.getDestinationAddress())
			{
				boolean drop = true;

				if (p.getProtocol() == IPv4.PROTOCOL_UDP || p.getProtocol() == IPv4.PROTOCOL_TCP) {
					generateIcmpMessage(p, inIface, (byte)3, (byte)3);
				} else if (p.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP)p.getPayload();
					if (icmpPacket.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
						generateIcmpMessage(p, inIface, (byte)0, (byte)0);
						drop = false;
					}
				}


				if (drop) {
					System.out.println("----------------------------------");
					System.out.println("the packet destination IP address matches, drop the packet!");
					System.out.println("----------------------------------");
					return;
				}
			}
		}
		
		// Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();
        
        RouteEntry desiredRouteEntry = this.routeTable.lookup(dstAddr);
        // If no RouteEntry matches, your router should drop the packet.
     	if (desiredRouteEntry == null)
     	{
     		generateIcmpMessage(ipPacket, inIface, (byte)3, (byte)0);
     		System.out.println("----------------------------------");
     		System.out.println("No RouteEntry matches, drop the packet!");
     		System.out.println("----------------------------------");
     		return;
     	}
     	
     	// Find an issue when switch doing broadcast, the router will send the broadcast packet back to switch.
     	Iface outIface = desiredRouteEntry.getInterface();
     	if (outIface == inIface)
     	{
     		System.out.println("----------------------------------");
     		System.out.println("Should not send the broadcast packet back to switch, drop the packet!");
     		System.out.println("----------------------------------");
     		return;
     	}
     	// Set source MAC address in Ethernet header
     	etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
     	
     	// If no gateway, then nextHop is IP destination
     	int nextHop = desiredRouteEntry.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry desiredArpEntry = this.arpCache.lookup(nextHop);
        if (null == desiredArpEntry)
        { 
            System.out.println("----------------------------------");
     		System.out.println("No ArpEntry matches for destination ip, start to send ARP requests!");
     		System.out.println("----------------------------------");
     		this.arpRequests(etherPacket, inIface, outIface, nextHop);
     		return; 
     	}
        etherPacket.setDestinationMACAddress(desiredArpEntry.getMac().toBytes());
        //System.out.println("Send the packet out of interface: " + outIface);
        this.sendPacket(etherPacket, outIface);
 		
        /* old version
 		// Need to find the MAC address of the outgoing interface as source.
 		ArpEntry outgoingArpEntry = this.arpCache.lookup(desiredRouteEntry.getInterface().getIpAddress());
 		if (outgoingArpEntry == null)
 		{
 			System.out.println("----------------------------------");
 			System.out.println("No ArpEntry matches for outgoing interface, drop the packet!");
 			System.out.println("----------------------------------");
 			return;
 		}

 		int dstIp = (desiredRouteEntry.getGatewayAddress() != 0) ? desiredRouteEntry.getGatewayAddress() : p.getDestinationAddress();
 		// If no ArpEntry matches, your router should drop the packet.
 		ArpEntry desiredArpEntry = this.arpCache.lookup(dstIp);
 		if (desiredArpEntry == null)
 		{
 			System.out.println("----------------------------------");
 			System.out.println("No ArpEntry matches for destination ip, send ARP requests!");
 			System.out.println("----------------------------------");
 			this.arpRequests(etherPacket, inIface, desiredRouteEntry.getInterface(), dstIp);
 			return;
 		}

 		System.out.println("Setting source mac address to: " + outgoingArpEntry.getMac().toString());
 		etherPacket.setSourceMACAddress(outgoingArpEntry.getMac().toString());
 		System.out.println("Setting destination mac address to: " + desiredArpEntry.getMac().toString());
 		etherPacket.setDestinationMACAddress(desiredArpEntry.getMac().toString());
 		*/ 
    }

	/**
	 * Check the correctness of a Ethernet packet.
	 * @param packet the IPv4 packet that was received.
	 * @return the correctness of a Ethernet packet.
	 */
	private boolean verifyChecksum(IPv4 packet)
	{
		ByteBuffer bb = ByteBuffer.wrap(packet.serialize());
		bb.rewind();

		// borrow the compute checksum code from the serialize() method in the IPv4 class.
		int accumulation = 0;
		byte headerLength = packet.getHeaderLength();
		for (int i = 0; i < headerLength * 2; ++i) {
			int temp = 0xffff & bb.getShort();
			// calculate the sum of each 16 bit value within the header, skipping only the checksum field itself.
			if (i != 5) {
				accumulation += temp;
			}
		}

		accumulation = ((accumulation >> 16) & 0xffff)
				+ (accumulation & 0xffff);
		short checksum = (short) (~accumulation & 0xffff);

        return checksum == packet.getChecksum();
	}
	
	/*******************************************************************/
	/******************************ICMP*********************************/
	/*******************************************************************/

	/**
	 * Generate ICMP message for different cases.
	 * @param packet the IPv4 packet that was received.
	 * @return the correctness of a Ethernet packet.
	 */
	private void generateIcmpMessage(IPv4 packet, Iface inIface, byte type, byte code)
	{
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);

		IPv4 ip = new IPv4();
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(packet.getSourceAddress());

		ICMP icmp = new ICMP();
		icmp.setIcmpType(type);
		icmp.setIcmpCode(code);

		Data data = new Data();

		if (type != 0) {
			int oriPacketHeaderLength = packet.getHeaderLength() * 4;
			byte[] ICMPPayload = new byte[4 + oriPacketHeaderLength + 8];
			byte[] oriIPPacket = packet.serialize();
			for (int i = 0; i < (oriPacketHeaderLength + 8); ++i) {
				ICMPPayload[i + 4] = oriIPPacket[i];
			}
			data.setData(ICMPPayload);
		} else {
			ICMP icmpPacket = (ICMP)packet.getPayload();
			ip.setSourceAddress(packet.getDestinationAddress());
			data.setData(icmpPacket.getPayload().serialize());
		}
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		this.forwardIpPacket(ether, null);
	}

	/*******************************************************************/
	/*******************************ARP*********************************/
	/*******************************************************************/

	private void handleArpPacket(Ethernet etherPacket, Iface inIface)
	{
		ARP arpPacket = (ARP)etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		// handle ARP Requests
		if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
			if (targetIp == inIface.getIpAddress()) {
				if (DEBUG_ARP) 
				{ System.out.println("-----receive ARP request-----");}
			
				// generate ARP reply packet
				Ethernet arpReplyPacket = new Ethernet();
		    	// construct Ethernet header
		    	arpReplyPacket.setEtherType(Ethernet.TYPE_ARP);
		    	arpReplyPacket.setSourceMACAddress(inIface.getMacAddress().toBytes());
		    	arpReplyPacket.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		    	// construct ARP header
		    	ARP arpHeader = new ARP();
		    	arpHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
		    	arpHeader.setProtocolType(ARP.PROTO_TYPE_IP);
		    	arpHeader.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		    	arpHeader.setProtocolAddressLength((byte) 4);
		    	arpHeader.setOpCode(ARP.OP_REPLY);
		    	arpHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		    	arpHeader.setSenderProtocolAddress(inIface.getIpAddress());
		    	arpHeader.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		    	arpHeader.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
		    	// link together & send reply packet
		    	arpReplyPacket.setPayload(arpHeader);
		    	
		    	if (DEBUG_ARP) 
				{ System.out.println("-----send ARP reply-----");}
				sendPacket(arpReplyPacket, inIface);
			}
			else{
				System.out.println("----------------------------------");
				System.out.println("Target IP protocol address doesn't match interface IP address, drop this ARP packet!");
				System.out.println("----------------------------------");
				return;
			}
		}

		// handle ARP Replies
		if (arpPacket.getOpCode() == ARP.OP_REPLY){
			if (DEBUG_ARP) 
			{ System.out.println("-----receive ARP reply-----");}
			// add entry to ARP cache
			MACAddress arpReplyMACAddr = new MACAddress(arpPacket.getSenderHardwareAddress());
			int arpReplyIp = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress());
			arpCache.insert(arpReplyMACAddr, arpReplyIp);
			// dequeue waiting packets
			synchronized(arpQueue)
			{
				List<Ethernet> sendQueue = arpQueue.get(arpReplyIp);
				if (sendQueue != null)
				{
					if (DEBUG_ARP) 
					{ System.out.println("-----dequeue waiting packets-----");}
					for (Ethernet ether : sendQueue)
					{
						ether.setDestinationMACAddress(arpPacket.getSenderHardwareAddress());
						sendPacket(ether, inIface);
					}
				}
			}
		}

	}

	private void arpRequests(final Ethernet etherPacket, final Iface inIface, final Iface outIface, final int dstip)
	{
		synchronized(arpQueue) {
			if (this.arpQueue.containsKey(dstip)) {
				if (DEBUG_ARP) 
				{ System.out.println("-----add packet to the queue, waiting-----");}
				this.arpQueue.get(dstip).add(etherPacket);
			}
			else {
				if (DEBUG_ARP) 
				{ System.out.println("-----create a new queue-----");}
				List<Ethernet> newArpQueue = new ArrayList<Ethernet>();
				newArpQueue.add(etherPacket);
				arpQueue.put(dstip, newArpQueue);
		    	// send ARP request
				Timer timer = new Timer();
				timer.schedule(new TimerTask() {
					int count = 0;
					@Override
		            public void run() {
		            	try {
		            		if (arpCache.lookup(dstip) != null) {
		            			this.cancel();
		            		}
		            		else {
		            			if (count > 2) {
		            				if (DEBUG_ARP) 
		            				{ System.out.println("-----Time Out, Drop this queue-----");}
		            				arpQueue.remove(dstip);
		            				generateIcmpMessage((IPv4) etherPacket.getPayload(), inIface, (byte)3, (byte)1);
		            				this.cancel();
		            			}
		            			else {
		            				sendARPReqPacket(etherPacket, inIface, outIface, dstip);
		            				count++;
		            				{ System.out.println("-----Send ARP request No." + count + "-----");}
		            			}
		            		}
		            	} catch(Exception e) {
							e.printStackTrace(System.out);
						}
		            }
				}, 0, 1000);
			
			}
		}
	}
	
	private void sendARPReqPacket(Ethernet etherPacket, Iface inIface, Iface outIface, int ip)
	{
		// generate ARP request packet
		Ethernet arpRequestPacket = new Ethernet();
		// construct Ethernet header
		arpRequestPacket.setEtherType(Ethernet.TYPE_ARP);
		arpRequestPacket.setSourceMACAddress(inIface.getMacAddress().toBytes());
		arpRequestPacket.setDestinationMACAddress(Ethernet.toMACAddress("FF:FF:FF:FF:FF:FF"));
		// construct ARP header
		ARP arpReqHeader = new ARP();
		arpReqHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpReqHeader.setProtocolType(ARP.PROTO_TYPE_IP);
		arpReqHeader.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arpReqHeader.setProtocolAddressLength((byte) 4);
		arpReqHeader.setOpCode(ARP.OP_REQUEST);
		arpReqHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arpReqHeader.setSenderProtocolAddress(inIface.getIpAddress());
		arpReqHeader.setTargetHardwareAddress(Ethernet.toMACAddress("00:00:00:00:00:00"));
		arpReqHeader.setTargetProtocolAddress(ip);
		// link together & send reply packet
		arpRequestPacket.setPayload(arpReqHeader);
		this.sendPacket(arpRequestPacket, outIface);
	}
	
	public void startingRIP()
	{
		for (Iface entry : this.getInterfaces().values()) {
			this.getRouteTable().insert(entry.getIpAddress() & entry.getSubnetMask(), 0, entry.getSubnetMask(), entry);

			// send RIP request 
			sendPacket(generateRipPacket(new Ethernet(), entry, false, RIPv2.COMMAND_REQUEST), entry);
		}

		// send an unsolicited RIP response out all of the routers interfaces every 10 seconds thereafter.
		this.sendTimer = new Timer();
		this.sendTimer.scheduleAtFixedRate(new unsolicitedRIP(), 10000, 10000);

		// Your router should time out route table entries for which an update has not been received for more than 30 seconds. 
		this.cleanTimer = new Timer();
		this.cleanTimer.scheduleAtFixedRate(new timeOutRIP(), 1000, 1000);
	}

	private Ethernet generateRipPacket(Ethernet packet, Iface inIface, boolean isSpecific, byte command)
	{
		IPv4 sourceIpv4 = (IPv4) packet.getPayload();
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toString());
		IPv4 ip = new IPv4();
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setTtl((byte)15);
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);		
		udp.setDestinationPort(UDP.RIP_PORT);

		RIPv2 rip = new RIPv2();

		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);

		if (isSpecific) {
			ether.setDestinationMACAddress(packet.getSourceMACAddress().toString());
			ip.setDestinationAddress(sourceIpv4.getSourceAddress());
		} else {
			ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
			ip.setDestinationAddress("224.0.0.9");
		}

		// construct rip table into rip packet

		for (RouteEntry entry : this.routeTable.getEntries())
		{
			int address = entry.getDestinationAddress();
			int mask = entry.getMaskAddress();
			int next = inIface.getIpAddress();
			int distance = entry.getDistance();
			
			RIPv2Entry ripEntry = new RIPv2Entry(address, mask, distance);
			ripEntry.setNextHopAddress(next);
			rip.addEntry(ripEntry);
		}
		
		ether.serialize();

		return ether;
	}

	public void sendUnsolicitedRIP()
	{
		for (Iface entry : this.interfaces.values()) {
			// send an unsolicited RIP response
			sendPacket(generateRipPacket(new Ethernet(), entry, false, RIPv2.COMMAND_RESPONSE), entry);
		}
		return;
	}
	
	public void cleanRIPTable()
	{
		this.getRouteTable().cleanTable();
	}

	class unsolicitedRIP extends TimerTask
	{
		public void run()
		{
			sendUnsolicitedRIP();
		}
	}

	class timeOutRIP extends TimerTask
	{
		public void run()
		{
			cleanRIPTable();
		}
	}
}
