package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;

import java.nio.ByteBuffer;
import java.util.Map;
/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
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

		// If no RouteEntry matches, your router should drop the packet.
		RouteEntry desiredRouteEntry = this.routeTable.lookup(p.getDestinationAddress());
		if (desiredRouteEntry == null)
		{
			generateIcmpMessage(p, inIface, (byte)3, (byte)0);
			System.out.println("----------------------------------");
			System.out.println("No RouteEntry matches, drop the packet!");
			System.out.println("----------------------------------");
			return;
		}
		
		// Find an issuse when switch doing broadcast, the router will send the broadcast packet back to switch.
		if (desiredRouteEntry.getInterface() == inIface)
		{
			System.out.println("----------------------------------");
			System.out.println("Should not send the broadcast packet back to switch, drop the packet!");
			System.out.println("----------------------------------");
			return;
		}

		// Need to find the Mac address of the outgoing interface as source.
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
			generateIcmpMessage(p, inIface, (byte)3, (byte)1);
			System.out.println("----------------------------------");
			System.out.println("No ArpEntry matches for destination ip, drop the packet!");
			System.out.println("----------------------------------");
			return;
		}

		System.out.println("Setting source mac address to: " + outgoingArpEntry.getMac().toString());
		etherPacket.setSourceMACAddress(outgoingArpEntry.getMac().toString());
		System.out.println("Setting destination mac address to: " + desiredArpEntry.getMac().toString());
		etherPacket.setDestinationMACAddress(desiredArpEntry.getMac().toString());
		
		// Update checksum. Call the serialize() function, since it will recompute the checksum onec the checksum is 0.
		p.resetChecksum();
		p.serialize();

		System.out.println("Send the packet out of interface: " + desiredRouteEntry.getInterface());
		
		sendPacket(etherPacket, desiredRouteEntry.getInterface());
		
		/********************************************************************/
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
		
		// borrow the compute checkcum code from the serialize() method in the IPv4 class.
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

	// get this part of code from TA's solutions, it should be more reliable than ours.
	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        {
			generateIcmpMessage(ipPacket, inIface, (byte)3, (byte)0);
			return; }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        { return; }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}