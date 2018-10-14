package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import static java.util.concurrent.TimeUnit.*;

/**
 * @author Aaron Gember-Jacobson
 */

public class Switch extends Device
{
	private ConcurrentHashMap<MACAddress, SwitchEntry> switchTable;
	private final long TIMEOUT = 15000;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */

	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		switchTable = new ConcurrentHashMap<MACAddress, SwitchEntry>();
		timer();
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

		MACAddress srcMAC = etherPacket.getSourceMAC();
		MACAddress dstMAC = etherPacket.getDestinationMAC();

		SwitchEntry srcEntry = new SwitchEntry(srcMAC, inIface);
		switchTable.put(srcMAC, srcEntry);

		if (switchTable.containsKey(dstMAC)) {
			SwitchEntry dstEntry = switchTable.get(dstMac);
			Iface outIface = dstEntry.getIface();
			sendPacket(etherPacket, outIface);
		}
		else {
			for (Iface ifa : interfaces.values()) {
				if (!inIface.equals(ifa)){
					sendPacket(etherPacket, ifa);
				}
			}
		}
		/********************************************************************/
	}

	private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

	public void timer() {
        scheduler.scheduleAtFixedRate(new Runnable() {
            public void run() {
            	try {
            		for (Map.Entry<MACAddress, SwitchEntry> entry : switchTable.entrySet()) {
						long leftTime = System.currentTimeMillis() - entry.getValue().getLastUpdateTime();
						if (leftTime > TIMEOUT){
							switchTable.remove(entry.getKey());
						}
            		}
            	} catch(Exception e) {
					e.printStackTrace(System.out);
				}
            }
        }, 0, 1, SECONDS);
    }
}

class SwitchEntry {
	private MACAddress macAddr;
	private Iface iface;
	private long lastUpdateTime;

	public SwitchEntry(MACAddress macAddr, Iface iface) {
		this.macAddr = macAddr;
		this.iface = iface;
		this.lastUpdateTime = System.currentTimeMillis();
	}

	public MACAddress getMACAddress() {
		return this.macAddr;
	}

	public Iface getIface() {
		return this.iface;
	}

	public long getLastUpdateTime() {
		return this.lastUpdateTime;
	}
}
