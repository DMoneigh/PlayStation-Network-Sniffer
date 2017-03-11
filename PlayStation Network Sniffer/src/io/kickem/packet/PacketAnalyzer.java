package io.kickem.packet;

import java.net.InetAddress;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;

import io.kickem.Sniffer;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

/**
 * Analyzes packets.
 * 
 * @author Desmond Jackson
 */
public class PacketAnalyzer extends Thread {

	/**
	 * The packet capturing handle.
	 */
	private PcapHandle handle;

	/**
	 * Analyzes the specified network's packets.
	 * 
	 * @param network The network to analyze
	 * 
	 * @throws PcapNativeException if error occurred
	 */
	public PacketAnalyzer(PcapNetworkInterface network) throws PcapNativeException {
		handle = network.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
		System.out.println("Analyzing packets on: " + network.getName());
	}

	@Override
	public void run() {
		while (handle.isOpen()) {
			try {
				Packet packet = handle.getNextPacket();
				if (packet != null) {
					IpV4Packet ipv4 = (IpV4Packet) packet.get(IpV4Packet.class);
					if (ipv4 != null) {
						IpV4Header header = ipv4.getHeader();
						if (header != null) {
							UdpPacket udp = (UdpPacket) ipv4.get(UdpPacket.class);
							if (udp != null) {
								char[] data = new String(udp.getRawData()).toCharArray();
								InetAddress src = header.getSrcAddr();
								InetAddress dst = header.getDstAddr();
								if (isPs4(data)) {
									if (!src.isSiteLocalAddress() && !Sniffer.PLAYERS.containsKey(src.getHostAddress()))
										Sniffer.PLAYERS.put(src.getHostAddress(), src.getHostAddress());
									if (!dst.isSiteLocalAddress() && !Sniffer.PLAYERS.containsKey(dst.getHostAddress()))
										Sniffer.PLAYERS.put(dst.getHostAddress(), dst.getHostAddress());
								} else if (isPs3(data)) {
									String first = grabUsername(data, 1);
									String second = grabUsername(data, 2);
									if (!src.isSiteLocalAddress() && (!Sniffer.PLAYERS.containsKey(first) || !Sniffer.PLAYERS.get(first).equals(src.getHostName())))
											Sniffer.PLAYERS.put(first, src.getHostAddress());
									if (!dst.isSiteLocalAddress() && (!Sniffer.PLAYERS.containsKey(second) || !Sniffer.PLAYERS.get(second).equals(dst.getHostName())))
											Sniffer.PLAYERS.put(second, src.getHostAddress());
								}
							}
						}
					}
				}
			} catch (NotOpenException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Grabs the player username.
	 * 
	 * @param data The UDP packet data
	 * 
	 * @param option The first or second player
	 * 
	 * @return The player username
	 */
	private String grabUsername(char data[], int option) {
		StringBuilder sb = new StringBuilder();
		int[] signature = option == 1 ? new int[] {0, 0, 0} : new int[] {0, 1, 0, 0, 0, 0, 0, 0};
		int sigCount = 0;
		int length = 0;
		for (int i = 0; i < data.length; i++) {
			int value = data[i];
			if (sigCount == signature.length) {
				if (value != 0 && length != 16) {
					sb.append((char) value);
					length++;
				} else
					return sb.toString();
			} else if (value == signature[sigCount])
				sigCount++;
			else
				sigCount = 0;
		}
		return sb.toString();
	}

	/**
	 * Checks if packet is from PlayStation 3.
	 * 
	 * @param date The UDP packet data
	 * 
	 * @return false if packet is not from PlayStation 3
	 */
	private boolean isPs3(char[] data) {
		int zeros = 0;
		for (int i = 0; i < data.length; i++) {
			if (zeros == 9) return true;
			if (data[i] == 0 || (data[i] == 1 && zeros == 1))
				zeros++;
			else
				zeros = 0;
		}
		return false;
	}

	/**
	 * Checks if packet is from PlayStation 4.
	 * 
	 * @param packet The UDP packet
	 * 
	 * @return false if packet is not from PlayStation 4
	 */
	private boolean isPs4(char[] data) {
		int zeros = 0;
		for (int i = 0; i < data.length; i++) {
			if (zeros == 12) return true;
			if (data[i] == 0)
				zeros++;
			else
				zeros = 0;
		}
		return false;
	}

}
