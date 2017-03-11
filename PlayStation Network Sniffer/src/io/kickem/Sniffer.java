package io.kickem;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import io.kickem.packet.PacketAnalyzer;

/**
 * KickEm.IO Sniffer
 * 
 * @author Desmond Jackson
 */
public class Sniffer extends Thread {
	
	/**
	 * A list of detected players.
	 */
	public static final Map<String, String> PLAYERS = new HashMap<String, String>();
	
	/**
	 * The main method.
	 * 
	 * @param args String arguments
	 */
	public static void main(String[] args) {
		try {
			for (PcapNetworkInterface network : Pcaps.findAllDevs())
				new PacketAnalyzer(network).start();
		} catch (PcapNativeException e) {
			e.printStackTrace();
		}
		printDisplay();
		Scanner scanner = new Scanner(System.in);
		while (scanner.hasNextLine()) {
			String line = scanner.nextLine();
			if (line.equalsIgnoreCase("list"))
				for (Entry<String, String> entry : PLAYERS.entrySet())
					System.out.println(entry.getKey() + " - " + entry.getValue());
			else if (line.startsWith("get")) {
				String[] arguments = line.split("get");
				if (arguments.length > 1)
					if (PLAYERS.containsKey(arguments[1]))
						System.out.println(PLAYERS.get(arguments[1]));
					else
						System.out.println("No ip address for that username");
			}
		}
		scanner.close();
	}
	
	/**
	 * Prints the display.
	 */
	private static void printDisplay() {
		System.out.println("=============== KickEm.IO Sniffer ===============");
		System.out.println("==== Commands");
		System.out.println("list - lists all ip addresses and names if any");
		System.out.println("get <username> - gets ip address of username if possible");
	}

}
