import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/*Ayat Kamona - B00858784
//Assignment 4 - this code simulates a router, and has the following assumptions as per the assignment instructions:
all the masks in the table are the default ones for Class A (255.0.0.0), Class B
(255.255.0,0) and Class C (255.255.255.0) and that the text files are error-free, that is, there is not need to test for malformed IP addresses,
etc.
*/
public class RouterSim {
    public static void main(String[] args) {
        // define the file names for routing table, packets, and output results
        String routingTableFileName = "RoutingTable.txt";
        String packetsFileName = "RandomPackets.txt";
        String outputFileName = "RoutingOutput.txt";

        // read the routing table from the specified file
        Map<String, String> routingTable = readRoutingTable(routingTableFileName);

        // read the packets from the specified file
        String[] packets = readPackets(packetsFileName);

        // initialize an array to store the results
        String[] results = new String[packets.length];

        // process each packet and store the results
        for (int i = 0; i < packets.length; i++) {
            results[i] = processPacket(packets[i], routingTable);
        }

        // write the results to the output file
        writeResults(outputFileName, results);
    }

    // read the routing table from a file and store it in a map
    private static Map<String, String> readRoutingTable(String fileName) {
        Map<String, String> routingTable = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            String destination = null;
            String nextHop = null;
            String interfaceName = null;

            // read the file line by line
            while ((line = reader.readLine()) != null) {
                if (destination == null) {
                    destination = line;
                } else if (nextHop == null) {
                    nextHop = line;
                } else if (interfaceName == null) {
                    interfaceName = line;

                    // store the routing information in the map
                    routingTable.put(destination, nextHop + " on interface " + interfaceName);

                    // reset the variables for the next entry
                    destination = null;
                    nextHop = null;
                    interfaceName = null;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return routingTable;
    }

    // read packets from a file and return them as an array of strings
    private static String[] readPackets(String fileName) {
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            return reader.lines().toArray(String[]::new);
        } catch (IOException e) {
            e.printStackTrace();
            return new String[0];
        }
    }

    // process a packet using the routing table and return a result string
    private static String processPacket(String packet, Map<String, String> routingTable) {
        if (!isValidIPAddress(packet)) {
            return packet + " is malformed; discarded";
        }

        // check if it's a loopback address
        if (packet.startsWith("127.")) {
            return packet + " is loopback; discarded";
        }

        // check for host-specific matches first
        for (String destination : routingTable.keySet()) {
            if (destination.contains("/32") && isMatchingDestination(packet, destination)) {
                String nextHopInfo = routingTable.get(destination);
                if (nextHopInfo.startsWith("-")) {
                    return packet + " will be forwarded on the directly connected network " + nextHopInfo.substring(1);
                } else {
                    String interfaceInfo = nextHopInfo;
                    return packet + " will be forwarded to " + interfaceInfo;
                }
            }
        }

        // check for subnet matches
        for (String destination : routingTable.keySet()) {
            if (isMatchingDestination(packet, destination)) {
                String nextHopInfo = routingTable.get(destination);
                if (nextHopInfo.startsWith("-")) {
                    return packet + " will be forwarded on the directly connected network" + nextHopInfo.substring(1);
                } else {
                    String interfaceInfo = nextHopInfo;
                    return packet + " will be forwarded to " + interfaceInfo;
                }
            }
        }

        // default route
        return packet + " will be forwarded on the directly connected network on interface E0";
    }

    // perform validation for IP addresses
    private static boolean isValidIPAddress(String ipAddress) {
        return true;
    }

    // check if the packet matches the given destination (subnets and host-specific)
    private static boolean isMatchingDestination(String packet, String destination) {
        if (destination.equals("0.0.0.0/0")) {
            // this is the default route so any packet matches
            return true;
        }

        String[] packetOctets = packet.split("\\.");
        String[] destinationParts = destination.split("/");

        if (destinationParts.length == 2) {
            // check if it's a subnet match
            String destinationIP = destinationParts[0];
            int subnetMask = Integer.parseInt(destinationParts[1]);
            String[] destinationOctets = destinationIP.split("\\.");

            // check if the first subnetMask bits match
            for (int i = 0; i < subnetMask / 8; i++) {
                if (!packetOctets[i].equals(destinationOctets[i])) {
                    return false;
                }
            }

            // check the remaining bits
            int remainingBits = subnetMask % 8;
            if (remainingBits != 0) {
                int mask = 0xFF << (8 - remainingBits);
                int packetValue = Integer.parseInt(packetOctets[subnetMask / 8]);
                int destinationValue = Integer.parseInt(destinationOctets[subnetMask / 8]);
                if ((packetValue & mask) != (destinationValue & mask)) {
                    return false;
                }
            }

            return true;
        }

        // regular ip address match
        String[] destinationOctets = destination.split("\\.");
        return packetOctets[0].equals(destinationOctets[0]) &&
                packetOctets[1].equals(destinationOctets[1]) &&
                packetOctets[2].equals(destinationOctets[2]) &&
                packetOctets[3].equals(destinationOctets[3]);
    }

    // write the results to an output file
    private static void writeResults(String fileName, String[] results) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(fileName))) {
            for (String result : results) {
                writer.println(result);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
