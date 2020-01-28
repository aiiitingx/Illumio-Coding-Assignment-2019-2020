
import java.io.BufferedReader;
import java.io.FileReader;

import java.util.*;
class Firewall {
    // set of all firewall rules
    private Set<Long> rules;

    // shifts used for encoding packet rules
    private final static int shiftDirectionKey = 56;
    private final static int shiftProtocolKey = 48;
    private final static int shiftPortKey = 32;
    private final static int bitsInByte = 8;

    /**
     * Constuctor of the Firewall class. Takes in a path to the csv file that
     * contains all rules of this firewall.
     *
     * @param pathToCSV
     */
    public Firewall(String pathToCSV) {
        rules = new HashSet<>();

        BufferedReader reader = null;
        try {
            String line = "";
            reader = new BufferedReader(new FileReader(pathToCSV));

            while ((line = reader.readLine()) != null) {
                String[] rule = line.split(",");
                List<Long> encodedRules = encodeRule(rule[0], rule[1], rule[2], rule[3]);
                for (Long encodedRule : encodedRules) {
                    rules.add(encodedRule);
                }
            }
        } catch (Exception e) {
            System.out.println("Error reading csv file.");
            System.out.println(e.getMessage());
        }

    }

    /**
     * Function that accecpts or reject a user's packet.
     *
     * @param packet The user input string
     * @return Whether the packet is to be accepted
     */
    public boolean accept_packet_str(String packet) {
        String[] packetArr = packet.trim().split(",");
        if (packetArr.length != 4)
            return false;
        return accept_packet(packetArr[0], packetArr[1], packetArr[2], packetArr[3]);
    }

    /***
     * Function that checks whether the input packet matches at least one of the
     * firewall rules
     *
     * @param direction Either inbound or outbound
     * @param protocol  Either tcp or udp
     * @param port      A single port number
     * @param ip        A single ip address
     * @return Whether the packet matches at least one of the firewall rules
     */
    public boolean accept_packet(String direction, String protocol, String port, String ip) {
        Long packetKey = getPacketKey(direction, protocol, port, ip);
        return rules.contains(packetKey);
    }

    /***
     * Function that calls encodeRule to get the encoding key of user packet
     *
     * @param direction Either inbound or outbound
     * @param protocol  Either tcp or udp
     * @param port      A single port number
     * @param ip        A single ip address
     * @return the encoding of the user packet
     */
    private Long getPacketKey(String direction, String protocol, String port, String ip) {
        List<Long> packetKeyList = encodeRule(direction, protocol, port, ip);
        return packetKeyList.get(0);
    }

    /***
     * Encodes the given rule(s)/packet to a long key
     *
     * @param direction Either inbound or outbound
     * @param protocol  Either tcp or udp
     * @param port      A single port number (rule/packet) or a range of port
     *                  numbers (rule)
     * @param ip        A single ip address (rule/packet) or a range of ip addresses
     *                  (rule)
     * @return A list of encoded long keys byte 0: direction byte 1: protocol byte
     *         2-3: port number byte 4-7: ip address
     */
    private List<Long> encodeRule(String direction, String protocol, String port, String ip) {
        List<Long> encodedRules = new ArrayList<Long>();// list of encoded rules to be returned
        Long directionKey = (direction.equals("inbound") ? 0l : 1l) << shiftDirectionKey;
        Long protocolKey = (protocol.equals("tcp") ? 0l : 1l) << shiftProtocolKey;

        String[] portRange = port.split("-");
        Long portStart = Long.parseLong(portRange[0]);
        Long portEnd = portRange.length > 1 ? Long.parseLong(portRange[1]) : portStart;

        String[] ipRange = ip.split("-");
        Long ipStart = ipToLong(ipRange[0]);
        Long ipEnd = ipRange.length > 1 ? ipToLong(ipRange[1]) : ipStart;

        for (int portOffset = 0; portOffset <= portEnd - portStart; portOffset++) {
            for (int ipOffset = 0; ipOffset <= ipEnd - ipStart; ipOffset++) {
                Long key = directionKey | protocolKey | (portStart + portOffset) << shiftPortKey | (ipStart + ipOffset);
                encodedRules.add(key);
            }
        }

        return encodedRules;
    }

    /**
     * Prints out all firewall rules
     */
    public void printAllRules() {
        for (Long key : rules) {
            String[] ruleInfo = decodeKey(key);
            System.out.println("key: " + key + ", direction: " + ruleInfo[0] + ", protocol: " + ruleInfo[1] + ", port:"
                    + ruleInfo[2] + ", ip:" + ruleInfo[3]);
        }
    }

    /**
     * Decodes the input long key to get the original rule/packet information
     *
     * @param key a long key to be decoded
     * @return A string array with original rule/packet information
     */
    public String[] decodeKey(Long key) {
        String[] info = new String[4];
        info[0] = (key >> shiftDirectionKey) == 0l ? "inbound" : "outbound";// direction
        info[1] = ((key >> shiftProtocolKey) & 1l) == 0l ? "tcp" : "udp";// protocol
        info[2] = String.valueOf((key >> shiftPortKey) & 0XFFFFl);// port
        info[3] = longToIp(key & 0XFFFFFFFFl);// ip address

        return info;
    }

    /**
     * Converts ip address to a long
     *
     * @param ipAddr The ip address to be converted
     * @return The long value of the input ip address
     */
    private static Long ipToLong(String ipAddr) {
        String[] ipArr = ipAddr.split("\\.");
        int ipLen = ipArr.length;
        Long ipLong = 0l;
        int power = ipLen - 1;
        for (int i = 0; i < ipLen; i++) {
            Long ipByte = Long.parseLong(ipArr[i]);
            ipLong += (ipByte << bitsInByte * power);
            power--;
        }
        // System.out.println(ipLong.toString());
        return ipLong;
    }

    /***
     * Convert a long back to original ip address form
     *
     * @param longIP The long to be converted
     * @return The ip address in its original form
     */
    private static String longToIp(Long longIP) {
        StringBuilder ipStringBuilder = new StringBuilder();

        for (int i = 3; i >= 0; i--) {
            ipStringBuilder.append(((longIP >> bitsInByte * i) & 0XFFl) + ".");
        }

        ipStringBuilder.deleteCharAt(ipStringBuilder.length() - 1);// remove the last "."
        return ipStringBuilder.toString();
    }

}