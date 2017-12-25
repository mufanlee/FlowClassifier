package pcapparser.net;


import org.apache.log4j.Logger;
import pcapparser.FlowFeatures;
import util.ArrayHelper;
import util.Timeval;

import java.lang.reflect.Method;
import java.util.*;

/**
 * This parse constructs high-level packet objects from a pcap file
 *
 * @author lipeng
 * @version 1.0
 *
 */
public class PacketParser
{
    protected static Logger logger = Logger.getLogger(PacketParser.class);
    /**
     * Convert packet data into an object.
     */
    public static Packet dataToPacket(int linkType, byte [] bytes) {
        int ethProtocol;

        // record the length of the headers associated with this link layer type.
        // this length is the offset to the header embedded in the packet.
        lLen = LinkLayer.getLinkLayerLength(linkType);

        // extract the protocol code for the type of header embedded in the
        // link-layer of the packet
        int offset = LinkLayer.getProtoOffset(linkType);
        if(offset == -1)
            // if there is no embedded protocol, assume IP?
            ethProtocol = EthernetProtocols.IP;
        else
            ethProtocol = ArrayHelper.extractInteger(bytes, offset,
                    EthernetFields.ETH_CODE_LEN);

        // try to recognize the ethernet type..
        switch(ethProtocol) {
            // arp
            case EthernetProtocols.ARP:
                return new ARPPacket(lLen, bytes);
            case EthernetProtocols.IP:
                // ethernet level code is recognized as IP, figure out what kind..
                int ipProtocol = IPProtocol.extractProtocol(lLen, bytes);
                switch(ipProtocol) {
                    // icmp
                    case IPProtocols.ICMP: return new ICMPPacket(lLen, bytes);
                    // igmp
                    case IPProtocols.IGMP: return new IGMPPacket(lLen, bytes);
                    // tcp
                    case IPProtocols.TCP: return new TCPPacket(lLen, bytes);
                    // udp
                    case IPProtocols.UDP: return new UDPPacket(lLen, bytes);
                    // unidentified ip..
                    default: return new IPPacket(lLen, bytes);
                }
                // ethernet level code not recognized, default to anonymous packet..
            default: return new EthernetPacket(lLen, bytes);
        }
    }

    /**
     * Convert captured packet data into an object.
     */
    public static Packet dataToPacket(int linkType, byte [] bytes, Timeval tv) {
        int ethProtocol;
        //the packet length of caption
        int caplen = bytes.length;

        // record the length of the headers associated with this link layer type.
        // this length is the offset to the header embedded in the packet.
        lLen = LinkLayer.getLinkLayerLength(linkType);

        // ethernet header >= 14
        if (caplen < 14) return null;

        // extract the protocol code for the type of header embedded in the
        // link-layer of the packet
        int offset = LinkLayer.getProtoOffset(linkType);
        if(offset == -1)
            // if there is no embedded protocol, assume IP?
            ethProtocol = EthernetProtocols.IP;
        else
            ethProtocol = ArrayHelper.extractInteger(bytes, offset,
                    EthernetFields.ETH_CODE_LEN);

        // try to recognize the ethernet type..
        switch(ethProtocol) {
            // arp
            case EthernetProtocols.ARP:
                return new ARPPacket(lLen, bytes, tv);
            case EthernetProtocols.IP:
                // ip header >= 14 + 20
                if (caplen < (14 + 20)) return new EthernetPacket(lLen, bytes, tv);

                // ethernet level code is recognized as IP, figure out what kind..
                int ipProtocol = IPProtocol.extractProtocol(lLen, bytes);
                switch(ipProtocol) {
                    // icmp
                    case IPProtocols.ICMP: return new ICMPPacket(lLen, bytes, tv);
                    // igmp
                    case IPProtocols.IGMP: return new IGMPPacket(lLen, bytes, tv);
                    // tcp
                    case IPProtocols.TCP:
                        // tcp header >= 14 + 20 + 20
                        if (caplen < (14 + 20 + 20)) return new IPPacket(lLen, bytes, tv);
                        return new TCPPacket(lLen, bytes, tv);
                    // udp
                    case IPProtocols.UDP:
                        // udp header >= 14 + 20 + 8
                        if (caplen < (14 + 20 + 8)) return new IPPacket(lLen, bytes, tv);
                        return new UDPPacket(lLen, bytes, tv);
                    // unidentified ip..
                    default: return new IPPacket(lLen, bytes, tv);
                }
                // ethernet level code not recognized, default to anonymous packet..
            default: return new EthernetPacket(lLen, bytes, tv);
        }
    }

    public static void packetToFlowMap(int linkType, byte [] bytes, Map<String, List<Packet>> forwardMap, Map<String, List<Packet>> backwardMap, int size, Timeval tv) {
        int ethProtocol, caplen = bytes.length;
        lLen = LinkLayer.getLinkLayerLength(linkType);
        if (caplen < 14) return ;
        int offset = LinkLayer.getProtoOffset(linkType);
        if(offset == -1) ethProtocol = EthernetProtocols.IP;
        else ethProtocol = ArrayHelper.extractInteger(bytes, offset, EthernetFields.ETH_CODE_LEN);

        switch(ethProtocol) {
            case EthernetProtocols.ARP: break;
            case EthernetProtocols.IP:
                if (caplen < (14 + 20)) return;
                int ipProtocol = IPProtocol.extractProtocol(lLen, bytes);
                switch(ipProtocol) {
                    case IPProtocols.ICMP: break;
                    case IPProtocols.IGMP: break;
                    case IPProtocols.TCP:
                        if (caplen < (14 + 20 + 20)) return;
                        TCPPacket tcp = new TCPPacket(lLen, bytes, tv);
                        putPacket2Map(tcp, forwardMap, backwardMap, size);
                        break;
                    case IPProtocols.UDP:
                        if (caplen < (14 + 20 + 8)) return;
                        UDPPacket udp = new UDPPacket(lLen, bytes, tv);
                        putPacket2Map(udp, forwardMap, backwardMap, size);
                        break;
                    default:
                        IPPacket ip = new IPPacket(lLen, bytes, tv);
                        logger.debug("The ip packet of the protocol " + ip.getIPProtocol() + " don't process...");
                        break;
                }
                break;
            default:
                EthernetPacket ethernet = new EthernetPacket(lLen, bytes, tv);
                logger.debug("The ethernet packet of the type " + ethernet.getEthernetProtocol() + " don't process...");
                break;
        }
    }

    private static void putPacket2Map(IPPacket packet, Map<String, List<Packet>> forwardMap, Map<String, List<Packet>> backwardMap, int SIZE) {
        String key1 = "" + packet.getSourceAddressAsLong() + packet.getDestinationAddressAsLong() + packet.getProtocol();
        String key2 = "" + packet.getDestinationAddressAsLong() + packet.getSourceAddressAsLong() + packet.getProtocol();
        if (packet.getProtocol() == IPProtocols.TCP) {
            TCPPacket tcp = (TCPPacket) packet;
            key1 += "" + tcp.getSourcePort() + tcp.getDestinationPort();
            key2 += "" + tcp.getDestinationPort() + tcp.getSourcePort();
        } else if (packet.getProtocol() == IPProtocols.UDP) {
            UDPPacket udp = (UDPPacket) packet;
            key1 += "" + udp.getSourcePort() + udp.getDestinationPort();
            key2 += "" + udp.getDestinationPort() + udp.getSourcePort();
        }
        if (forwardMap != null) {
            if (forwardMap.containsKey(key2)) {
                if (!backwardMap.containsKey(key1))
                    backwardMap.put(key1, new ArrayList<>());
                List<Packet> l = backwardMap.get(key1);
                if (l != null && l.size() < SIZE) {
                    l.add(packet);
                }
            } else {
                if (!forwardMap.containsKey(key1))
                    forwardMap.put(key1, new ArrayList<>());
                List<Packet> l = forwardMap.get(key1);
                if (l != null && l.size() < SIZE) {
                    l.add(packet);
                }
            }
        }
    }

    public static List<FlowFeatures> extractFlowFeatures(Map<String, List<Packet>> forwardMap, Map<String, List<Packet>> backwardMap, int SIZE) {
        if (forwardMap == null || backwardMap == null) return null;

        List<FlowFeatures> features = new ArrayList<>();
        Iterator<Map.Entry<String, List<Packet>>> itr = forwardMap.entrySet().iterator();
        while (itr.hasNext()) {
            Map.Entry<String, List<Packet>> entry = itr.next();
            List<Packet> fpkts = entry.getValue();
            if (fpkts == null) {
                logger.error("The List in Map is null!");
                return null;
            }
            IPPacket ip = (IPPacket) fpkts.get(0);
            if (ip.getProtocol() == IPProtocols.TCP && fpkts.size() < SIZE - 1) { continue; }
            if (ip.getProtocol() == IPProtocols.UDP && fpkts.size() < SIZE - 2) { continue; }

            Class cls = fpkts.get(0).getClass();
            String name = cls.getSimpleName(), key = null;
            List<Packet> bpkts = null, pkts = null;
            FlowFeatures fts = new FlowFeatures();
            switch (name) {
                case "TCPPacket":
                    TCPPacket tcp = (TCPPacket) fpkts.get(0);
                    // Flow info
                    fts.setFlow((int) tcp.getSourceAddressAsLong(), (int) tcp.getDestinationAddressAsLong(), tcp.getSourcePort(), tcp.getDestinationPort(), tcp.getProtocol());
                    int soc = isServeOrClient(tcp);
                    fts.setServerOrClient(soc);
                    key = "" + tcp.getDestinationAddressAsLong() + tcp.getSourceAddressAsLong() + tcp.getProtocol() + tcp.getDestinationPort() + tcp.getSourcePort();
                    break;
                case "UDPPacket":
                    UDPPacket udp = (UDPPacket) fpkts.get(0);
                    // Flow info
                    fts.setFlow((int) udp.getSourceAddressAsLong(), (int) udp.getDestinationAddressAsLong(), udp.getSourcePort(), udp.getDestinationPort(), udp.getProtocol());
                    key = "" + udp.getDestinationAddressAsLong() + udp.getSourceAddressAsLong() + udp.getProtocol() + udp.getDestinationPort() + udp.getSourcePort();
                    break;
                default:
                    break;
            }
            bpkts = backwardMap.get(key);
            /*for (Packet pkt : fpkts) {
                logger.info(pkt.getTimeval());
            }
            System.out.println();
            for (Packet pkt : bpkts) {
                logger.info(pkt.getTimeval());
            }*/
            pkts = new ArrayList<>(fpkts);
            if (bpkts != null) pkts.addAll(bpkts);
            Collections.sort(pkts, new Comparator<Packet>() {
                @Override
                public int compare(Packet pkt1, Packet pkt2) {
                    return (int) (pkt1.getTimeval().getMicroTime() - pkt2.getTimeval().getMicroTime());
                }
            });

            // Inter-arrival time
            computeInterArrivalTime(fpkts, bpkts, fts);

            // Bytes in Ethernet packet
            computeBytes(fpkts, fts, "eth", 1);
            computeBytes(bpkts, fts, "eth", 2);
            computeBytes( pkts, fts, "eth", 3);

            // Bytes in IP Packet
            computeBytes(fpkts, fts, "ip", 1);
            computeBytes(bpkts, fts, "ip", 2);
            computeBytes( pkts, fts, "ip", 3);

            // Payload in Datagram
            if (name.equals("TCPPacket")) {
                computeBytes(fpkts, fts, "tcppld", 1);
                computeBytes(bpkts, fts, "tcppld", 2);
                computeBytes( pkts, fts, "tcppld", 3);
            }
            if (name.equals("UDPPacket")) {
                computeBytes(fpkts, fts, "udppld", 1);
                computeBytes(bpkts, fts, "udppld", 2);
                computeBytes( pkts, fts, "udppld", 3);
            }

            // Control bytes in packet
            if (name.equals("TCPPacket")) {
                computeBytes(fpkts, fts, "ctl", 1);
                computeBytes(bpkts, fts, "ctl", 2);
                computeBytes( pkts, fts, "ctl", 3);
            }

            // Duration
            computeDuration(fpkts, bpkts, pkts, fts);

            // Round-Trip Time (RTT)
            computeRTT(pkts, fts);

            // Size of the first 5 packets
            //computeSizeOfPacket(fpkts, bpkts, fts, name, SIZE - 2);
            computeSizeOfPacket(fpkts, bpkts, pkts, fts, name, SIZE - 2);

            //logger.info(fts.toString());
            features.add(fts);
        }
        return features;
    }

    private static List<Integer> computeInterArrivalTime(List<Packet> pkts, FlowFeatures ff, int flag) {
        if (pkts == null || pkts.size() <= 1) return null;

        int maxIAT = Integer.MIN_VALUE, minIAT = Integer.MAX_VALUE;
        double medIAT = 0.0, meaIAT = 0.0, varIAT = 0.0;
        List<Integer> iats = new ArrayList<>();
        for (int i = 1; i < pkts.size(); i++) {
            //logger.info(pkts.get(i-1).getTimeval() + "->" + pkts.get(i).getTimeval());
            int iat = (int) (pkts.get(i).getTimeval().getMicroTime() - pkts.get(i - 1).getTimeval().getMicroTime());
            iats.add(iat);
            if (iat > maxIAT) maxIAT = iat;
            if (iat < minIAT) minIAT = iat;
            meaIAT += iat;
        }
        meaIAT /= iats.size();
        varIAT = variance(iats, meaIAT);
        medIAT = median(iats);

        if (flag == 1)
            ff.setForwardInterArrivalTime(maxIAT, minIAT, medIAT, meaIAT, varIAT);
        else if (flag == 2)
            ff.setBackwardInterArrivalTime(maxIAT, minIAT, medIAT, meaIAT, varIAT);
        return iats;
    }

    private static void computeInterArrivalTime(List<Packet> fpkts, List<Packet> bpkts, FlowFeatures ff) {
        // Forward inter-arrival time
        List<Integer> iats = computeInterArrivalTime(fpkts, ff, 1);
        // Backward inter-arrival time
        List<Integer> tmps = computeInterArrivalTime(bpkts, ff, 2);
        if (tmps != null && tmps.size() != 0) iats.addAll(tmps);

        int maxIAT = Integer.MIN_VALUE, minIAT = Integer.MAX_VALUE;
        double medIAT = 0.0, meaIAT = 0.0, varIAT = 0.0;
        for (int i = 0; i < iats.size(); i++) {
            if (iats.get(i) > maxIAT) maxIAT = iats.get(i);
            if (iats.get(i) < minIAT) minIAT = iats.get(i);
            meaIAT += iats.get(i);
        }
        meaIAT /= iats.size();
        medIAT = median(iats);
        varIAT = variance(iats, meaIAT);
        ff.setInterArrivalTime(maxIAT, minIAT, medIAT, meaIAT, varIAT);
    }

    private static void computeBytes(List<Packet> pkts, FlowFeatures ff, String cls, int flag) {
        if (pkts == null || pkts.size() == 0) return;

        int maxBytes = Integer.MIN_VALUE, minBytes = Integer.MAX_VALUE;
        double medBytes = 0.0, meaBytes = 0.0, varBytes = 0.0;
        List<Integer> list = new ArrayList<>();
        for (int i = 0; i < pkts.size(); i++) {
            int length = 0;
            switch (cls) {
                case "eth":
                    length = ((IPPacket) pkts.get(i)).getLength();
                    break;
                case "ip":
                    IPPacket ip = (IPPacket) pkts.get(i);
                    length = ip.getLength() - ip.getHeaderLength();
                    break;
                case "tcppld":
                    length = ((TCPPacket) pkts.get(i)).getPayloadDataLength();
                    break;
                case "udppld":
                    length = ((UDPPacket) pkts.get(i)).getUDPData().length;
                    break;
                case "ctl":
                    length = ((TCPPacket) pkts.get(i)).getTCPHeaderLength();
                    break;
            }
            list.add(length);
            if (length > maxBytes) maxBytes = length;
            if (length < minBytes) minBytes = length;
            meaBytes += length;
        }
        meaBytes /= pkts.size();
        varBytes = variance(list, meaBytes);
        medBytes = median(list);
        switch (cls) {
            case "eth":
                if (flag == 1)
                    ff.setForwardETHBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 2)
                    ff.setBackwardETHBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 3)
                    ff.setETHBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                break;
            case "ip":
                if (flag == 1)
                    ff.setForwardIPBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 2)
                    ff.setBackwardIPBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 3)
                    ff.setIPBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                break;
            case "tcppld":
            case "udppld":
                if (flag == 1)
                    ff.setForwardPayloadBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 2)
                    ff.setBackwardPayloadBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 3)
                    ff.setPayloadBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                break;
            case "ctl":
                if (flag == 1)
                    ff.setForwardControlBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 2)
                    ff.setBackwardControlBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                else if (flag == 3)
                    ff.setControlBytes(maxBytes, minBytes, medBytes, meaBytes, varBytes);
                break;
        }
    }

    private static void computeRTT(List<Packet> pkts, FlowFeatures ff) {
        if (pkts == null || pkts.size() == 0) return;
        int fstRTT = 0, maxRTT = Integer.MIN_VALUE, minRTT = Integer.MAX_VALUE;
        double medRTT = 0.0, meaRTT = 0.0, varRTT = 0.0;
        boolean isFirst = true;
        List<Integer> rtts = new ArrayList<>();
        for (int i = 1; i < pkts.size(); i++) {
            IPPacket ip1 = (IPPacket) pkts.get(i - 1);
            IPPacket ip2 = (IPPacket) pkts.get(i);
            if (ip2.getSourceAddressAsLong() == ip1.getDestinationAddressAsLong() && ip2.getDestinationAddressAsLong() == ip1.getSourceAddressAsLong()) {
                //logger.info(ip1.getTimeval().getMicroTime() + "->" + ip2.getTimeval().getMicroTime());
                int time = (int) (ip2.getTimeval().getMicroTime() - ip1.getTimeval().getMicroTime());
                if (isFirst) { fstRTT = time; isFirst = false; }
                rtts.add(time);
                meaRTT += time;
                if (time > maxRTT) maxRTT = time;
                if (time < minRTT) minRTT = time;
            }
        }
        if (rtts.size() != 0)
            meaRTT /= rtts.size();
        else
            meaRTT = 0;
        medRTT = median(rtts);
        varRTT = variance(rtts, meaRTT);
        ff.setRTT(fstRTT, maxRTT, minRTT, medRTT, meaRTT, varRTT);
    }

    private static void computeDuration(List<Packet> fpkts, List<Packet> bpkts, List<Packet> pkts, FlowFeatures ff) {
        long duration = 0, fduration = 0, bduration = 0;
        if (fpkts != null) {
            fduration = fpkts.get(fpkts.size() - 1).getTimeval().getMicroTime() - fpkts.get(0).getTimeval().getMicroTime();
        }
        if (bpkts != null) {
            bduration = bpkts.get(bpkts.size() - 1).getTimeval().getMicroTime() - bpkts.get(0).getTimeval().getMicroTime();
        }
        if (pkts != null) {
            duration = pkts.get(pkts.size() - 1).getTimeval().getMicroTime() - pkts.get(0).getTimeval().getMicroTime();
        }
        ff.setDuration(duration, fduration, bduration);
    }

    private static void computeSizeOfPacket(List<Packet> fpkts, List<Packet> bpkts, List<Packet> pkts, FlowFeatures ff, String cls, int SIZE) {
        int fsize = 0, bsize = 0, size = 0;
        for (int i = 0, j = 0; i < SIZE; i++) {
            if (cls.equals("TCPPacket")) {
                TCPPacket tcp = (TCPPacket) fpkts.get(j++);
                if (tcp.isSyn()) i--;
                fsize += tcp.getPayloadDataLength();
                if (j >= fpkts.size()) break;
            } else if (cls.equals("UDPPacket")) {
                fsize += ((UDPPacket) fpkts.get(i)).getLength();
            }
        }
        if (bpkts != null) {
            for (int i = 0, j = 0; i < SIZE; i++) {
                if (cls.equals("TCPPacket")) {
                    TCPPacket tcp = (TCPPacket) bpkts.get(j++);
                    if (tcp.isSyn() && tcp.isAck()) i--;
                    bsize += tcp.getPayloadDataLength();
                    if (j >= bpkts.size()) break;
                } else if (cls.equals("UDPPacket")) {
                    if (i >= bpkts.size()) break;
                    bsize += ((UDPPacket) bpkts.get(i)).getLength();
                }
            }
        }
        for (int i = 0, j = 0; i < SIZE; i++) {
            if (cls.equals("TCPPacket")) {
                TCPPacket tcp = (TCPPacket) pkts.get(j++);
                if (tcp.isSyn() || (tcp.isSyn() && tcp.isAck())) i--;
                size += tcp.getPayloadDataLength();
                if (j >= pkts.size()) break;
            } else if (cls.equals("UDPPacket")) {
                size += ((UDPPacket) pkts.get(i)).getLength();
            }
        }
        ff.setSizeOf5Pkt(size, fsize, bsize);
    }

    @Deprecated
    private static void computeSizeOfPacket(List<Packet> fpkts, List<Packet> bpkts, FlowFeatures ff, String cls, int SIZE) {
        int size = 0, i = 0;
        if (cls.equals("TCPPacket")) {
            TCPPacket tcp = null;
            int j = 0;
            if (bpkts != null && bpkts.size() != 0) {
                for (; i < SIZE / 2; i++) {
                    tcp = (TCPPacket) bpkts.get(j++);
                    if (tcp.isSyn() && tcp.isAck()) i--;
                    size += tcp.getPayloadDataLength();
                    if (j >= bpkts.size()) break;
                }
            }
            j = 0;
            for (; i < SIZE; i++) {
                tcp = (TCPPacket) fpkts.get(j++);
                if (tcp.isSyn() || (tcp.isAck() && tcp.getPayloadDataLength() == 0 && j == 1)) i--;
                size +=  tcp.getPayloadDataLength();
                if (j >= fpkts.size()) break;
            }
        } else if (cls.equals("UDPPacket")) {
            int j = 0;
            if (bpkts != null && bpkts.size() != 0) {
                //logger.info(bpkts.size());
                for (; i < SIZE / 2; i++) {
                    size += ((UDPPacket) bpkts.get(j++)).getLength();
                    if (j >= bpkts.size()) break;
                }
            }
            j = 0;
            for (; i < SIZE; i++) {
                size += ((UDPPacket) fpkts.get(j++)).getLength();
                if (j >= fpkts.size()) break;
            }
        }
        //ff.setSizeOf5Pkt(size);
    }

    /**
     * Length in bytes of the link-level headers that this parse is
     * decoding packets for.
     */
    private static int lLen;

    private static final int WELL_KNOWN_PORT = 1023;
    private static final int REGISTERED_PORT = 49151;

    /**
     *  Get Port from src port and dst port for flow features.
     */
    private static int getWellKnownedPort(int src, int dst) {
        if (dst >= 0 && dst <= REGISTERED_PORT) {
            return dst;
        } else if (src >= 0 && src <= REGISTERED_PORT){
            return src;
        } else {
            return src < dst ? src : dst;
        }
    }

    /**
     * Judge the packet is froms server or client
     */
    private static int isServeOrClient(TCPPacket tcp) {
        int srcPort = tcp.getSourcePort();
        int dstPort = tcp.getDestinationPort();
        if (dstPort >= 0 && dstPort <= WELL_KNOWN_PORT) {
            return 2;
        } else if (srcPort >= 0 && srcPort <= WELL_KNOWN_PORT){
            return 1;
        } else {
            return srcPort < dstPort ? 1 : 2;
        }
    }

    /**
     * Median of the numbers
     */
    private static double median(List<Integer> nums) {
        if (nums == null || nums.size() == 0) return 0.0;
        Collections.sort(nums);
        int n = nums.size();
        if (n % 2 != 0) return nums.get(n / 2);
        else return (nums.get(n / 2 - 1) + nums.get(n / 2)) / 2;
    }

    /**
     * Variance of the numbers
     */
    private static double variance(List<Integer> nums, double mean) {
        if (nums == null || nums.size() == 0) return 0.0;
        double var = 0.0;
        for (int i = 0; i < nums.size(); i++)
            var += (nums.get(i) - mean) * (nums.get(i) - mean);
        var /= nums.size();
        return var;
    }
}