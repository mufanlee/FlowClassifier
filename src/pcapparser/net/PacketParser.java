package pcapparser.net;


import org.apache.log4j.Logger;
import pcapparser.FlowClass;
import pcapparser.FlowFeatures;
import pcapparser.util.ArrayHelper;
import pcapparser.util.HexHelper;
import pcapparser.util.Timeval;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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
                return new ARPPacket(lLen, bytes, tv);
            case EthernetProtocols.IP:
                // ethernet level code is recognized as IP, figure out what kind..
                int ipProtocol = IPProtocol.extractProtocol(lLen, bytes);
                switch(ipProtocol) {
                    // icmp
                    case IPProtocols.ICMP: return new ICMPPacket(lLen, bytes, tv);
                    // igmp
                    case IPProtocols.IGMP: return new IGMPPacket(lLen, bytes, tv);
                    // tcp
                    case IPProtocols.TCP: return new TCPPacket(lLen, bytes, tv);
                    // udp
                    case IPProtocols.UDP: return new UDPPacket(lLen, bytes, tv);
                    // unidentified ip..
                    default: return new IPPacket(lLen, bytes, tv);
                }
                // ethernet level code not recognized, default to anonymous packet..
            default: return new EthernetPacket(lLen, bytes, tv);
        }
    }

    public static FlowFeatures packetToFlowFeatures(int linkType, byte [] bytes) {
        FlowFeatures feature = null;

        int ethProtocol;
        lLen = LinkLayer.getLinkLayerLength(linkType);
        int offset = LinkLayer.getProtoOffset(linkType);
        if(offset == -1)
            // if there is no embedded protocol, assume IP?
            ethProtocol = EthernetProtocols.IP;
        else
            ethProtocol = ArrayHelper.extractInteger(bytes, offset,
                    EthernetFields.ETH_CODE_LEN);

        switch(ethProtocol) {
            // arp
            case EthernetProtocols.ARP:
                //ARPPacket arp = new ARPPacket(lLen, bytes);
                break;
            case EthernetProtocols.IP:
                // ethernet level code is recognized as IP, figure out what kind..
                int ipProtocol = IPProtocol.extractProtocol(lLen, bytes);
                int port = 0;
                switch(ipProtocol) {
                    // icmp
                    case IPProtocols.ICMP:
                        //ICMPPacket icmp = new ICMPPacket(lLen, bytes);
                        break;
                    // igmp
                    case IPProtocols.IGMP:
                        //IGMPPacket igmp = new IGMPPacket(lLen, bytes);
                        break;
                    // tcp
                    case IPProtocols.TCP:
                        TCPPacket tcp = new TCPPacket(lLen, bytes);
                        //port = getWellKnownedPort(tcp.getSourcePort(), tcp.getDestinationPort());
                        int serOrCli = isServeOrClient(tcp);
                        feature = new FlowFeatures(tcp.getSourceAddressAsLong(), tcp.getDestinationAddressAsLong(),
                                tcp.getSourcePort(), tcp.getDestinationPort(), tcp.getProtocol(), serOrCli, 0);
                        break;
                    // udp
                    case IPProtocols.UDP:
                        UDPPacket udp = new UDPPacket(lLen, bytes);
                        //port = getWellKnownedPort(udp.getSourcePort(), udp.getDestinationPort());
                        feature = new FlowFeatures(udp.getSourceAddressAsLong(), udp.getDestinationAddressAsLong(),
                                udp.getSourcePort(), udp.getDestinationPort(), udp.getProtocol(),0, 0);
                        break;
                    // unidentified ip..
                    default:
                        IPPacket ip = new IPPacket(lLen, bytes);
                        logger.warn("The ip packet of the protocol " + ip.getIPProtocol() + " don't process...");
                        break;
                }
                break;
                // ethernet level code not recognized, default to anonymous packet..
            default:
                EthernetPacket ethernet = new EthernetPacket(lLen, bytes);
                logger.warn("The ethernet packet of the type " + ethernet.getEthernetProtocol() + " don't process...");
                break;
        }
        return feature;
    }

    public static void packetToMap(int linkType, byte [] bytes, Map<String, List<Packet>> map, int size) {
        int ethProtocol;
        lLen = LinkLayer.getLinkLayerLength(linkType);
        int offset = LinkLayer.getProtoOffset(linkType);
        if(offset == -1)
            // if there is no embedded protocol, assume IP?
            ethProtocol = EthernetProtocols.IP;
        else
            ethProtocol = ArrayHelper.extractInteger(bytes, offset,
                    EthernetFields.ETH_CODE_LEN);

        switch(ethProtocol) {
            // arp
            case EthernetProtocols.ARP:
                //ARPPacket arp = new ARPPacket(lLen, bytes);
                break;
            case EthernetProtocols.IP:
                // ethernet level code is recognized as IP, figure out what kind..
                int ipProtocol = IPProtocol.extractProtocol(lLen, bytes);
                int port = 0;
                switch(ipProtocol) {
                    // icmp
                    case IPProtocols.ICMP:
                        //ICMPPacket icmp = new ICMPPacket(lLen, bytes);
                        break;
                    // igmp
                    case IPProtocols.IGMP:
                        //IGMPPacket igmp = new IGMPPacket(lLen, bytes);
                        break;
                    // tcp
                    case IPProtocols.TCP:
                        TCPPacket tcp = new TCPPacket(lLen, bytes);
                        if (tcp.isSyn() || tcp.isRst() || tcp.isFin()) {
                            break;
                        }
                        if (tcp.isAck() && tcp.getPayloadDataLength() == 0) {
                            break;
                        }
                        String key = "" + tcp.getSourceAddressAsLong() + tcp.getDestinationAddressAsLong()
                                + tcp.getProtocol() + tcp.getSourcePort() + tcp.getDestinationPort();
                        String rekey = "" + tcp.getDestinationAddressAsLong() + tcp.getSourceAddressAsLong()
                                + tcp.getProtocol() + tcp.getDestinationPort() + tcp.getSourcePort();
                        if (map != null) {
                            if (!map.containsKey(key) && !map.containsKey(rekey)) {
                                map.put(key, new ArrayList<>());
                            }
                            List<Packet> l = null;
                            if (map.containsKey(key)) {
                                l = map.get(key);
                                //logger.info(tcp.toString());
                            } else if (map.containsKey(rekey)) {
                                //logger.info(tcp.toString());
                                l = map.get(rekey);
                            }
                            if (l != null && l.size() < size) {
                                l.add(tcp);
                            }
                        }
                        break;
                    // udp
                    case IPProtocols.UDP:
                        UDPPacket udp = new UDPPacket(lLen, bytes);
                        key = "" + udp.getSourceAddressAsLong() + udp.getDestinationAddressAsLong()
                                + udp.getProtocol() + udp.getSourcePort() + udp.getDestinationPort();
                        rekey = "" + udp.getDestinationAddressAsLong() + udp.getSourceAddressAsLong()
                                + udp.getProtocol() + udp.getDestinationPort() + udp.getSourcePort();
                        //logger.info(udp.toString());
                        if (map != null) {
                            if (!map.containsKey(key) && !map.containsKey(rekey)) {
                                map.put(key, new ArrayList<>());
                            }
                            List<Packet> l = null;
                            if (map.containsKey(key)) {
                                l = map.get(key);
                                //logger.info(udp.toString());
                            } else if (map.containsKey(rekey)) {
                                l = map.get(rekey);
                                //logger.info(udp.toString());
                            }
                            if (l.size() < size) {
                                l.add(udp);
                            }
                        }
                        break;
                    // unidentified ip..
                    default:
                        IPPacket ip = new IPPacket(lLen, bytes);
                        logger.warn("The ip packet of the protocol " + ip.getIPProtocol() + " don't process...");
                        break;
                }
                break;
            // ethernet level code not recognized, default to anonymous packet..
            default:
                EthernetPacket ethernet = new EthernetPacket(lLen, bytes);
                logger.warn("The ethernet packet of the type " + ethernet.getEthernetProtocol() + " don't process...");
                break;
        }
    }

    public static List<FlowFeatures> mapToFlowFeatures(Map<String, List<Packet>> map, int threshold) {
        if (map == null) return null;
        List<FlowFeatures> features = new ArrayList<>();
        Iterator<Map.Entry<String, List<Packet>>> ite = map.entrySet().iterator();
        while (ite.hasNext()) {
            Map.Entry<String, List<Packet>> entry = ite.next();
            List<Packet> pktList = entry.getValue();
            if (pktList == null) {
                logger.error("The List in Map is null!");
                return null;
            }
            /*if (pktList.size() < 6) {
                continue;
            }*/
            Class cls = pktList.get(0).getClass();
            String name = cls.getSimpleName();
            FlowFeatures fts = null;
            int size = 0;
            switch (name) {
                case "TCPPacket":
                    TCPPacket tcp = (TCPPacket) pktList.get(0);
                    int soc = isServeOrClient(tcp);
                    fts = new FlowFeatures(tcp.getSourceAddressAsLong(), tcp.getDestinationAddressAsLong(),
                            tcp.getSourcePort(), tcp.getDestinationPort(), tcp.getProtocol(), soc);
                    for (int i = 0; i < pktList.size(); i++) {
                        tcp = (TCPPacket) pktList.get(i);
                        //logger.info(tcp.toString());
                        size += tcp.getPayloadDataLength();
                    }
                    fts.setSizeOf3Pkt(size);
                    if (size >= threshold)
                        fts.setFlowClass(FlowClass.Elephant);
                    else
                        fts.setFlowClass(FlowClass.Mouse);
                    logger.info(fts.toString());
                    features.add(fts);
                    break;
                case "UDPPacket":
                    UDPPacket udp = (UDPPacket) pktList.get(0);
                    fts = new FlowFeatures(udp.getSourceAddressAsLong(), udp.getDestinationAddressAsLong(),
                            udp.getSourcePort(), udp.getDestinationPort(), udp.getProtocol(), 0);
                    for (int i = 0; i < pktList.size(); i++) {
                        udp = (UDPPacket) pktList.get(i);
                        //logger.info(udp.toString());
                        size += udp.getUDPLength() - UDPFields.UDP_HEADER_LEN;
                    }
                    fts.setSizeOf3Pkt(size);
                    if (size >= threshold)
                        fts.setFlowClass(FlowClass.Elephant);
                    else
                        fts.setFlowClass(FlowClass.Mouse);
                    logger.info(fts.toString());
                    features.add(fts);
                    break;
                default:
                    break;
            }
        }
        return features;
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
}