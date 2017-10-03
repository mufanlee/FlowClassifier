package pcapparser.net;

/**
 * Link-layer type codes.
 * <p>
 * Taken from libpcap/bpf/net/bpf.h and pcap/net/bpf.h.
 * <p>
 * The link-layer type is used to determine what data-structure the
 * IP protocol bits will be encapsulated inside of.
 * <p>
 * On a 10/100mbps network, packets are encapsulated inside of ethernet.
 * 14-byte ethernet headers which contain MAC addresses and an ethernet type
 * field.
 * <p>
 * On ethernet over ppp, the link-layer type is raw, and packets
 * are not encapsulated in any ethernet header.
 * <p>
 *
 * @author lipeng
 * @version 1.0
 */
public interface LinkLayers
{
    /**
     * no link-layer encapsulation
     */
    int NULL = 0;

    /**
     * Ethernet (10Mb)
     */
    int EN10MB = 1;

    /**
     * Experimental Ethernet (3Mb)
     */
    int EN3MB = 2;

    /**
     * Amateur Radio AX.25
     */
    int AX25 = 3;

    /**
     * Proteon ProNET Token Ring
     */
    int PRONET = 4;

    /**
     * Chaos
     */
    int CHAOS = 5;

    /**
     * IEEE 802 Networks
     */
    int IEEE802 = 6;

    /**
     * ARCNET
     */
    int ARCNET = 7;

    /**
     * Serial Line IP
     */
    int SLIP = 8;

    /**
     * Point-to-point Protocol
     */
    int PPP = 9;

    /**
     * FDDI
     */
    int FDDI = 10;

    /**
     * LLC/SNAP encapsulated atm
     */
    int ATM_RFC1483 = 100;

    /**
     * raw IP
     */
    int RAW = 101;

    /**
     * BSD Slip.
     */
    int SLIP_BSDOS = 102;

    /**
     * BSD PPP.
     */
    int PPP_BSDOS = 103;

    /**
     * IP over ATM.
     */
    int ATM_CLIP = 19;

    /**
     * PPP over HDLC.
     */
    int PPP_SERIAL = 50;

    /**
     * Cisco HDLC.
     */
    int CHDLC = 104;

    /**
     * IEEE 802.11 wireless.
     */
    int IEEE802_11 = 105;

    /**
     * OpenBSD loopback.
     */
    int LOOP = 108;

    /**
     * Linux cooked sockets.
     */
    int LINUX_SLL = 113;

    /**
     * unknown link-layer type
     */
    int UNKNOWN = -1;
}