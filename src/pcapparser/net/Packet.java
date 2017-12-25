package pcapparser.net;

import util.Timeval;

import java.io.Serializable;

/**
 * A network packet.
 * <p>
 * This class currently contains no implementation because only ethernet
 * is supported. In other words, all instances of packets returned by
 * packet factory will always be at least as specific as EthernetPacket.
 * <p>
 * On large ethernet networks, I sometimes see packets which don't have
 * link-level ethernet headers. If and when I figure out what these are,
 * maybe this class will be the root node of a packet hierarchy derived
 * from something other than ethernet.
 *
 * @author lipeng
 * @version 1.0
 */
public class Packet implements Serializable
{
    public String toColoredString(boolean colored) {
        return toString();
    }

    /**
     * Fetch data portion of the packet.
     */
    public byte [] getHeader() {
        return null;
    }

    /**
     * Fetch data portion of the packet.
     */
    public byte [] getData() {
        return null;
    }

    public String getColor() {
        return "";
    }

    public Timeval getTimeval() {
        return null;
    }
}