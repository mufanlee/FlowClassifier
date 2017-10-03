package pcapparser.net;


/**
 * Ethernet protocol utility class.
 *
 * @author lipeng
 * @version 1.0
 */
public class EthernetProtocol implements EthernetProtocols, EthernetFields
{
    /**
     * Extract the protocol type field from packet data.
     * <p>
     * The type field indicates what type of data is contained in the
     * packet's data block.
     * @param packetBytes packet bytes.
     * @return the ethernet type code. i.e. 0x800 signifies IP datagram.
     */
    public static int extractProtocol(byte [] packetBytes) {
        // convert the bytes that contain the type code into a value..
        return packetBytes[ETH_CODE_POS] << 8 | packetBytes[ETH_CODE_POS + 1];
    }
}