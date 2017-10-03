package pcapparser.net;

/**
 * Ethernet protocol field encoding information.
 *
 * @author lipeng
 * @version 1.0
 *
 */
public interface EthernetFields
{
    // field lengths

    /**
     * Width of the ethernet type code in bytes.
     */
    int ETH_CODE_LEN = 2;


    // field positions

    /**
     * Position of the destination MAC address within the ethernet header.
     */
    int ETH_DST_POS = 0;

    /**
     * Position of the source MAC address within the ethernet header.
     */
    int ETH_SRC_POS = MACAddress.WIDTH;

    /**
     * Position of the ethernet type field within the ethernet header.
     */
    int ETH_CODE_POS = MACAddress.WIDTH * 2;


    // complete header length

    /**
     * Total length of an ethernet header in bytes.
     */
    int ETH_HEADER_LEN = ETH_CODE_POS + ETH_CODE_LEN; // == 14
}