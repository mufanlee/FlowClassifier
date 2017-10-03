package pcapparser;

/**
 * PCAP File field encoding information.
 *
 * @author lipeng
 * @version 1.0
 *
 */

public interface PcapFields {
    // field lengths
    /**
     * Width of the magic number field in bytes.
     */
    int MAGIC_NUM_LEN = 4;

    /**
     * Width of the major version and minor version length field in bytes.
     */
    int VER_LEN = 4;

    /**
     * Width of the thiszone field in bytes.
     */
    int THIS_ZONE_LEN = 4;

    /**
     * Width of the sigfigs field in bytes.
     */
    int SIGFIGS_LEN = 4;

    /**
     * Width of the snaplen field in bytes.
     */
    int SNAPLEN_LEN = 4;

    /**
     * Width of the link type field in bytes.
     */
    int LINK_TYPE_LEN = 4;


    // field positions
    /**
     * Position of the magic number within the global header.
     */
    int MAGIC_NUM_POS = 0;

    /**
     * Position of the version within the global header.
     */
    int VER_POS = MAGIC_NUM_POS + MAGIC_NUM_LEN;

    /**
     * Position of the thiszone within the global header.
     */
    int THIS_ZONE_POS = VER_POS + VER_LEN;

    /**
     * Position of the sigfigs within the global header.
     */
    int SIGFIGS_POS = THIS_ZONE_POS + THIS_ZONE_LEN;

    /**
     * Position of the snaplen within the global header.
     */
    int SNAPLEN_POS = SIGFIGS_POS + SIGFIGS_LEN;

    /**
     * Position of the linktype within the global header.
     */
    int LINK_TYPE_POS = SNAPLEN_POS + SNAPLEN_LEN;

    // complete header length

    /**
     * Total length of an global header in bytes.
     */
    int GLOBAL_HEADER_LEN = LINK_TYPE_POS + LINK_TYPE_LEN; // == 24
}
