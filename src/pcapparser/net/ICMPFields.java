package pcapparser.net;


/**
 * ICMP protocol field encoding information.
 *
 * @author lipeng
 * @version 1.0
 */
public interface ICMPFields
{
    // field lengths

    /**
     * Length of the ICMP message type code in bytes.
     */
    int ICMP_CODE_LEN = 1;

    /**
     * Length of the ICMP subcode in bytes.
     */
    int ICMP_SUBC_LEN = 1;

    /**
     * Length of the ICMP header checksum in bytes.
     */
    int ICMP_CSUM_LEN = 2;


    // field positions

    /**
     * Position of the ICMP message type.
     */
    int ICMP_CODE_POS = 0;

    /**
     * Position of the ICMP message subcode.
     */
    int ICMP_SUBC_POS = ICMP_CODE_POS + ICMP_CODE_LEN;

    /**
     * Position of the ICMP header checksum.
     */
    int ICMP_CSUM_POS = ICMP_SUBC_POS + ICMP_CODE_LEN;


    // complete header length

    /**
     * Length in bytes of an ICMP header.
     */
    int ICMP_HEADER_LEN = ICMP_CSUM_POS + ICMP_CSUM_LEN; // == 4
}