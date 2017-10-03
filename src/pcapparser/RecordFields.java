package pcapparser;

/**
 * RecordHeader field encoding information.
 *
 * @author lipeng
 * @version 1.0
 *
 */

public interface RecordFields {

    // field lengths

    /**
     * Width of the timestamp(s) field in bytes.
     */
    int TS_SEC_LEN = 4;

    /**
     * Width of the timestamp(ms) field in bytes.
     */
    int TS_USEC_LEN = 4;

    /**
     * Width of the capture length field in bytes.
     */
    int CAPLEN_LEN = 4;

    /**
     * Width of the original packet length field in bytes.
     */
    int ORGLEN_LEN = 4;

    // field positions
    /**
     * Position of the timestamp(s) within the global header.
     */
    int TS_SEC_POS = 0;

    /**
     * Position of the timestamp(ms) within the global header.
     */
    int TS_USEC_POS = TS_SEC_POS + TS_SEC_LEN;

    /**
     * Position of the capture length within the global header.
     */
    int CAPLEN_POS = TS_USEC_POS + TS_USEC_LEN;

    /**
     * Position of the original packet length within the global header.
     */
    int ORGLEN_POS = CAPLEN_POS + CAPLEN_LEN;

    // complete header length

    /**
     * Total length of an record header in bytes.
     */
    int RECORD_HEADER_LEN = ORGLEN_POS + ORGLEN_LEN; // == 16
}
