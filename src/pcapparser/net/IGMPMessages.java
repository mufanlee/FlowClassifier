package pcapparser.net;


/**
 * Code constants for IGMP message types.
 *
 * From RFC #2236.
 *
 * @author lipeng
 * @version 1.0
 */
public interface IGMPMessages
{
    /**
     * membership query.
     */
    int QUERY = 0x11;

    /**
     * v1 membership report.
     */
    int V1_REPORT = 0x12;

    /**
     * v2 membership report.
     */
    int V2_REPORT = 0x16;

    /**
     * Leave group.
     */
    int LEAVE = 0x17;
}