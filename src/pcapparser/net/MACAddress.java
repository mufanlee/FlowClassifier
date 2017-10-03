package pcapparser.net;

import pcapparser.util.HexHelper;

/**
 * MAC address.
 * <p>
 * This class doesn't yet store MAC addresses. Only a utility method
 * to extract a MAC address from a big-endian byte array is implemented.
 *
 * @author lipeng
 * @version 1.0
 */
public class MACAddress
{
    /**
     * Extract a MAC address from an array of bytes.
     * @param offset the offset of the address data from the start of the
     * packet.
     * @param bytes an array of bytes containing at least one MAC address.
     */
    public static String extract(int offset, byte [] bytes) {
        StringBuffer sa = new StringBuffer();
        for(int i=offset; i<offset + WIDTH; i++) {
            sa.append(HexHelper.toString(bytes[i]));
            if(i != offset + WIDTH - 1)
                sa.append(':');
        }
        return sa.toString();
    }

    /**
     * Generate a random MAC address.
     */
    public static long random() {
        return (long)(0xffffffffffffL * Math.random());
    }

    /**
     * The width in bytes of a MAC address.
     */
    public static final int WIDTH = 6;
}