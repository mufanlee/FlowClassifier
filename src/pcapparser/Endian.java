package pcapparser;

/**
 * Network-byte order.
 *
 * @author lipeng
 * @version 1.0
 *
 */

public enum Endian {
    LITTLE_ENDIAN(0),
    BIG_ENDIAN(1);

    private int val;
    private Endian(int val) {
        this.val = val;
    }
}
