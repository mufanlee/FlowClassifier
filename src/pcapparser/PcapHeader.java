package pcapparser;

import pcapparser.net.LinkLayer;
import pcapparser.util.AnsiEscapeSequences;
import pcapparser.util.ArrayHelper;
import pcapparser.util.HexHelper;

import java.io.Serializable;

/**
 * An Pcap file.
 * <p>
 * Contains global header and payload in an Pcap file.
 * <p>
 *
 * @author lipeng
 * @version 1.0
 *
 */
public class PcapHeader implements PcapFields, Serializable{

    // store the data here
    protected byte[] _bytes;
    protected Endian _endian;

    /**
     * Construct a new pcap header.
     */
    public PcapHeader(byte [] bytes) {
        _bytes = bytes;
        if (getMagicNumber() == 0x4d3c2b1a)
            _endian = Endian.LITTLE_ENDIAN;
        else if (getMagicNumber() == 0xa1b2c3d4)
            _endian = Endian.BIG_ENDIAN;
        else                                // otherwise, assume little endian ?
            _endian = Endian.LITTLE_ENDIAN;
        _endianSet = true;
    }

    protected boolean _endianSet = false;
    public Endian getEndian() {
        if (!_endianSet) {
            if (getMagicNumber() == 0x4d3c2b1a)
                _endian = Endian.LITTLE_ENDIAN;
            else if (getMagicNumber() == 0xa1b2c3d4)
                _endian = Endian.BIG_ENDIAN;
            else                                // otherwise, assume little endian ?
                _endian = Endian.LITTLE_ENDIAN;
            _endianSet = true;
        }

        return _endian;
    }
    /**
     * Fetch the global header length.
     */
    public int getGlobalHeaderLength() {
        return GLOBAL_HEADER_LEN;
    }

    /**
     * Fetch the global header as a byte array.
     */
    public byte[] getGlobalHeader() {
        return _bytes;
    }

    /**
     * Fetch the pcap record as a byte array.
     */
    /*private byte[] _recordsBytes = null;
    public byte[] getRecords() {
        if (_recordsBytes == null) {
            _recordsBytes = PacketEncoding.extractData(0, getGlobalHeaderLength(), _bytes);
        }
        return _recordsBytes;
    }*/

    /**
     * Fetch the magic number.
     */
    private int _magicNumber;
    private boolean _magicNumberSet = false;
    public int getMagicNumber() {
        if (!_magicNumberSet) {
            _magicNumber = ArrayHelper.extractInteger(_bytes, MAGIC_NUM_POS, MAGIC_NUM_LEN, Endian.BIG_ENDIAN);
            _magicNumberSet = true;
        }
        return _magicNumber;
    }

    /**
     * Fetch the major version.
     */
    private int _majorVersion;
    private boolean _majorVersionSet = false;
    public int getMajorversion() {
        if (!_majorVersionSet) {
            _majorVersion = ArrayHelper.extractInteger(_bytes, VER_POS, VER_LEN - 2, _endian);
            _majorVersionSet = true;
        }
        return _majorVersion;
    }

    /**
     * Fetch the minor version.
     */
    private int _minorVersion;
    private boolean _minorVersionSet = false;
    public int getMinorVersion() {
        if (!_minorVersionSet) {
            _minorVersion = (ArrayHelper.extractInteger(_bytes, VER_POS, VER_LEN, _endian) & 0xffff0000) >> 16;
            _minorVersionSet = true;
        }
        return _minorVersion;
    }

    /**
     * Fetch the version.
     */
    private String _version = null;
    public String getVersion() {
        if (_version == null) {
            _version = getMajorversion() + "." + getMinorVersion();
        }
        return _version;
    }

    /**
     * Fetch the correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps.
     */
    private int _thiszone;
    private boolean _thiszoneSet = false;
    public int getThiszone() {
        if (!_thiszoneSet) {
            _thiszone = ArrayHelper.extractInteger(_bytes, THIS_ZONE_POS, THIS_ZONE_LEN, _endian);
            _thiszoneSet = true;
        }
        return _thiszone;
    }

    /**
     * Fetch the accuracy of time stamps.  In practice, all tools set it to 0.
     */
    private int _sigfigs;
    private boolean _sigfigsSet = false;
    public int getSigfigs() {
        if (!_sigfigsSet) {
            _sigfigs = ArrayHelper.extractInteger(_bytes, SIGFIGS_POS, SIGFIGS_LEN, _endian);
            _sigfigsSet = true;
        }
        return _sigfigs;
    }

    /**
     * Fetch the the maximum length of packet.
     */
    private int _snaplen;
    private boolean _snaplenSet = false;
    public int getSnaplen() {
        if (!_snaplenSet) {
            _snaplen = ArrayHelper.extractInteger(_bytes, SNAPLEN_POS, SNAPLEN_LEN, _endian);
            _snaplenSet = true;
        }
        return _snaplen;
    }

    /**
     * Fetch the link type.
     */
    private int _linktype;
    private boolean _linktypeSet = false;
    public int getLinkType() {
        if (!_linktypeSet) {
            _linktype = ArrayHelper.extractInteger(_bytes, LINK_TYPE_POS, LINK_TYPE_LEN, _endian);
            _linktypeSet = true;
        }
        return _linktype;
    }

    /**
     * Convert this pcap file to a readable string.
     */
    public String toString() {
        return toColoredString(false);
    }

    /**
     * Generate string with contents describing this pcap header.
     * @param colored whether or not the string should contain ansi
     * color escape sequences.
     */
    public String toColoredString(boolean colored) {
        StringBuffer buffer = new StringBuffer();
        buffer.append('[');
        if(colored) buffer.append(getColor());
        buffer.append("PcapHeader");
        if(colored) buffer.append(AnsiEscapeSequences.RESET);
        buffer.append(": ");
        buffer.append("majorNumber=0x" + HexHelper.toString(getMagicNumber()) + ", ");
        buffer.append("version=" + getVersion() + ", ");
        buffer.append("thiszone=" + getThiszone() + ", ");
        buffer.append("sigfigs=" + getSigfigs() + ", ");
        buffer.append("snaplen=" + getSnaplen() + "(0x" + HexHelper.toString(getSnaplen()) + "), ");
        buffer.append("linktype=" + LinkLayer.getDescription(getLinkType()));
        buffer.append(']');

        return buffer.toString();
    }

    /**
     * Fetch ascii escape sequence of the color associated with this packet type.
     */
    public String getColor() {
        return AnsiEscapeSequences.DARK_GRAY;
    }
}
