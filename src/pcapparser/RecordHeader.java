package pcapparser;

import pcapparser.util.AnsiEscapeSequences;
import pcapparser.util.ArrayHelper;
import pcapparser.util.Timeval;

import java.io.Serializable;

/**
 * An RecordHeader.
 * <p>
 * Contains record header and payload in an RecordHeader.
 * <p>
 *
 * @author lipeng
 * @version 1.0
 *
 */
public class RecordHeader implements RecordFields, Serializable{

    protected byte[] _bytes;
    protected Endian _endian;

    /**
     * Create a new record header.
     */
    public RecordHeader(byte[] bytes, Endian endian) {
        _bytes = bytes;
        _endian = endian;
    }

    /**
     * Fetch the record header as a byte array.
     */
    public byte[] getRecordHeader() {
        return _bytes;
    }

    /**
     * Fetch the global header length.
     */
    public int getRecordHeaderLength() {
        return RECORD_HEADER_LEN;
    }

    /**
     * Fetch the packet as a byte array.
     */
    /*private byte[] _packetBytes = null;
    public byte[] getPacket() {
        if (_packetBytes == null) {
            _packetBytes = PacketEncoding.extractData(0, getRecordHeaderLength(), _bytes, getCaptureLength());
        }
        return _packetBytes;
    }*/

    /**
     * Fetch the timestamp(s).
     */
    private int _tsSec;
    private boolean _tsSecSet = false;
    public int getTimestampSec() {
        if (!_tsSecSet) {
            _tsSec = ArrayHelper.extractInteger(_bytes, TS_SEC_POS, TS_SEC_LEN, _endian);
            _tsSecSet = true;
        }
        return _tsSec;
    }

    /**
     * Fetch the timestamp(ms).
     */
    private int _tsUsec;
    private boolean _tsUsecSet = false;
    public int getTimestampUsec() {
        if (!_tsUsecSet) {
            _tsUsec = ArrayHelper.extractInteger(_bytes, TS_USEC_POS, TS_USEC_LEN, _endian);
            _tsUsecSet = true;
        }
        return _tsUsec;
    }

    /**
     * Fetch the capture length.
     */
    private int _caplen;
    private boolean _caplenSet = false;
    public int getCaptureLength() {
        if (!_caplenSet) {
            _caplen = ArrayHelper.extractInteger(_bytes, + CAPLEN_POS, CAPLEN_LEN, _endian);
            _caplenSet = true;
        }
        return _caplen;
    }

    /**
     * Fetch the original length.
     */
    private int _orglen;
    private boolean _orglenSet = false;
    public int getOrginalLength() {
        if (!_orglenSet) {
            _orglen = ArrayHelper.extractInteger(_bytes, + ORGLEN_POS, ORGLEN_LEN, _endian);
            _orglenSet = true;
        }
        return _orglen;
    }

    /**
     * Fetch the capture time.
     */
    private Timeval _timeval = null;
    public Timeval getTime() {
        if (_timeval == null) {
            _timeval = new Timeval(getTimestampSec(), getOrginalLength());
        }
        return _timeval;
    }

    /**
     * Convert this record to a readable string.
     */
    public String toString() {
        return toColoredString(false);
    }

    /**
     * Generate string with contents describing this record header.
     * @param colored whether or not the string should contain ansi
     * color escape sequences.
     */
    public String toColoredString(boolean colored) {
        StringBuffer buffer = new StringBuffer();
        buffer.append('[');
        if(colored) buffer.append(getColor());
        buffer.append("RecordHeader");
        if(colored) buffer.append(AnsiEscapeSequences.RESET);
        buffer.append(": ");
        buffer.append("time=" + getTime().getDate().toString() + ", ");
        //buffer.append("time=" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(getTime().getDate()) + ", ");
        buffer.append("caplen=" + getCaptureLength() + ", ");
        buffer.append("orglen=" + getOrginalLength());
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
