package util;

import java.io.StringWriter;


/**
 * Functions for formatting and printing binary data in hexadecimal.
 *
 * @author lipeng
 * @version 1.0
        */
public class HexHelper {
    /**
     * validate the Ip Address
     * */
    public static boolean isIPAddress(String text) {
        if (text != null && !text.isEmpty()) {
            String regex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])\\."
                    + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                    + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                    + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
            if (text.matches(regex)) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }

    /**
     * Convert an int (32 bits in Java) to a decimal quad of the form
     * aaa.bbb.ccc.ddd.
     */
    public static String toQuadString(int i) {
        StringBuffer sb = new StringBuffer();
        for(int p = 0; p < 4; p++) {
            int q = (int)(i & 0xff);
            sb.append(q);
            if(p < 3)
                sb.append('.');
            i >>= 8;
        }

        return sb.toString();
    }

    /**
     * Convert an ip bytes array to a string.
     */
    public static String byteArrayToIpString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            builder.append(bytes[i] & 0xff);
            builder.append(".");
        }
        builder.deleteCharAt(builder.length() - 1);
        return builder.toString();
    }

    /**
     * Convert an int to an ip string.
     */
    public static String intToIpString(int i) {
        return byteArrayToIpString(intToByteArray(i));
    }

    /**
     * Convert an int to bytes array.
     */
    public static byte[] intToByteArray(int i) {
        byte[] result = new byte[4];
        //由高位到低位
        result[0] = (byte)((i >> 24) & 0xFF);
        result[1] = (byte)((i >> 16) & 0xFF);
        result[2] = (byte)((i >> 8) & 0xFF);
        result[3] = (byte)(i & 0xFF);
        return result;
    }

    /**
     * Convert an ip string to an int.
     */
    public static int ipStringToInt(final String string) throws IllegalArgumentException{
        int start = 0;
        int shift = 24;

        int raw = 0;
        while (shift >= 0) {
            int end = string.indexOf('.', start);
            if (end == start || !((shift > 0) ^ (end < 0)))
                throw new IllegalArgumentException("IP Address not well formed: " + string);

            String substr =
                    end > 0 ? string.substring(start, end) : string.substring(start);
            int val = Integer.parseInt(substr);
            if (val < 0 || val > 255)
                throw new IllegalArgumentException("IP Address not well formed: " + string);

            raw |= val << shift;

            shift -= 8;
            start = end + 1;
        }
        return raw;
    }

    /**
     * Convert an int to a hexadecimal string.
     */
    public static String toString(int i) {
        StringBuffer sb = new StringBuffer();
        for(int p = 0; p < 8; p++) {
            byte b = (byte)(i & 0xf);
            sb.append(nibbleToDigit(b));
            i >>= 4;
        }

        return sb.reverse().toString();
    }

    /**
     * Converts the lower four bits of a byte into the ascii digit
     * which represents its hex value. For example:
     * nibbleToDigit(10) produces 'a'.
     */
    public static char nibbleToDigit(byte x) {
        char c = (char)(x & 0xf); // mask low nibble
        return(c > 9 ? (char)(c - 10 + 'a') : (char)(c + '0')); // int to hex char
    }

    /**
     * Convert a single byte into a string representing its hex value.
     * i.e. -1 -> "ff"
     * @param b the byte to convert.
     * @return a string containing the hex equivalent.
     */
    public static String toString(byte b) {
        StringBuffer sb = new StringBuffer();
        sb.append(nibbleToDigit((byte)(b >> 4)));
        sb.append(nibbleToDigit(b));
        return sb.toString();
    }

    /**
     * Returns a text representation of a byte array.
     *
     * @param bytes a byte array
     * @return a string containing the hex equivalent of the bytes.
     */
    public static String toString(byte [] bytes) {
        StringWriter sw = new StringWriter();

        int length = bytes.length;
        if(length > 0) {
            for(int i = 0; i < length; i++) {
                sw.write(toString(bytes[i]));
                if(i != length - 1)
                    sw.write(" ");
            }
        }
        return(sw.toString());
    }
}