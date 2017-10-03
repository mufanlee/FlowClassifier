package pcapparser.util;

import java.io.*;


/**
 * Writes data to file
 *
 * @author lipeng
 * @version 1.0
 *
 */
public class FileUtility
{
    public static String readFile(String filename) throws IOException {
        String readString = "";

        File f = new File(filename);
        char[] readIn = new char[(new Long(f.length())).intValue()];

        BufferedReader in = new BufferedReader(new FileReader(f));

        in.read(readIn);
        readString = new String(readIn);

        in.close();

        return readString;
    }

    public static void writeFile(String str, String filename, boolean append)
            throws IOException {

        int length = str.length();
        FileWriter out = new FileWriter(filename, append);
        out.write(str, 0, length);
        out.close();
    }

    public static void writeFile(byte[] bytes, String filename, boolean append)
            throws IOException {

        FileOutputStream out = new FileOutputStream(filename, append);
        out.write(bytes, 0, bytes.length);
        out.close();
    }

    public static void writeFile(byte[][] bytes, String filename, boolean append)
            throws IOException {

        writeFile(bytes[0], filename, append);
        for (int i=1; i < bytes.length; i++)
            writeFile(bytes[i], filename, true);
    }

    public static void writeFile(byte[][] bytes, int beginIndex, int endIndex,
                                 String filename, boolean append)
            throws IOException {
        writeFile(bytes[beginIndex], filename, append);
        for (int i=beginIndex + 1; i<=endIndex; i++)
            writeFile(bytes[i], filename, true);
    }
}
