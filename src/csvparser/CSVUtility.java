package csvparser;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import org.apache.log4j.Logger;

import java.io.*;
import java.util.List;

public class CSVUtility {
    /**
     * logger
     */
    public static Logger logger = Logger.getLogger(CSVUtility.class);

    public static List<String []> reader(String fileName) {
        return reader(new File(fileName));
    }

    public static List<String []> reader(File file) {
        return reader(file, ',');
    }

    public static List<String []> reader(File file, char separator) {
        List<String[]> res = null;
        CSVReader reader = null;
        try {
            FileReader fr = new FileReader(file);
            if (',' == separator) {
                reader = new CSVReader(fr);
            } else {
                reader = new CSVReader(fr, separator);
            }
            res = reader.readAll();
            reader.close();
        } catch (FileNotFoundException e) {
            logger.error("File not found!");
            return null;
        } catch (IOException e) {
            logger.error("IO Exception: " + e.getMessage());
            return null;
        }
        return res;
    }

    public static boolean writer(String fileName, List<String []> list) {
        return writer(new File(fileName), list);
    }

    public static boolean writer(File file, List<String []> list) {
        return writer(file, list, ',', CSVWriter.NO_QUOTE_CHARACTER);
    }

    public static boolean writer(File file, List<String []> list, char separator, char quotechar) {
        CSVWriter writer = null;
        if (file.exists())
            file.delete();
        try {
            FileWriter fw = new FileWriter(file);
            if (',' == separator) {
                writer = new CSVWriter(fw);
            } else {
                writer = new CSVWriter(fw, separator, quotechar);
            }
            writer.writeAll(list);
            writer.close();
        } catch (IOException e) {
            logger.error("IO Exception: " + e.getMessage());
            return false;
        }
        return true;
    }
}
