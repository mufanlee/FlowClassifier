package util;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import java.io.*;

public class DatasetHelper {
    static Logger logger = Logger.getLogger(DatasetHelper.class);

    public static boolean merge(String dirName, String fileName) throws IOException {
        File dir = new File(dirName);
        if (!dir.exists()) {
            logger.error("File path not found!");
            return false;
        }

        File file = new File(fileName);
        if (!file.exists()) {
            file.createNewFile();
        } else {
            file.delete();
            file.createNewFile();
        }

        File[] files = dir.listFiles();
        boolean isFirst = true;
        BufferedReader reader;
        BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
        for (File f : files) {
            logger.info(f.getName());
            if (isFirst) {
                reader = new BufferedReader(new FileReader(f));
                String line;
                while ((line = reader.readLine()) != null) {
                    writer.write(line + "\n");
                }
                isFirst = false;
                reader.close();
            } else {
                reader = new BufferedReader(new FileReader(f));
                String line;
                boolean isStart = false;
                while ((line = reader.readLine()) != null) {
                    if (line.length() > 1 && line.charAt(0) == '@' && (line.substring(1)).equals("data")) {
                        isStart = true;
                        break;
                    }
                }

                if (isStart) {
                    while ((line = reader.readLine()) != null) {
                        if (line.length() > 0 && line.charAt(0) != '%') {
                            writer.write(line + "\n");
                        }
                    }
                }
                reader.close();
            }
        }
        writer.close();
        return true;
    }

    public static void main(String []args) {
        PropertyConfigurator.configure("configs/log4j.properties");
        try {
            boolean res = DatasetHelper.merge("datasets/201701", "datasets/201701.arff");
            System.out.println(res);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
