package util;

import org.apache.log4j.Logger;

import java.io.*;
import java.util.Properties;

/**
 * A SystemConfigurator for configuring the System.
 *
 * @author lipeng
 * @version 1.0
 */
public class SystemConfigurator {
    public static final String DEFAULT_CONFIG_FILE = "configs/flowClassifier.properties";
    public static Logger logger = Logger.getLogger(SystemConfigurator.class);

    private static Properties prop = new Properties();
    private static String configFile = DEFAULT_CONFIG_FILE;
    static {
        load();
    }

    public static void setConfigFile(String file){
        configFile = file;
        load();
    }

    private static void load() {
        try {
            prop.load(new FileInputStream(configFile));
        } catch (FileNotFoundException e) {
            logger.error("File not found!");
        } catch (IOException e) {
            logger.error("Properties load error!");
        }
    }

    public static String read(String key) {
        return prop.getProperty(key);
    }

    public static String read(String fileName, String key) {
        Properties prop = new Properties();
        InputStream in = null;
        try {
            in = new BufferedInputStream(new FileInputStream(fileName));
            prop.load(in);
            String res = prop.getProperty(key);
            return res;
        } catch (FileNotFoundException e) {
            logger.error("File not found!");
            return null;
        } catch (IOException e) {
            logger.error("Properties load error!");
            return null;
        } finally {
                try {
                    if (in != null) in.close();
                } catch (IOException e) {
                    logger.error("File close error!");
                    return null;
                }
        }
    }

    public static void write(String fileName, String key, String value) {
        Properties prop = new Properties();
        OutputStream out = null;
        try {
            out = new FileOutputStream(fileName, true);
            prop.setProperty(key, value);
            prop.store(out, key);
        } catch (FileNotFoundException e) {
            logger.error("File not found!");
        } catch (IOException e) {
            logger.error("Properties store error!");
        } finally {
            if (out != null) try {
                out.close();
            } catch (IOException e) {
                logger.error("File close error!");
            }
        }
    }

    public static void update(String fileName, String key, String value) {
        Properties prop = new Properties();
        OutputStream out = null;
        try {
            prop.load(new FileInputStream(fileName));
            out = new FileOutputStream(fileName);
            prop.setProperty(key, value);
            prop.store(out, key);
        } catch (FileNotFoundException e) {
            logger.error("File not found!");
        } catch (IOException e) {
            logger.error("Properties store error!");
        } finally {
            if (out != null) try {
                out.close();
            } catch (IOException e) {
                logger.error("File close error!");
            }
        }
    }
}
