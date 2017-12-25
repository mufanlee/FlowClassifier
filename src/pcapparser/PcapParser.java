package pcapparser;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import pcapparser.net.*;
import util.FileUtility;
import util.SystemConfigurator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A reader for parsing the .pcap file
 *
 * @author lipeng
 * @version 1.0
 */
public class PcapParser {

    /**
     * logger
     */
    protected Logger logger = Logger.getLogger(PcapParser.class);

    /**
     * Pcap file header information.
     */
    public PcapHeader pcapHeader = null;

    /**
     * Record header information for each record.
     */
    public List<RecordHeader> recordHeaders = new ArrayList<>();

    /**
     * Pcap file.
     */
    private File _file = null;

    /**
     * Save features to the file "saveCSVFile"
     */
    private String saveCSVFile = "datasets/features.csv";
    private String saveARFFFile = "datasets/features.arff";

    Map<String, List<Packet>> forwardFlowMap;
    Map<String, List<Packet>> backwardFlowMap;

    private static final int SIZE = 7;

    // construct
    public PcapParser(){
        forwardFlowMap = new HashMap<>(2048);
        backwardFlowMap = new HashMap<>(2048);
    }

    public PcapParser(String filename){
        _file = new File(filename);
        forwardFlowMap = new HashMap<>(2048);
        backwardFlowMap = new HashMap<>(2048);
    }

    public PcapParser(File file) {
        _file = file;
        forwardFlowMap = new HashMap<>(2048);
        backwardFlowMap = new HashMap<>(2048);
    }

    public void setSaveFile(String fileName) {
        String name = "datasets/" + fileName;
        this.saveCSVFile = name + ".csv";
        this.saveARFFFile = name + ".arff";
    }

    /**
     * Parse pcap file.
     */
    public boolean parse() {
        if (_file == null) return false;
        return parse(_file);
    }

    public boolean parse(String filename) {
        _file = new File(filename);
        return parse();
    }

    public boolean parse(File file) {
        byte[] GLOBAL_HEADER = new byte[PcapFields.GLOBAL_HEADER_LEN];
        byte[] RECORD_HEADER = new byte[RecordFields.RECORD_HEADER_LEN];
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            //read pcap header
            if (fis.read(GLOBAL_HEADER) != -1) {
                pcapHeader = new PcapHeader(GLOBAL_HEADER);
                logger.info(pcapHeader);
                Endian endian = pcapHeader.getEndian();     // get endian
                int linkType = pcapHeader.getLinkType();    // get link type
                logger.info("Endian: " + pcapHeader.getEndian());
                logger.info("Link Type: " + LinkLayer.getDescription(pcapHeader.getLinkType()));

                // write tile of the features' file
                //csv
                //String csvHeader = SystemConfigurator.read("csv");
                //FileUtility.writeFile(csvHeader+ "\r\n", saveCSVFile, false);
                //arff
                String arffHeader = SystemConfigurator.read("arff");
                FileUtility.writeFile(arffHeader + "\r\n", saveARFFFile, false);

                // read record header
                while (fis.read(RECORD_HEADER) != -1) {
                    RecordHeader recordHeader = new RecordHeader(RECORD_HEADER, endian);
                    //logger.debug(recordHeader);

                    // read packet
                    byte[] PACKET = new byte[recordHeader.getCaptureLength()];
                    if (fis.read(PACKET) != -1) {
                        //Packet packet = PacketParser.dataToPacket(linkType, PACKET, recordHeader.getTime());
                        //logger.debug(packet);
                        PacketParser.packetToFlowMap(linkType, PACKET, forwardFlowMap, backwardFlowMap, SIZE, recordHeader.getTime());
                    }
                }

                logger.info("Flow numbers: " + forwardFlowMap.size());
                List<FlowFeatures> features = PacketParser.extractFlowFeatures(forwardFlowMap, backwardFlowMap, SIZE);
                logger.info("Flow Features numbers: " + features.size());

                // set the class
                //FlowClassSetter setter = new FlowClassSetter();
                List<FlowFeatures> flowFeatures = FlowClassSetter.setFlowFeatureClass(features, file.getAbsolutePath());

                FileUtility.writeFile("% instances: " + flowFeatures.size() + "\r\n\r\n", saveARFFFile, true);
                logger.info("Flow Features with Class numbers: " + flowFeatures.size());
                if (features != null) {
                    for (FlowFeatures fts : flowFeatures) {
                        if (fts != null) {
                            //FileUtility.writeFile(fts.toCSV() + "\r\n", saveCSVFile, true);
                            FileUtility.writeFile(fts.toCSV() + "\r\n", saveARFFFile, true);
                        }
                    }
                }
                return true;
            }
        } catch (FileNotFoundException e) {
            logger.error("File not found!");
            return false;
        } catch (IOException e) {
            logger.error("IO Exception: " + e.getMessage());
            return false;
        }
        return false;
    }

    public void handleFile(String path) {
        File file = new File(path);
        if (!file.exists()) {
            logger.error("File not found!");
        }
        if (file.isDirectory()) {
            logger.error("File is a directory!");
        }
        PcapParser parser = new PcapParser(file);
        String name = file.getName().substring(0, file.getName().indexOf("."));
        parser.setSaveFile(name);
        parser.parse();
    }

    public void handleDirectory(String path) {
        File dir = new File(path);
        if (!dir.exists()) {
            logger.error("File path not found!");
        }

        String dirName = path.substring(path.lastIndexOf("/") + 1);
        File newDir = new File("datasets/" + dirName);
        if (!newDir.exists()) {
            newDir.mkdir();
        }

        PcapParser parser;
        File[] files = dir.listFiles();
        for (File file : files) {
            if (file.isDirectory()) continue;
            String name = dirName + "/" + file.getName().substring(0, file.getName().indexOf("."));
            parser = new PcapParser();
            parser.setSaveFile(name);
            parser.parse(file);
            System.gc();
        }
    }

    // main
    public static void main(String []args) {
        PropertyConfigurator.configure("configs/log4j.properties");

        PcapParser parser = new PcapParser();

        String path = "/home/lipeng/workspace/datasets/WIDE/201701";
        File file = new File(path);
        if (file.exists()) {
            if (file.isDirectory()) {
                parser.handleDirectory(path);
            } else {
                parser.handleFile(path);
            }
        } else {
            System.out.println("File not found!");
        }
    }
}