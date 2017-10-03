package pcapparser;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import pcapparser.net.*;
import pcapparser.util.FileUtility;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A parser for parsing the .pcap file
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

    /**
     * Threshold of Elephant Flow
     */
    private static final int THRESHOLD = 1000;

    Map<String, List<Packet>> map = new HashMap<>(1000);

    private static final int SIZE = 3;

    // construct
    public PcapParser(){}

    public PcapParser(String filename){
        _file = new File(filename);
    }

    public PcapParser(File file) {
        _file = file;
    }

    /**
     * Parse pcap file.
     */
    public boolean parse() {
        if (_file == null) return false;
        return parse(_file);
    }

    public boolean parse(String filename) {
        File f = new File(filename);
        return parse(f);
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
                logger.debug(pcapHeader);
                Endian endian = pcapHeader.getEndian();     // get endian
                int linkType = pcapHeader.getLinkType();    // get link type

                // write tile of the features' file
                //csv
                StringBuffer sb = new StringBuffer();
                /*sb.append("port,").append("protocol,").append("flags,").append("length,")
                        .append("dstIP,").append("payload,").append("class");*/
                sb.append("srcIP,").append("dstIP,").append("srcPort,").append("dstPort,").append("protocol,")
                        .append("serverOrClient,").append("packetSize,").append("class");
                  FileUtility.writeFile(sb.toString() + "\r\n", saveCSVFile, false);

                //arff
                FileUtility.writeFile("@relation flowClassify" + "\r\n\r\n", saveARFFFile, false);
                StringBuffer sb1 = new StringBuffer();
                sb1.append("@attribute ").append("srcIp ").append("numeric\r\n");
                sb1.append("@attribute ").append("dstIp ").append("numeric\r\n");
                sb1.append("@attribute ").append("srcPort ").append("numeric\r\n");
                sb1.append("@attribute ").append("dstPort ").append("numeric\r\n");
                sb1.append("@attribute ").append("protocol ").append("numeric\r\n");
                sb1.append("@attribute ").append("serverOrClient ").append("numeric\r\n");
                sb1.append("@attribute ").append("packetSize ").append("numeric\r\n");
                sb1.append("@attribute ").append("class ").append("{Elephant, Mouse}\r\n");
                sb1.append("\r\n@data\r\n");
                FileUtility.writeFile(sb1.toString() + "\r\n", saveARFFFile, true);

                // read record header
                int i = 0;
                while (fis.read(RECORD_HEADER) != -1) {
                    RecordHeader recordHeader = new RecordHeader(RECORD_HEADER, endian);
                    //logger.debug(recordHeader);
                    // read packet
                    byte[] PACKET = new byte[recordHeader.getCaptureLength()];
                    if (fis.read(PACKET) != -1) {
                        Packet packet = PacketParser.dataToPacket(linkType, PACKET, recordHeader.getTime());
                        //logger.debug(packet);

                        PacketParser.packetToMap(linkType, PACKET, map, SIZE);
                        if (i == (500000)) break;
                        i++;
                    }
                }

                List<FlowFeatures> features = PacketParser.mapToFlowFeatures(map, THRESHOLD);
                FileUtility.writeFile("% instances: " + features.size() + "\r\n\r\n", saveARFFFile, true);
                if (features != null) {
                    for (FlowFeatures fts : features) {
                        if (fts != null) {
                            FileUtility.writeFile(fts.toCSV() + "\r\n", saveCSVFile, true);
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

    // test
    public static void main(String []args) {
        PropertyConfigurator.configure("configs/log4j.properties");

        PcapParser parser = new PcapParser();
        //parser.parse("F:/workspace/java/PcapAnalyer/music.pcap");
        parser.parse("F:/Weka/datasets/sig_00000_20010830012447.pcap");
    }
}
