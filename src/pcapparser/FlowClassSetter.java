package pcapparser;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import util.HexHelper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FlowClassSetter {

    /**
     * logger
     */
    protected static Logger logger = Logger.getLogger(FlowClassSetter.class);

    public static List<FlowFeatures> setFlowFeatureClass(List<FlowFeatures> features, String file) {
        String cmd = "ndpiReader -i " + file + " -v 1";
        BufferedReader br = exec(cmd);
        Map<Flow, Integer> map = getFlowWithClass(br);

        logger.info(map.size());

        try {
            Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "ndpiReader -i " + file + " -v 1 > logs/dpiResult"});
        } catch (IOException e) {
            logger.error("Execute command for outputting result to file error!");
        }

        logger.info("Detected Flow numbers: " + map.size());

        List<FlowFeatures> res = new ArrayList<>();
        for (FlowFeatures f : features) {
            Flow f1 = new Flow(f.getSrcIP(), f.getDstIP(), f.getProtocol(), f.getSrcPort(), f.getDstPort());
            Flow f2 = new Flow(f.getDstIP(), f.getSrcIP(), f.getProtocol(), f.getDstPort(), f.getSrcPort());
            if (map.containsKey(f1)) {
                f.setFlowFeatureClass(FlowFeatureClass.ofClass(map.get(f1)));
                res.add(f);
            } else if (map.containsKey(f2)){
                f.setFlowFeatureClass(FlowFeatureClass.ofClass(map.get(f2)));
                res.add(f);
            } else {
                logger.debug("Flow Feature don't have class: " + f);
            }
        }
        return res;
    }

    public static Map<Flow, Integer> getFlowWithClass(BufferedReader br) {
        if (br == null) return null;

        try {
            Map<Flow, Integer> flows = new HashMap<>();
            String line;
            int i = 0, flowNum = 0;
            boolean isCan = false;
            while ((line = br.readLine()) != null) {
                if (line.length() > 14) {
                    if (!isCan) {
                        String s = line.substring(0, 14);
                        if (s.equals("Detected flows")) {
                            String[] ss = line.split(" ");
                            flowNum = Integer.parseInt(ss[2]);
                            isCan = true;
                            continue;
                        }
                    } else if (i < flowNum) {
                        i++;
                        String []ss = line.split("\t| ");
                        String []ipp = ss[2].split(":");
                        String srcIp = ipp[0], srcPort = ipp[1];
                        ipp = ss[4].split(":");
                        String dstIp = ipp[0], dstPort = ipp[1];
                        String protocol = ss[1].split("/")[0];
                        if (!HexHelper.isIPAddress(srcIp) || !HexHelper.isIPAddress(dstIp)) {
                            continue;
                        }

                        Flow flow = new Flow(srcIp, dstIp, protocol, srcPort, dstPort);
                        String []fc = ss[6].split("/");
                        int cls = 0;
                        if (fc[0].contains(".")) {
                            cls = Integer.parseInt(fc[0].split("\\.")[0]);
                        } else {
                            cls = Integer.parseInt(fc[0]);
                        }
                        flows.put(flow, cls);
                        //logger.info(flow.toString() + " " + ss[6]);
                    }
                }
            }
            return flows;
        } catch (IOException e) {
            logger.error("BufferReader readLine error!");
            return null;
        }
    }

    /**
     * Execute the command of the System
     * @param cmd the command
     * @return the string of the command return
     */
    public static BufferedReader exec(String cmd) {
        Runtime runtime = Runtime.getRuntime();
        try {
            Process process = runtime.exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return br;
        } catch (IOException e) {
            logger.error("Execute cmd error!");
            return null;
        }
    }

    // test
    public static void main(String []args) {
        PropertyConfigurator.configure("configs/log4j.properties");
        //FlowClassSetter seter = new FlowClassSetter();
        //CSVUtility.reader("F:/Weka/datasets/sig_00000_20010830012447_tcp.csv");
        //seter.getFlowWithClass("F:/Weka/datasets/sig_00000_20010830012447_tcp.csv", "F:/Weka/datasets/sig_00000_20010830012447_udp.csv");

        //BufferedReader br = FlowClassSetter.exec("ndpiReader -i ../datasets/sigcomm01/sig_00000.pcap -v 1");
        BufferedReader br = FlowClassSetter.exec("ndpiReader -i /home/lipeng/workspace/datasets/test2.pcap -v");
        FlowClassSetter.getFlowWithClass(br);
    }
}
