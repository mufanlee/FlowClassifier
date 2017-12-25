package pcapparser;

import util.HexHelper;

/**
 * Flow features
 *
 * @author lipeng
 * @version 1.0
 */
public class FlowFeatures {
    /**
     * IP 地址（4 字节）
     */
    private int srcIP;
    private int dstIP;

    /**
     * 端口号（2 字节）
     */
    private int srcPort;
    private int dstPort;

    /**
     * 协议类型（1 字节）
     */
    private int protocol;

    /**
     * Packet inter-arrival time (Maximum, Minimum, Mean, Median, Variance)
     */
    private    int maxIAT;
    private    int minIAT;
    private double medIAT;
    private double meaIAT;
    private double varIAT;

    /**
     * Forward inter-arrival time
     */
    private    int maxFIAT;
    private    int minFIAT;
    private double medFIAT;
    private double meaFIAT;
    private double varFIAT;

    /**
     * Backward inter-arrival time
     */
    private    int maxBIAT;
    private    int minBIAT;
    private double medBIAT;
    private double meaBIAT;
    private double varBIAT;

    /**
     * Bytes in Ethernet packet, using the size of the packet on the wire
     */
    private    int maxETHBytes;
    private    int minETHBytes;
    private double medETHBytes;
    private double meaETHBytes;
    private double varETHBytes;

    private    int maxFETHBytes;
    private    int minFETHBytes;
    private double medFETHBytes;
    private double meaFETHBytes;
    private double varFETHBytes;

    private    int maxBETHBytes;
    private    int minBETHBytes;
    private double medBETHBytes;
    private double meaBETHBytes;
    private double varBETHBytes;

    /**
     * Bytes in IP Packet, using the size of payload declared by the IP packet
     */
    private    int maxIPBytes;
    private    int minIPBytes;
    private double medIPBytes;
    private double meaIPBytes;
    private double varIPBytes;

    private    int maxFIPBytes;
    private    int minFIPBytes;
    private double medFIPBytes;
    private double meaFIPBytes;
    private double varFIPBytes;

    private    int maxBIPBytes;
    private    int minBIPBytes;
    private double medBIPBytes;
    private double meaBIPBytes;
    private double varBIPBytes;

    /**
     * Payload in Datagram, using the size of payload declared by the TCP/UDP datagram
     */
    private    int maxPLDBytes;
    private    int minPLDBytes;
    private double medPLDBytes;
    private double meaPLDBytes;
    private double varPLDBytes;

    private    int maxFPLDBytes;
    private    int minFPLDBytes;
    private double medFPLDBytes;
    private double meaFPLDBytes;
    private double varFPLDBytes;

    private    int maxBPLDBytes;
    private    int minBPLDBytes;
    private double medBPLDBytes;
    private double meaBPLDBytes;
    private double varBPLDBytes;
    /**
     * Control bytes in packet, size of the (IP/TCP) packet header
     */
    private    int maxCTLBytes;
    private    int minCTLBytes;
    private double medCTLBytes;
    private double meaCTLBytes;
    private double varCTLBytes;

    private    int maxFCTLBytes;
    private    int minFCTLBytes;
    private double medFCTLBytes;
    private double meaFCTLBytes;
    private double varFCTLBytes;

    private    int maxBCTLBytes;
    private    int minBCTLBytes;
    private double medBCTLBytes;
    private double meaBCTLBytes;
    private double varBCTLBytes;

    /**
     * Round-Trip Time (RTT)
     */
    private double fstRTT;
    private double maxRTT;
    private double minRTT;
    private double medRTT;
    private double meaRTT;
    private double varRTT;

    /**
     * Duration
     */
    private long duration;
    private long fduration;
    private long bduration;

    /**
     * Average packet throughput and byte throughput
     */


    /**
     * 数据包来自服务器or客户端，仅用于TCP
     */
    private int serverOrClient;

    /**
     * 前5个数据包大小
     */
    private int sizeOf5Pkt;
    private int fsizeOf5Pkt;
    private int bsizeOf5Pkt;

    /**
     * Feature class
     */
    private FlowFeatureClass flowFeatureClass;

    public FlowFeatures() {}

    public int getSrcIP() {
        return srcIP;
    }

    public void setSrcIP(int srcIP) {
        this.srcIP = srcIP;
    }

    public int getDstIP() {
        return dstIP;
    }

    public void setDstIP(int dstIP) {
        this.dstIP = dstIP;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public void setFlow(int srcIP, int dstIP, int srcPort, int dstPort, int protocol) {
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public void setInterArrivalTime(int maxIAT, int minIAT, double medIAT, double meaIAT, double varIAT) {
        this.maxIAT = maxIAT;
        this.minIAT = minIAT;
        this.medIAT = medIAT;
        this.meaIAT = meaIAT;
        this.varIAT = varIAT;
    }

    public void setForwardInterArrivalTime(int maxFIAT, int minFIAT, double medFIAT, double meaFIAT, double varFIAT) {
        this.maxFIAT = maxFIAT;
        this.minFIAT = minFIAT;
        this.medFIAT = medFIAT;
        this.meaFIAT = meaFIAT;
        this.varFIAT = varFIAT;
    }

    public void setBackwardInterArrivalTime(int maxBIAT, int minBIAT, double medBIAT, double meaBIAT, double varBIAT) {
        this.maxBIAT = maxBIAT;
        this.minBIAT = minBIAT;
        this.medBIAT = medBIAT;
        this.meaBIAT = meaBIAT;
        this.varBIAT = varBIAT;
    }

    public void setETHBytes(int maxETHBytes, int minETHBytes, double medETHBytes, double meaETHBytes, double varETHBytes) {
        this.maxETHBytes = maxETHBytes;
        this.minETHBytes = minETHBytes;
        this.medETHBytes = medETHBytes;
        this.meaETHBytes = meaETHBytes;
        this.varETHBytes = varETHBytes;
    }

    public void setForwardETHBytes(int maxFETHBytes, int minFETHBytes, double medFETHBytes, double meaFETHBytes, double varFETHBytes) {
        this.maxFETHBytes = maxFETHBytes;
        this.minFETHBytes = minFETHBytes;
        this.medFETHBytes = medFETHBytes;
        this.meaFETHBytes = meaFETHBytes;
        this.varFETHBytes = varFETHBytes;
    }

    public void setBackwardETHBytes(int maxBETHBytes, int minBETHBytes, double medBETHBytes, double meaBETHBytes, double varBETHBytes) {
        this.maxBETHBytes = maxBETHBytes;
        this.minBETHBytes = minBETHBytes;
        this.medBETHBytes = medBETHBytes;
        this.meaBETHBytes = meaBETHBytes;
        this.varBETHBytes = varBETHBytes;
    }

    public void setIPBytes(int maxIPBytes, int minIPBytes, double medIPBytes, double meaIPBytes, double varIPBytes) {
        this.maxIPBytes = maxIPBytes;
        this.minIPBytes = minIPBytes;
        this.medIPBytes = medIPBytes;
        this.meaIPBytes = meaIPBytes;
        this.varIPBytes = varIPBytes;
    }

    public void setForwardIPBytes(int maxFIPBytes, int minFIPBytes, double medFIPBytes, double meaFIPBytes, double varFIPBytes) {
        this.maxFIPBytes = maxFIPBytes;
        this.minFIPBytes = minFIPBytes;
        this.medFIPBytes = medFIPBytes;
        this.meaFIPBytes = meaFIPBytes;
        this.varFIPBytes = varFIPBytes;
    }

    public void setBackwardIPBytes(int maxBIPBytes, int minBIPBytes, double medBIPBytes, double meaBIPBytes, double varBIPBytes) {
        this.maxBIPBytes = maxBIPBytes;
        this.minBIPBytes = minBIPBytes;
        this.medBIPBytes = medBIPBytes;
        this.meaBIPBytes = meaBIPBytes;
        this.varBIPBytes = varBIPBytes;
    }

    public void setPayloadBytes(int maxPLDBytes, int minPLDBytes, double medPLDBytes, double meaPLDBytes, double varPLDBytes) {
        this.maxPLDBytes = maxPLDBytes;
        this.minPLDBytes = minPLDBytes;
        this.medPLDBytes = medPLDBytes;
        this.meaPLDBytes = meaPLDBytes;
        this.varPLDBytes = varPLDBytes;
    }

    public void setForwardPayloadBytes(int maxFPLDBytes, int minFPLDBytes, double medFPLDBytes, double meaFPLDBytes, double varFPLDBytes) {
        this.maxFPLDBytes = maxFPLDBytes;
        this.minFPLDBytes = minFPLDBytes;
        this.medFPLDBytes = medFPLDBytes;
        this.meaFPLDBytes = meaFPLDBytes;
        this.varFPLDBytes = varFPLDBytes;
    }

    public void setBackwardPayloadBytes(int maxBPLDBytes, int minBPLDBytes, double medBPLDBytes, double meaBPLDBytes, double varBPLDBytes) {
        this.maxBPLDBytes = maxBPLDBytes;
        this.minBPLDBytes = minBPLDBytes;
        this.medBPLDBytes = medBPLDBytes;
        this.meaBPLDBytes = meaBPLDBytes;
        this.varBPLDBytes = varBPLDBytes;
    }

    public void setControlBytes(int maxCTLBytes, int minCTLBytes, double medCTLBytes, double meaCTLBytes, double varCTLBytes) {
        this.maxCTLBytes = maxCTLBytes;
        this.minCTLBytes = minCTLBytes;
        this.medCTLBytes = medCTLBytes;
        this.meaCTLBytes = meaCTLBytes;
        this.varCTLBytes = varCTLBytes;
    }

    public void setForwardControlBytes(int maxFCTLBytes, int minFCTLBytes, double medFCTLBytes, double meaFCTLBytes, double varFCTLBytes) {
        this.maxFCTLBytes = maxFCTLBytes;
        this.minFCTLBytes = minFCTLBytes;
        this.medFCTLBytes = medFCTLBytes;
        this.meaFCTLBytes = meaFCTLBytes;
        this.varFCTLBytes = varFCTLBytes;
    }

    public void setBackwardControlBytes(int maxBCTLBytes, int minBCTLBytes, double medBCTLBytes, double meaBCTLBytes, double varBCTLBytes) {
        this.maxBCTLBytes = maxBCTLBytes;
        this.minBCTLBytes = minBCTLBytes;
        this.medBCTLBytes = medBCTLBytes;
        this.meaBCTLBytes = meaBCTLBytes;
        this.varBCTLBytes = varBCTLBytes;
    }

    public void setRTT(double fstRTT, double maxRTT, double minRTT, double medRTT, double meaRTT, double varRTT) {
        this.fstRTT = fstRTT;
        this.maxRTT = maxRTT;
        this.minRTT = minRTT;
        this.medRTT = medRTT;
        this.meaRTT = meaRTT;
        this.varRTT = varRTT;
    }

    public void setDuration(long duration, long fduration, long bduration) {
        this.duration = duration;
        this.fduration = fduration;
        this.bduration = bduration;
    }

    public void setServerOrClient(int serverOrClient) {
        this.serverOrClient = serverOrClient;
    }

    public void setSizeOf5Pkt(int size, int fsize, int bsize) {
        this.sizeOf5Pkt = size;
        this.fsizeOf5Pkt = fsize;
        this.bsizeOf5Pkt = bsize;
    }

    public FlowFeatureClass getFlowFeatureClass() {
        return flowFeatureClass;
    }

    public void setFlowFeatureClass(FlowFeatureClass flowFeatureClass) {
        this.flowFeatureClass = flowFeatureClass;
    }

    public String toCSV() {
        StringBuffer buffer = new StringBuffer();
        buffer.append(srcIP).append(",")
                .append(dstIP).append(",")
                .append(srcPort).append(",")
                .append(dstPort).append(",")
                .append(protocol).append(",")

                .append(maxIAT).append(",")
                .append(minIAT).append(",")
                .append(medIAT).append(",")
                .append(meaIAT).append(",")
                .append(varIAT).append(",")

                .append(maxFIAT).append(",")
                .append(minFIAT).append(",")
                .append(medFIAT).append(",")
                .append(meaFIAT).append(",")
                .append(varFIAT).append(",")

                .append(maxBIAT).append(",")
                .append(minBIAT).append(",")
                .append(medBIAT).append(",")
                .append(meaBIAT).append(",")
                .append(varBIAT).append(",")

                .append(maxETHBytes).append(",")
                .append(minETHBytes).append(",")
                .append(medETHBytes).append(",")
                .append(meaETHBytes).append(",")
                .append(varETHBytes).append(",")

                .append(maxFETHBytes).append(",")
                .append(minFETHBytes).append(",")
                .append(medFETHBytes).append(",")
                .append(meaFETHBytes).append(",")
                .append(varFETHBytes).append(",")

                .append(maxBETHBytes).append(",")
                .append(minBETHBytes).append(",")
                .append(medBETHBytes).append(",")
                .append(meaBETHBytes).append(",")
                .append(varBETHBytes).append(",")

                .append(maxIPBytes).append(",")
                .append(minIPBytes).append(",")
                .append(medIPBytes).append(",")
                .append(meaIPBytes).append(",")
                .append(varIPBytes).append(",")

                .append(maxFIPBytes).append(",")
                .append(minFIPBytes).append(",")
                .append(medFIPBytes).append(",")
                .append(meaFIPBytes).append(",")
                .append(varFIPBytes).append(",")

                .append(maxBIPBytes).append(",")
                .append(minBIPBytes).append(",")
                .append(medBIPBytes).append(",")
                .append(meaBIPBytes).append(",")
                .append(varBIPBytes).append(",")

                .append(maxPLDBytes).append(",")
                .append(minPLDBytes).append(",")
                .append(medPLDBytes).append(",")
                .append(meaPLDBytes).append(",")
                .append(varPLDBytes).append(",")

                .append(maxFPLDBytes).append(",")
                .append(minFPLDBytes).append(",")
                .append(medFPLDBytes).append(",")
                .append(meaFPLDBytes).append(",")
                .append(varFPLDBytes).append(",")

                .append(maxBPLDBytes).append(",")
                .append(minBPLDBytes).append(",")
                .append(medBPLDBytes).append(",")
                .append(meaBPLDBytes).append(",")
                .append(varBPLDBytes).append(",")

                .append(maxCTLBytes).append(",")
                .append(minCTLBytes).append(",")
                .append(medCTLBytes).append(",")
                .append(meaCTLBytes).append(",")
                .append(varCTLBytes).append(",")

                .append(maxFCTLBytes).append(",")
                .append(minFCTLBytes).append(",")
                .append(medFCTLBytes).append(",")
                .append(meaFCTLBytes).append(",")
                .append(varFCTLBytes).append(",")

                .append(maxBCTLBytes).append(",")
                .append(minBCTLBytes).append(",")
                .append(medBCTLBytes).append(",")
                .append(meaBCTLBytes).append(",")
                .append(varBCTLBytes).append(",")

                .append(fstRTT).append(",")
                .append(maxRTT).append(",")
                .append(minRTT).append(",")
                .append(medRTT).append(",")
                .append(meaRTT).append(",")
                .append(varRTT).append(",")

                .append(duration).append(",")
                .append(fduration).append(",")
                .append(bduration).append(",")

                .append(serverOrClient).append(",")

                .append(sizeOf5Pkt).append(",")
                .append(fsizeOf5Pkt).append(",")
                .append(bsizeOf5Pkt).append(",")

                .append(flowFeatureClass);

        return buffer.toString();
    }

    @Override
    public String toString() {
        StringBuilder buffer = new StringBuilder();
        buffer.append('[');
        buffer.append("pcapparser.FlowFeatures");
        buffer.append(": ");
        //buffer.append("srcIP=" + srcIP + ", ");
        buffer.append("srcIP=").append(HexHelper.intToIpString(srcIP)).append(", ");
        //buffer.append("dstIP=" + dstIP + ", ");
        buffer.append("dstIP=").append(HexHelper.intToIpString(dstIP)).append(", ");
        buffer.append("srcPort=").append(srcPort).append(", ");
        buffer.append("dstPort=").append(dstPort).append(", ");
        buffer.append("protocol=").append(protocol).append(", ");
        buffer.append("IAT=").append(maxIAT).append(" ").append(minIAT).append(" ").append(medIAT).append(" ").append(meaIAT).append(" ").append(varIAT).append(", ");
        buffer.append("FIAT=").append(maxFIAT).append(" ").append(minFIAT).append(" ").append(medFIAT).append(" ").append(meaFIAT).append(" ").append(varFIAT).append(", ");
        buffer.append("BIAT=").append(maxBIAT).append(" ").append(minBIAT).append(" ").append(medBIAT).append(" ").append(meaBIAT).append(" ").append(varBIAT).append(", ");
        buffer.append("ETHBytes=").append(maxETHBytes).append(" ").append(minETHBytes).append(" ").append(medETHBytes).append(" ").append(meaETHBytes).append(" ").append(varETHBytes).append(", ");
        buffer.append("FETHBytes=").append(maxFETHBytes).append(" ").append(minFETHBytes).append(" ").append(medFETHBytes).append(" ").append(meaFETHBytes).append(" ").append(varFETHBytes).append(", ");
        buffer.append("BETHBytes=").append(maxBETHBytes).append(" ").append(minBETHBytes).append(" ").append(medBETHBytes).append(" ").append(meaBETHBytes).append(" ").append(varBETHBytes).append(", ");
        buffer.append("IPBytes=").append(maxIPBytes).append(" ").append(minIPBytes).append(" ").append(medIPBytes).append(" ").append(meaIPBytes).append(" ").append(varIPBytes).append(", ");
        buffer.append("FIPBytes=").append(maxFIPBytes).append(" ").append(minFIPBytes).append(" ").append(medFIPBytes).append(" ").append(meaFIPBytes).append(" ").append(varFIPBytes).append(", ");
        buffer.append("BIPBytes=").append(maxBIPBytes).append(" ").append(minBIPBytes).append(" ").append(medBIPBytes).append(" ").append(meaBIPBytes).append(" ").append(varBIPBytes).append(", ");
        buffer.append("CTLBytes=").append(maxCTLBytes).append(" ").append(minCTLBytes).append(" ").append(medCTLBytes).append(" ").append(meaCTLBytes).append(" ").append(varCTLBytes).append(", ");
        buffer.append("FCTLBytes=").append(maxFCTLBytes).append(" ").append(minFCTLBytes).append(" ").append(medFCTLBytes).append(" ").append(meaFCTLBytes).append(" ").append(varFCTLBytes).append(", ");
        buffer.append("BCTLBytes=").append(maxBCTLBytes).append(" ").append(minBCTLBytes).append(" ").append(medBCTLBytes).append(" ").append(meaBCTLBytes).append(" ").append(varBCTLBytes).append(", ");
        buffer.append("PLDBytes=").append(maxPLDBytes).append(" ").append(minPLDBytes).append(" ").append(medPLDBytes).append(" ").append(meaPLDBytes).append(" ").append(varPLDBytes).append(", ");
        buffer.append("FPLDBytes=").append(maxFPLDBytes).append(" ").append(minFPLDBytes).append(" ").append(medFPLDBytes).append(" ").append(meaBPLDBytes).append(" ").append(varBPLDBytes).append(", ");
        buffer.append("BPLDBytes=").append(maxBPLDBytes).append(" ").append(minBPLDBytes).append(" ").append(medBPLDBytes).append(" ").append(meaBPLDBytes).append(" ").append(varBPLDBytes).append(", ");
        buffer.append("RTT=").append(fstRTT).append(" ").append(maxRTT).append(" ").append(minRTT).append(" ").append(medRTT).append(" ").append(meaRTT).append(" ").append(varRTT).append(", ");
        buffer.append("Duration=").append(duration).append(" ").append(fduration).append(" ").append(bduration).append(", ");
        buffer.append("serverOrClient=").append(serverOrClient).append(", ");
        buffer.append("sizeOf5Pkt=").append(sizeOf5Pkt).append(", ").append(fsizeOf5Pkt).append(", ").append(bsizeOf5Pkt).append(", ");
        buffer.append(']');
        return buffer.toString();
    }
}