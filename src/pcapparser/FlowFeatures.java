package pcapparser;

import pcapparser.util.HexHelper;

/**
 * Flow features
 *
 * @author lipeng
 * @version 0.2
 */
public class FlowFeatures {
    // 流特征：源IP地址、目的IP地址、源端口号、目的端口号、协议、server vs client、前3个数据包的大小
    //

    /**
     * IP 地址（4 字节）
     */
    private long srcIP;
    private long dstIP;

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
     * 数据包来自服务器or客户端，仅用于TCP
     */
    private int serOrCli;

    /**
     * 前3个数据包大小
     */
    private int sizeOf3Pkt;

    private FlowClass flowClass;

    public FlowFeatures(long srcIP, long dstIP, int srcPort, int dstPort, int protocol, int serOrCli) {
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.serOrCli = serOrCli;
    }

    public FlowFeatures(long srcIP, long dstIP, int srcPort, int dstPort, int protocol, int serOrCli, int sizeOf3Pkt) {
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.serOrCli = serOrCli;
        this.sizeOf3Pkt = sizeOf3Pkt;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setSizeOf3Pkt(int sizeOf3Pkt) {
        this.sizeOf3Pkt = sizeOf3Pkt;
    }

    public FlowClass getFlowClass() {
        return flowClass;
    }

    public void setFlowClass(FlowClass flowClass) {
        this.flowClass = flowClass;
    }

    public String toCSV() {
        StringBuffer buffer = new StringBuffer();
        buffer.append(srcIP).append(",")
                .append(dstIP).append(",")
                .append(srcPort).append(",")
                .append(dstPort).append(",")
                .append(protocol).append(",")
                .append(serOrCli).append(",")
                .append(sizeOf3Pkt).append(",")
                .append(flowClass);

        return buffer.toString();
    }

    @Override
    public String toString() {
        StringBuffer buffer = new StringBuffer();
        buffer.append('[');
        buffer.append("pcapparser.FlowFeatures");
        buffer.append(": ");
        //buffer.append("srcIP=" + srcIP + ", ");
        buffer.append("srcIP=" + HexHelper.intToIpString((int) srcIP) + ", ");
        //buffer.append("dstIP=" + dstIP + ", ");
        buffer.append("dstIP=" + HexHelper.intToIpString((int) dstIP) + ", ");
        buffer.append("srcPort=" + srcPort + ", ");
        buffer.append("dstPort=" + dstPort + ", ");
        buffer.append("protocol=" + protocol + ", ");
        buffer.append("serOrCli=" + serOrCli + ", ");
        buffer.append("sizeOf3Pkt=" + sizeOf3Pkt);
        buffer.append(']');

        return buffer.toString();
    }
}