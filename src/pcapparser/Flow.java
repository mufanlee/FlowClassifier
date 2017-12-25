package pcapparser;

import util.HexHelper;

public class Flow {
    /**
     * IP 地址（4 字节）
     */
    private int srcIP;
    private int dstIP;

    /**
     * 协议类型（1 字节）
     */
    private int protocol;

    /**
     * 端口号（2 字节）
     */
    private int srcPort;
    private int dstPort;

    public Flow(int srcIP, int dstIP, int protocol, int srcPort, int dstPort) {
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.protocol = protocol;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
    }

    public Flow(String srcIP, String dstIP, String protocol, String srcPort, String dstPort) {
        this.srcIP = HexHelper.ipStringToInt(srcIP);
        this.dstIP = HexHelper.ipStringToInt(dstIP);
        this.protocol = Integer.parseInt(protocol);
        this.srcPort = Integer.parseInt(srcPort);
        this.dstPort = Integer.parseInt(dstPort);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Flow flow = (Flow) o;

        if (srcIP != flow.srcIP) return false;
        if (dstIP != flow.dstIP) return false;
        if (protocol != flow.protocol) return false;
        if (srcPort != flow.srcPort) return false;
        return dstPort == flow.dstPort;
    }

    @Override
    public int hashCode() {
        int result = srcIP;
        result = 31 * result + dstIP;
        result = 31 * result + protocol;
        result = 31 * result + srcPort;
        result = 31 * result + dstPort;
        return result;
    }

    @Override
    public String toString() {
        StringBuffer buffer = new StringBuffer();
        buffer.append('[');
        buffer.append("pcapparser.Flow");
        buffer.append(": ");
        //buffer.append("srcIP=" + srcIP + ", ");
        buffer.append("srcIP=" + HexHelper.intToIpString((int) srcIP) + ", ");
        //buffer.append("dstIP=" + dstIP + ", ");
        buffer.append("dstIP=" + HexHelper.intToIpString((int) dstIP) + ", ");
        buffer.append("srcPort=" + srcPort + ", ");
        buffer.append("dstPort=" + dstPort + ", ");
        buffer.append("protocol=" + protocol);
        buffer.append(']');

        return buffer.toString();
    }
}
