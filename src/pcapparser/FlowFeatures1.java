package pcapparser;

/**
 * Flow features
 *
 * @author lipeng
 * @version 0.2
 */
public class FlowFeatures1 {
    // 9个流特征：端口号、协议、TCP flags、数据包的长度、目的IP地址、载荷大小、
    //          前3个数据包的大小、数据包到达间隔时间、流的存在时间

    private int port;

    /**
     * 协议类型（1 字节）
     */
    private int protocol;

    /**
     * 标识TCP不同的控制消息(1 字节)
     */
    private boolean URG;
    private boolean ACK;
    private boolean PSH;
    private boolean RST;
    private boolean SYN;
    private boolean FIN;
    private int flags;

    /**
     * 总长度（2 字节）
     */
    private int length;

    /**
     * 目的 IP（4 字节）
     */
    private long dstIP;

    private int payloadLen;

    private FlowClass flowClass;

    public FlowFeatures1(int port, int protocol, boolean URG, boolean ACK, boolean PSH, boolean RST,
                        boolean SYN, boolean FIN, int flags, int length, long dstIP, int payload) {
        this.port = port;
        this.protocol = protocol;
        this.URG = URG;
        this.ACK = ACK;
        this.PSH = PSH;
        this.RST = RST;
        this.SYN = SYN;
        this.FIN = FIN;
        this.flags = flags;
        this.length = length;
        this.dstIP = dstIP;
        this.payloadLen = payload;
    }

    public int getProtocol() {
        return protocol;
    }

    public FlowClass getFlowClass() {
        return flowClass;
    }

    public void setFlowClass(FlowClass flowClass) {
        this.flowClass = flowClass;
    }

    public String toCSV() {
        StringBuffer buffer = new StringBuffer();
        buffer.append(port).append(",")
                .append(protocol).append(",")
                .append(flags).append(",")
                .append(length).append(",")
                .append(dstIP).append(",")
                .append(payloadLen).append(",")
                .append(flowClass);

        return buffer.toString();
    }

    @Override
    public String toString() {
        StringBuffer buffer = new StringBuffer();
        buffer.append('[');
        buffer.append("pcapparser.FlowFeatures");
        buffer.append(": ");
        buffer.append("port=" + port + ", ");
        buffer.append("protocol=" + protocol + ", ");
        if(URG) buffer.append("urg, ");
        if(ACK) buffer.append("ack, ");
        if(PSH) buffer.append("psh, ");
        if(RST) buffer.append("rst, ");
        if(SYN) buffer.append("syn, ");
        if(FIN) buffer.append("fin, ");
        buffer.append("flags=" + flags + ", ");
        buffer.append("length=" + length + ", ");
        buffer.append("dstIP=" + dstIP + ", ");
        buffer.append("payload=" + payloadLen);
        buffer.append(']');

        return buffer.toString();
    }
}
