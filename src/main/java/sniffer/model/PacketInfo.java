package sniffer.model;

import javafx.beans.property.SimpleStringProperty;
import sniffer.model.headers.EthernetHeader;
import sniffer.model.headers.IpHeader;
import sniffer.model.headers.TcpHeader;
import sniffer.util.PacketDetailsBuilder;

public class PacketInfo {

    private final SimpleStringProperty sourceIP = new SimpleStringProperty("");
    private final SimpleStringProperty destinationIP = new SimpleStringProperty("");
    private final SimpleStringProperty protocol = new SimpleStringProperty("");
    private final SimpleStringProperty length = new SimpleStringProperty("");

    private String packetDetails;

    private EthernetHeader ethernetHeader;
    private IpHeader ipHeader;
    private TcpHeader tcpHeader;

    private String httpPayload;

    public String getPacketDetails() {
        if (packetDetails == null) {
            packetDetails = PacketDetailsBuilder.getPacketDetailsString(this);
        }
        return packetDetails;
    }

    public String getSourceIP() {
        return sourceIP.get();
    }

    public SimpleStringProperty sourceIPProperty() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP.set(sourceIP);
    }

    public String getDestinationIP() {
        return destinationIP.get();
    }

    public SimpleStringProperty destinationIPProperty() {
        return destinationIP;
    }

    public void setDestinationIP(String destinationIP) {
        this.destinationIP.set(destinationIP);
    }

    public String getProtocol() {
        return protocol.get();
    }

    public SimpleStringProperty protocolProperty() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol.set(protocol);
    }

    public String getLength() {
        return length.get();
    }

    public SimpleStringProperty lengthProperty() {
        return length;
    }

    public void setLength(String length) {
        this.length.set(length);
    }

    public EthernetHeader getEthernetHeader() {
        return ethernetHeader;
    }

    public void setEthernetHeader(EthernetHeader ethernetHeader) {
        this.ethernetHeader = ethernetHeader;
    }

    public IpHeader getIpHeader() {
        return ipHeader;
    }

    public void setIpHeader(IpHeader ipHeader) {
        this.ipHeader = ipHeader;
    }

    public TcpHeader getTcpHeader() {
        return tcpHeader;
    }

    public void setTcpHeader(TcpHeader tcpHeader) {
        this.tcpHeader = tcpHeader;
    }

    public String getHttpPayload() {
        return httpPayload;
    }

    public void setHttpPayload(String httpPayload) {
        this.httpPayload = httpPayload;
    }
}
