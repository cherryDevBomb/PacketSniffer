package sniffer.model;

import javafx.beans.property.SimpleStringProperty;
import lombok.Getter;
import lombok.Setter;
import sniffer.model.headers.EthernetHeader;
import sniffer.model.headers.IpHeader;

public class PacketInfo {

    private final SimpleStringProperty sourceIP = new SimpleStringProperty("");
    private final SimpleStringProperty destinationIP = new SimpleStringProperty("");

    @Getter
    @Setter
    private EthernetHeader ethernetHeader;
    @Getter
    @Setter
    private IpHeader ipHeader;

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
}
