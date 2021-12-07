package sniffer.parser;

import sniffer.model.PacketInfo;
import sniffer.model.headers.EthernetHeader;
import sniffer.model.headers.EthernetHeaderType;

public class PacketParser {

    public static PacketInfo parsePacket(byte[] header, byte[] payload) {
        PacketInfo packetInfo = new PacketInfo();

        EthernetHeader ethernetHeader = EthernetHeader.parse(header);
        if (!EthernetHeaderType.IPV4.equals(ethernetHeader.getType())) {
            return null;
        }

        return packetInfo;
    }
}
