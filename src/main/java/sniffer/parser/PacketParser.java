package sniffer.parser;

import sniffer.model.PacketInfo;
import sniffer.model.headers.EthernetHeader;
import sniffer.model.headers.EthernetHeaderType;
import sniffer.model.headers.IpHeader;
import sniffer.model.headers.IpProtocolType;
import sniffer.util.ByteUtils;

public class PacketParser {

    public static PacketInfo parsePacket(byte[] header, byte[] payload) {
        PacketInfo packetInfo = new PacketInfo();

        EthernetHeader ethernetHeader = EthernetHeader.parse(header);
        if (!EthernetHeaderType.IPV4.equals(ethernetHeader.getType())) {
            return null;
        }

        IpHeader ipHeader = IpHeader.parse(payload);
        if (!IpProtocolType.TCP.equals(ipHeader.getProtocol())) {
            return null;
        }

        //TODO start parsing TCP header from payload[ipHeader.ipHeaderLength:]

        packetInfo.setSourceIP(ByteUtils.byteArrayToIPString(ipHeader.getSourceAddress()));
        packetInfo.setDestinationIP(ByteUtils.byteArrayToIPString(ipHeader.getDestinationAddress()));

        packetInfo.setEthernetHeader(ethernetHeader);
        packetInfo.setIpHeader(ipHeader);

        return packetInfo;
    }
}
