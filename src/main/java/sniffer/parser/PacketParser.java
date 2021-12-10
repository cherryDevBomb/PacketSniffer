package sniffer.parser;

import sniffer.model.PacketInfo;
import sniffer.model.headers.*;
import sniffer.util.ByteUtils;

import java.util.Arrays;

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

        // ipHeader length is measured in 32-bit words -> multiply by 4 to get length in bytes
        TcpHeader tcpHeader = TcpHeader.parse(Arrays.copyOfRange(payload, ipHeader.getIpHeaderLength() * 4, payload.length));

        packetInfo.setEthernetHeader(ethernetHeader);
        packetInfo.setIpHeader(ipHeader);
        packetInfo.setTcpHeader(tcpHeader);

        packetInfo.setSourceIP(ByteUtils.byteArrayToIPString(ipHeader.getSourceAddress()));
        packetInfo.setDestinationIP(ByteUtils.byteArrayToIPString(ipHeader.getDestinationAddress()));
        packetInfo.setProtocol(ipHeader.getProtocol().toString());
        packetInfo.setLength(String.valueOf(header.length + ipHeader.getTotalLength()));

        return packetInfo;
    }
}
