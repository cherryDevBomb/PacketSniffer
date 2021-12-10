package sniffer.parser;

import sniffer.model.PacketInfo;
import sniffer.model.headers.*;
import sniffer.util.ByteUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

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

        // check for http content
        int offset = (ipHeader.getIpHeaderLength() * 4) + (tcpHeader.getDataOffset() * 4);
        Optional<String> httpContent = getHttpContent(Arrays.copyOfRange(payload, offset, payload.length));
        httpContent.ifPresent(packetInfo::setHttpPayload);

        packetInfo.setEthernetHeader(ethernetHeader);
        packetInfo.setIpHeader(ipHeader);
        packetInfo.setTcpHeader(tcpHeader);

        packetInfo.setSourceIP(ByteUtils.byteArrayToIPString(ipHeader.getSourceAddress()));
        packetInfo.setDestinationIP(ByteUtils.byteArrayToIPString(ipHeader.getDestinationAddress()));
        packetInfo.setProtocol(httpContent.isPresent() ? "HTTP" : ipHeader.getProtocol().toString());
        packetInfo.setLength(String.valueOf(header.length + ipHeader.getTotalLength()));

        return packetInfo;
    }

    private static Optional<String> getHttpContent(byte[] content) {
        if (content.length > 0) {
            String data = new String(content, StandardCharsets.UTF_8);
            if (data.contains("HTTP")) {
                int contentEndIndex = data.indexOf("\r\n\r\n");
                if (contentEndIndex != -1) {
                    return Optional.of(data.substring(0, contentEndIndex));
                }
            }
        }
        return Optional.empty();
    }
}
