package sniffer.util;

import sniffer.model.PacketInfo;
import sniffer.model.headers.EthernetHeader;
import sniffer.model.headers.IpHeader;
import sniffer.model.headers.TcpHeader;

public class PacketDetailsBuilder {

    public static String getPacketDetailsString(PacketInfo packetInfo) {
        EthernetHeader ethernetHeader = packetInfo.getEthernetHeader();
        IpHeader ipHeader = packetInfo.getIpHeader();
        TcpHeader tcpHeader = packetInfo.getTcpHeader();

        // Formatted values for Ethernet header
        String destinationMAC = ByteUtils.byteArrayToHexString(ethernetHeader.getDest(), ":");
        String sourceMAC = ByteUtils.byteArrayToHexString(ethernetHeader.getSrc(), ":");
        String typeHex = NumberUtils.numberToHexString(ethernetHeader.getType().getValue(), 4);

        // Formatted values for IP header
        String versionBinary = NumberUtils.numberToBinaryString(ipHeader.getIpVersion(), 4);
        String ipHeaderLenBinary = NumberUtils.numberToBinaryString(ipHeader.getIpHeaderLength(), 4);
        String differentiatedServicesHex = NumberUtils.numberToHexString(ipHeader.getTypeOfService(), 2);
        String idHex = NumberUtils.numberToHexString(Short.toUnsignedInt(ipHeader.getIdentification()), 4);
        String ipChecksumHex = NumberUtils.numberToHexString(Short.toUnsignedInt(ipHeader.getChecksum()), 4);

        // Formatted values for TCP header
        String tcpHeaderLenBinary = NumberUtils.numberToBinaryString(tcpHeader.getDataOffset(), 4);
        String reservedBinary = NumberUtils.numberToBinaryString(tcpHeader.getReserved(), 3);
        String tcpChecksumHex = NumberUtils.numberToHexString(Short.toUnsignedInt(tcpHeader.getChecksum()), 4);

        StringBuilder stringBuilder = new StringBuilder()
                .append("Ethernet Header\n")
                .append(String.format("\tDestination: %s\n", destinationMAC))
                .append(String.format("\tSource: %s\n", sourceMAC))
                .append(String.format("\tType: %s (%s)\n", ethernetHeader.getType().toString(), typeHex))
                .append("IP Header\n")
                .append(String.format("\t%s .... = Version: %d\n", versionBinary, ipHeader.getIpVersion()))
                .append(String.format("\t.... %s = Header Length: %d bytes (%d)\n", ipHeaderLenBinary, ipHeader.getIpHeaderLength() * 4, ipHeader.getIpHeaderLength()))
                .append(String.format("\tDifferentiated Services Field: %s\n", differentiatedServicesHex))
                .append(String.format("\tTotal Length: %d\n", ipHeader.getTotalLength()))
                .append(String.format("\tIdentification: %s\n", idHex))
                .append(String.format("\t%s... = Reserved Bit\n", ipHeader.isReservedBit() ? "1" : "0"))
                .append(String.format("\t.%s.. = Don't Fragment\n", ipHeader.isDontFragment() ? "1" : "0"))
                .append(String.format("\t..%s. = More Fragments\n", ipHeader.isMoreFragment() ? "1" : "0"))
                .append(String.format("\tFragment offset: %s\n", ipHeader.getFragmentOffset()))
                .append(String.format("\tTime To Live: %s\n", ipHeader.getTtl()))
                .append(String.format("\tProtocol: %s (%d)\n", ipHeader.getProtocol().toString(), ipHeader.getProtocol().getValue()))
                .append(String.format("\tHeader Checksum: %s\n", ipChecksumHex))
                .append(String.format("\tSource Address: %s\n", packetInfo.getSourceIP()))
                .append(String.format("\tDestination Address: %s\n", packetInfo.getDestinationIP()))
                .append("TCP Header\n")
                .append(String.format("\tSource Port: %d\n", tcpHeader.getSourcePort()))
                .append(String.format("\tDestination Port: %d\n", tcpHeader.getDestinationPort()))
                .append(String.format("\tSequence Number: %d\n", tcpHeader.getSequence()))
                .append(String.format("\tAcknowledgement Number: %d\n", tcpHeader.getAcknowledge()))
                .append(String.format("\t.... %s = Header Length: %d bytes (%d)\n", tcpHeaderLenBinary, tcpHeader.getDataOffset() * 4, tcpHeader.getDataOffset()))
                .append(String.format("\tFlags:\n"))
                .append(String.format("\t\t%s. .... .... = Reserved\n", reservedBinary))
                .append(String.format("\t\t...%s .... .... = Nonce\n", tcpHeader.isNonce() ? "1" : "0"))
                .append(String.format("\t\t.... %s... .... = Congestion Window Reduced\n", tcpHeader.isCwr() ? "1" : "0"))
                .append(String.format("\t\t.... .%s.. .... = ECN-Echo\n", tcpHeader.isEcn() ? "1" : "0"))
                .append(String.format("\t\t.... ..%s. .... = Urgent\n", tcpHeader.isUrg() ? "1" : "0"))
                .append(String.format("\t\t.... ...%s .... = Acknowledgement\n", tcpHeader.isAck() ? "1" : "0"))
                .append(String.format("\t\t.... .... %s... = Push\n", tcpHeader.isPsh() ? "1" : "0"))
                .append(String.format("\t\t.... .... .%s.. = Reset\n", tcpHeader.isRst() ? "1" : "0"))
                .append(String.format("\t\t.... .... ..%s. = Syn\n", tcpHeader.isSyn() ? "1" : "0"))
                .append(String.format("\t\t.... .... ...%s = Fin\n", tcpHeader.isFin() ? "1" : "0"))
                .append(String.format("\tWindow: %d\n", tcpHeader.getWindow()))
                .append(String.format("\tChecksum: %s\n", tcpChecksumHex))
                .append(String.format("\tUrgent Pointer: %d\n", tcpHeader.getUrgentPointer()))
                .append((packetInfo.getHttpPayload()) != null ? String.format("HTTP payload:\n %s\n", packetInfo.getHttpPayload()) : "");

        return stringBuilder.toString();
    }
}
