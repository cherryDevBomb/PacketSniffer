package sniffer.util;

import sniffer.model.PacketInfo;
import sniffer.model.headers.EthernetHeader;
import sniffer.model.headers.IpHeader;

public class PacketDetailsBuilder {

    public static String getPacketDetailsString(PacketInfo packetInfo) {
        EthernetHeader ethernetHeader = packetInfo.getEthernetHeader();
        IpHeader ipHeader = packetInfo.getIpHeader();

        String destinationMAC = ByteUtils.byteArrayToHexString(ethernetHeader.getDest(), ":");
        String sourceMAC = ByteUtils.byteArrayToHexString(ethernetHeader.getSrc(), ":");
        String typeHex = NumberUtils.numberToHexString(ethernetHeader.getType().getValue(), 4);

        String versionBinary = NumberUtils.numberToBinaryString(ipHeader.getIpVersion(), 4);
        String headerLenBinary = NumberUtils.numberToBinaryString(ipHeader.getIpHeaderLength(), 4);
        String differentiatedServicesHex = NumberUtils.numberToHexString(ipHeader.getTypeOfService(), 2);
        String idHex = NumberUtils.numberToHexString(ipHeader.getIdentification(), 4);
        String headerChecksumHex = NumberUtils.numberToHexString(ipHeader.getIdentification(), 4);

        StringBuilder stringBuilder = new StringBuilder()
                .append("Ethernet Header\n")
                .append(String.format("\tDestination: %s\n", destinationMAC))
                .append(String.format("\tSource: %s\n", sourceMAC))
                .append(String.format("\tType: %s (%s)\n", ethernetHeader.getType().toString(), typeHex))
                .append("IP Header\n")
                .append(String.format("\t%s .... = Version: %d\n", versionBinary, ipHeader.getIpVersion()))
                .append(String.format("\t.... %s = Header Length: %d bytes (%d)\n", headerLenBinary, ipHeader.getIpHeaderLength() * 4, ipHeader.getIpHeaderLength()))
                .append(String.format("\tDifferentiated Services Field: %s\n", differentiatedServicesHex))
                .append(String.format("\tTotal Length: %d\n", ipHeader.getTotalLength()))
                .append(String.format("\tIdentification: %s\n", idHex))
                .append(String.format("\t%s... = Reserved Bit\n", ipHeader.isReservedBit() ? "1" : "0"))
                .append(String.format("\t.%s.. = Don't Fragment\n", ipHeader.isDontFragment() ? "1" : "0"))
                .append(String.format("\t..%s. = More Fragments\n", ipHeader.isMoreFragment() ? "1" : "0"))
                .append(String.format("\tFragment offset: %s\n", ipHeader.getFragmentOffset()))
                .append(String.format("\tTime To Live: %s\n", ipHeader.getTtl()))
                .append(String.format("\tProtocol: %s (%d)\n", ipHeader.getProtocol().toString(), ipHeader.getProtocol().getValue()))
                .append(String.format("\tHeader Checksum: %s\n", headerChecksumHex))
                .append(String.format("\tSource Address: %s\n", packetInfo.getSourceIP()))
                .append(String.format("\tDestination Address: %s\n", packetInfo.getDestinationIP()));

        return stringBuilder.toString();
    }
}
