package sniffer.model.headers;

import lombok.Builder;
import lombok.Data;

import java.nio.ByteBuffer;
import java.util.Arrays;

@Data
@Builder
public class IpHeader {

    private byte ipVersion;
    private byte ipHeaderLength; //value represents number of 32-bit words => multiply with 4 to get length in bytes
    private byte typeOfService;
    private short totalLength;
    private short identification;
    private boolean reservedBit;
    private boolean dontFragment;
    private boolean moreFragment;
    private byte fragmentOffset;
    private byte ttl;
    private IpProtocolType protocol;
    private short checksum;
    private byte[] sourceAddress;
    private byte[] destinationAddress;

    public static IpHeader parse(byte[] bytes) {
        return IpHeader.builder()
                .ipVersion((byte) (bytes[0] >> 4 & 0x0F))
                .ipHeaderLength((byte) (bytes[0] & 0x0F))
                .typeOfService(bytes[1])
                .totalLength(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 2, 4)).getShort())
                .identification(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 4, 6)).getShort())
                .reservedBit((bytes[6] >> 7 & 1) == 1)
                .dontFragment((bytes[6] >> 6 & 1) == 1)
                .moreFragment((bytes[6] >> 5 & 1) == 1)
                .fragmentOffset((byte) (bytes[7] & 0b00011111))
                .ttl(bytes[8])
                .protocol(IpProtocolType.getType(bytes[9]))
                .checksum(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 10, 12)).getShort())
                .sourceAddress(Arrays.copyOfRange(bytes, 12, 16))
                .destinationAddress(Arrays.copyOfRange(bytes, 16, 20))
                .build();
    }

}
