package sniffer.model.headers;

import lombok.Builder;
import lombok.Data;

import java.nio.ByteBuffer;
import java.util.Arrays;

@Data
@Builder
public class IpHeader {

    private byte ipVersion;             //4 bits
    private byte ipHeaderLength;        //4 bits - represents number of 32-bit words in the header
    private byte typeOfService;         //8 bits
    private short totalLength;          //16 bits
    private short identification;       //16 bits
    private boolean reservedBit;        //1 bit
    private boolean dontFragment;       //1 bit
    private boolean moreFragment;       //1 bit
    private short fragmentOffset;       //13 bits
    private int ttl;                    //8 bits
    private IpProtocolType protocol;    //8 bits
    private short checksum;             //16 bits
    private byte[] sourceAddress;       //32 bits
    private byte[] destinationAddress;  //32 bits

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
                .fragmentOffset((short) (ByteBuffer.wrap(Arrays.copyOfRange(bytes, 6, 8)).getShort() & 0x1FFF))
                .ttl(Byte.toUnsignedInt(bytes[8]))
                .protocol(IpProtocolType.getType(bytes[9]))
                .checksum(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 10, 12)).getShort())
                .sourceAddress(Arrays.copyOfRange(bytes, 12, 16))
                .destinationAddress(Arrays.copyOfRange(bytes, 16, 20))
                .build();
    }

}
