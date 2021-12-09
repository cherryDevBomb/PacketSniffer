package sniffer.model.headers;

import lombok.Builder;
import lombok.Data;

import java.nio.ByteBuffer;
import java.util.Arrays;

@Data
@Builder
public class TcpHeader {

    private int sourcePort;         //16 bits
    private int destinationPort;    //16 bits
    private int sequence;           //32 bits
    private int acknowledge;        //32 bits
    private byte dataOffset;        //4 bits - represents number of 32-bit words in the header
    private byte reserved;          //3 bits
    private boolean nonce;          //1 bit
    private boolean cwr;            //1 bit
    private boolean ecn;            //1 bit
    private boolean urg;            //1 bit
    private boolean ack;            //1 bit
    private boolean psh;            //1 bit
    private boolean rst;            //1 bit
    private boolean syn;            //1 bit
    private boolean fin;            //1 bit
    private int window;             //8 bits
    private short checksum;         //8 bits
    private short urgentPointer;    //8 bits

    public static TcpHeader parse(byte[] bytes) {
        return TcpHeader.builder()
                .sourcePort(Short.toUnsignedInt(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 2)).getShort()))
                .destinationPort(Short.toUnsignedInt(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 2, 4)).getShort()))
                .sequence(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 4, 8)).getInt())
                .acknowledge(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 12)).getInt())
                .dataOffset((byte) (bytes[12] >> 4 & 0x0F))
                .reserved((byte) (bytes[12] >> 1 & 0b00000111))
                .nonce((bytes[12] & 1) == 1)
                .cwr((bytes[13] & 1) == 1)
                .ecn((bytes[13] & 1) == 1)
                .urg((bytes[13] & 1) == 1)
                .ack((bytes[13] & 1) == 1)
                .psh((bytes[13] & 1) == 1)
                .rst((bytes[13] & 1) == 1)
                .syn((bytes[13] & 1) == 1)
                .fin((bytes[13] & 1) == 1)
                .window(Byte.toUnsignedInt(bytes[14]))
                .checksum((bytes[15]))
                .urgentPointer((bytes[16]))
                .build();
    }
}
