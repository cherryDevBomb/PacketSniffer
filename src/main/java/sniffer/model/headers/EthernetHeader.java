package sniffer.model.headers;

import lombok.Builder;
import lombok.Data;

import java.nio.ByteBuffer;
import java.util.Arrays;

@Data
@Builder
public class EthernetHeader {

    private byte[] dest;                //48 bits
    private byte[] src;                 //48 bits
    private EthernetHeaderType type;    //16 bits

    public static EthernetHeader parse(byte[] bytes) {
        return EthernetHeader.builder()
                .dest(Arrays.copyOfRange(bytes, 0, 6))
                .src(Arrays.copyOfRange(bytes, 6, 12))
                .type(EthernetHeaderType.getType(ByteBuffer.wrap(Arrays.copyOfRange(bytes, 12, 14)).getShort()))
                .build();
    }
}
