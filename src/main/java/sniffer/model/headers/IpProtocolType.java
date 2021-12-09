package sniffer.model.headers;

import lombok.Getter;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public enum IpProtocolType {

    TCP((byte) 0x06),
    UDP((byte) 0x11);

    private static final Map<Byte, IpProtocolType> LOOKUP_MAP;

    static {
        LOOKUP_MAP = Arrays.stream(values()).collect(Collectors.toMap(val -> val.value, val -> val));
    }

    @Getter
    private final byte value;

    IpProtocolType(byte value) {
        this.value = value;
    }

    public static IpProtocolType getType(byte value) {
        return LOOKUP_MAP.get(value);
    }
}