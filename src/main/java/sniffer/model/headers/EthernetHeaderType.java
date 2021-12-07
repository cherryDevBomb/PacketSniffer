package sniffer.model.headers;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public enum EthernetHeaderType {

    IPV4((short) 0x0800),
    IPV6((short) 0x86DD);

    private static final Map<Short, EthernetHeaderType> LOOKUP_MAP;

    static {
        LOOKUP_MAP = Arrays.stream(values()).collect(Collectors.toMap(val -> val.value, val -> val));
    }

    private final short value;

    EthernetHeaderType(short value) {
        this.value = value;
    }

    public static EthernetHeaderType getType(short value) {
        return LOOKUP_MAP.get(value);
    }
}
