package sniffer.util;

import java.util.stream.Collectors;

import com.google.common.primitives.Bytes;

public class ByteUtils {

    public static String byteArrayToHexString(byte[] bytes) {
        return byteArrayToHexString(bytes, "");
    }

    public static String byteArrayToHexString(byte[] bytes, String delimiter) {
        return Bytes.asList(bytes)
                .stream()
                .map(i -> String.format("%02x", i))
                .collect(Collectors.joining(delimiter));
    }

    public static boolean[] byteArrayToBooleanArray(byte[] bytes) {
        int lengthInBits = bytes.length * 8;
        boolean[] booleanArray = new boolean[lengthInBits];
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                booleanArray[i * 8 + j] = (bytes[i] & (1 << j)) != 0;
            }
        }
        return booleanArray;
    }
}
