package sniffer.util;

public class NumberUtils {

    public static String numberToHexString(int value, int len) {
        String pattern = "%" + len + "s";
        String hexString = String.format(pattern, Integer.toHexString(value)).replace(' ', '0');
        return "0x" + hexString;
    }

    public static String numberToBinaryString(int value, int len) {
        String pattern = "%" + len + "s";
        return String.format(pattern, Integer.toBinaryString(value)).replace(' ', '0');
    }
}
