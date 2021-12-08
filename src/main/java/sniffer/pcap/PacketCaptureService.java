package sniffer.pcap;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import sniffer.model.PacketInfo;
import sniffer.parser.PacketParser;
import sniffer.util.Observable;
import sniffer.util.Observer;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class PacketCaptureService implements Observable {

    private static final int SNAP_LEN = 65536;
    private static final int TIMEOUT = 10;

    private PcapHandle handle;

    @Getter
    private final List<Observer> observers = new ArrayList<>();

    @Getter
    private final List<PacketInfo> packets = new ArrayList<>();

    public List<PcapNetworkInterface> findDevices() {
        setNpcapSystemProperty();

        List<PcapNetworkInterface> devices = null;
        try {
            devices = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            log.error("Failed call to Pcaps.findAllDevs()");
        }
        return devices;
    }

    public void initHandle(PcapNetworkInterface networkInterface) {
        try {
            handle = networkInterface.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT);
        } catch (PcapNativeException e) {
            log.error("Error on initHandle()", e);
        }
    }

    public void capture() {
        try {
            handle.loop(0, (Packet packet) -> {
                PacketInfo packetInfo = PacketParser.parsePacket(packet.getHeader().getRawData(), packet.getPayload().getRawData());
                if (packetInfo != null) {
                    packets.add(packetInfo);
                    observers.forEach(Observer::updateView);
                }
            });
        } catch (InterruptedException e) {
            log.info("The loop terminated due to a call to breakLoop()");
        } catch (PcapNativeException | NotOpenException e) {
            log.error("Error on capture()", e);
        }
    }

    public void stopCapture() {
        try {
            handle.breakLoop();
        } catch (NotOpenException e) {
            log.error("Error on stopCapture()");
        }
    }

    public void resetHandle() {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
        packets.clear();
    }

    private void setNpcapSystemProperty() {
        String prop = System.getProperty("jna.library.path");
        if (prop == null || prop.isEmpty()) {
            prop = "C:/Windows/System32/Npcap";
        } else {
            prop += ";C:/Windows/System32/Npcap";
        }
        System.setProperty("jna.library.path", prop);
    }
}
