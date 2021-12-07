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
import java.util.Optional;

@Slf4j
public class PacketCaptureService implements Observable {

    private static final int SNAP_LEN = 65536;
    private static final int TIMEOUT = 10;

    private PcapHandle handle;

    @Getter
    private final List<Observer> observers = new ArrayList<>();

    @Getter
    private final List<PacketInfo> packets = new ArrayList<>();

    public void initHandle() {
        try {
            Optional<PcapNetworkInterface> deviceOpt = findDevices().stream().filter(d -> d.getDescription().contains("Ethernet Adapter")).findFirst();
            if (!deviceOpt.isPresent()) {
                log.error("Ethernet Adapter not found");
                return;
            }
//            PcapNetworkInterface networkInterface = Pcaps.getDevByName(deviceOpt.get().getName());
            PcapNetworkInterface networkInterface = Pcaps.getDevByName("\\Device\\NPF_{3BBE4475-C0E3-4EBA-8709-B146A9C5F423}"); //W(hy)TF
            handle = networkInterface.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT);
//            BpfProgram bpfProgram = handle.compileFilter(BFP_EXPRESSION, BpfProgram.BpfCompileMode.NONOPTIMIZE, PcapHandle.PCAP_NETMASK_UNKNOWN);
//            handle.setFilter(bpfProgram);
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

    private List<PcapNetworkInterface> findDevices() {
        List<PcapNetworkInterface> devices = null;
        try {
            // TODO remove after restart to see if it gets picked up from PATH
            String prop = System.getProperty("jna.library.path");
            if (prop == null || prop.isEmpty()) {
                prop = "C:/Windows/System32/Npcap";
            } else {
                prop += ";C:/Windows/System32/Npcap";
            }
            System.setProperty("jna.library.path", prop);
            // end TODO

            devices = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            log.error("Failed call to Pcaps.findAllDevs()");
        }
        return devices;
    }

}
