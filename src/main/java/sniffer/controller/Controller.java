package sniffer.controller;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.event.Event;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TableView;
import lombok.extern.slf4j.Slf4j;
import sniffer.model.PacketInfo;
import sniffer.pcap.PacketCaptureService;
import sniffer.util.Observer;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class Controller implements Observer {

    @FXML
    private TableView<PacketInfo> tableView;
    @FXML
    private Button startBtn;
    @FXML
    private Button stopBtn;

    private final PacketCaptureService pCapService = new PacketCaptureService();

    private ExecutorService executorService;

    @FXML
    private void initialize() {
        pCapService.registerObserver(this);
        pCapService.initHandle();
        Platform.runLater(() -> tableView.setItems(FXCollections.observableArrayList(pCapService.getPackets())));
    }

    @FXML
    public void startClicked(Event e) {
        log.debug("Start clicked");
        executorService = Executors.newSingleThreadExecutor(); //TODO consider moving initialization to declaration and making executor final
        executorService.execute(pCapService::capture);
        startBtn.setDisable(true);
        stopBtn.setDisable(false);
    }

    @FXML
    public void stopClicked(Event e) {
        log.debug("Stop clicked");
        executorService.shutdownNow();
        pCapService.stopCapture();
        startBtn.setDisable(false);
        stopBtn.setDisable(true);
    }

    @Override
    public void updateView() {
        tableView.setItems(FXCollections.observableArrayList(pCapService.getPackets()));
    }
}
