package sniffer.controller;

import javafx.collections.FXCollections;
import javafx.event.Event;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TableView;
import sniffer.model.PacketInfo;
import sniffer.pcap.PacketCaptureService;
import sniffer.util.Observer;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
//        Platform.runLater(() -> tableView.setItems(FXCollections.observableArrayList(pCapService.getNetworks().values())));
    }

    @FXML
    public void startClicked(Event e) {
        System.out.println("Start clicked");
        executorService = Executors.newSingleThreadExecutor();
        executorService.execute(pCapService::capture);
        startBtn.setDisable(true);
        stopBtn.setDisable(false);
    }

    @FXML
    public void stopClicked(Event e) {
        System.out.println("Stop clicked");
        executorService.shutdown();
        startBtn.setDisable(false);
        stopBtn.setDisable(true);
    }

    @Override
    public void updateView() {
        tableView.setItems(FXCollections.observableArrayList(pCapService.getNetworks().values()));
    }
}
