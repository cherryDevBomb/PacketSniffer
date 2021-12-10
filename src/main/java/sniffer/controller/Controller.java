package sniffer.controller;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.event.Event;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.text.Font;
import javafx.util.StringConverter;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapNetworkInterface;
import sniffer.model.PacketInfo;
import sniffer.pcap.PacketCaptureService;
import sniffer.util.Observer;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class Controller implements Observer {

    @FXML
    private ComboBox<PcapNetworkInterface> comboBox;
    @FXML
    private Button startBtn;
    @FXML
    private Button stopBtn;
    @FXML
    private TableView<PacketInfo> tableView;
    @FXML
    private TextArea packetDetailsArea;

    private final PacketCaptureService pCapService = new PacketCaptureService();

    private ExecutorService executorService;

    @FXML
    private void initialize() {
        pCapService.registerObserver(this);
        initComboBox();
        packetDetailsArea.setFont(Font.font("monospace"));
        Platform.runLater(() -> {
            tableView.setItems(FXCollections.observableArrayList(pCapService.getPackets()));
            tableView.getSelectionModel().selectedItemProperty().addListener((observableValue, oldSelection, newSelection) -> {
                if (newSelection != null) {
                    packetDetailsArea.setText(newSelection.getPacketDetails());
                }
            });
        });
    }

    @FXML
    public void startClicked(Event e) {
        log.debug("Start clicked");
        executorService = Executors.newSingleThreadExecutor();
        executorService.execute(pCapService::capture);
        startBtn.setDisable(true);
        stopBtn.setDisable(false);
        comboBox.setDisable(true);
    }

    @FXML
    public void stopClicked(Event e) {
        log.debug("Stop clicked");
        executorService.shutdownNow();
        pCapService.stopCapture();
        startBtn.setDisable(false);
        stopBtn.setDisable(true);
        comboBox.setDisable(false);
    }

    @Override
    public void updateView() {
        tableView.setItems(FXCollections.observableArrayList(pCapService.getPackets()));
    }

    private void initComboBox() {
        Platform.runLater(() -> comboBox.setItems(FXCollections.observableArrayList(pCapService.findDevices())));

        comboBox.setConverter(new StringConverter<PcapNetworkInterface>() {
            @Override
            public String toString(PcapNetworkInterface device) {
                return device == null ? null : String.format("%s - %s", device.getName(), device.getDescription());
            }

            @Override
            public PcapNetworkInterface fromString(String string) {
                return comboBox.getItems().stream()
                        .filter(i -> i.getName().equals(string.split(" - ")[0]))
                        .findAny()
                        .orElse(null);
            }
        });

        comboBox.setOnAction((event) -> {
            pCapService.resetHandle();
            updateView();
            PcapNetworkInterface selectedDevice = comboBox.getSelectionModel().getSelectedItem();
            pCapService.initHandle(selectedDevice);
            startBtn.setDisable(false);
        });
    }
}
