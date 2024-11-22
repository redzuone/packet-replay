import sys
import scapy.all as scapy
import time
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow, QApplication, QPushButton, QVBoxLayout,
    QLabel, QFileDialog, QWidget, QDoubleSpinBox, QCheckBox
)

SOURCE_IP_ADDRESS = '192.168.0.2'
DESTINATION_IP_ADDRESS = '127.0.0.1'
DESTINATION_PORT = 3000

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.controller = None
        self.init_ui()
        self._connect_signals()

    def init_ui(self) -> None:
        self.setWindowTitle('Packet Replay')
        # Layout and widgets
        central_widget = QWidget()
        self.main_layout = QVBoxLayout()
        central_widget.setLayout(self.main_layout)
        self.setCentralWidget(central_widget)

        self.delay_lineedit = QDoubleSpinBox()
        self.main_layout.addWidget(self.delay_lineedit)
        self.delay_lineedit.setDecimals(3)
        self.delay_lineedit.setRange(0, 1000)
        self.delay_lineedit.setSingleStep(0.012)
        self.delay_lineedit.setValue(0.01)

        self.status_label = QLabel('Status: No file loaded')
        self.main_layout.addWidget(self.status_label)
        self.status_label.setWordWrap(True)
        self.load_button = QPushButton('Load File')
        self.main_layout.addWidget(self.load_button)
        self.start_button = QPushButton('Start Replay')
        self.main_layout.addWidget(self.start_button)
        self.stop_button = QPushButton('Stop Replay')
        self.main_layout.addWidget(self.stop_button)
        self.run_by_step_checkbox = QCheckBox("Run by step")
        self.main_layout.addWidget(self.run_by_step_checkbox)
        self.step_btn = QPushButton('Step')
        self.main_layout.addWidget(self.step_btn)

    def _connect_signals(self) -> None:
        self.step_btn.clicked.connect(self.step)
        self.run_by_step_checkbox.stateChanged.connect(self.run_by_step)
        self.load_button.clicked.connect(self.on_load_file)
        self.start_button.clicked.connect(self.on_start_replay)
        self.stop_button.clicked.connect(self.on_stop_replay)

    def run_by_step(self, state) -> None:
        state = Qt.CheckState(state) == Qt.CheckState.Checked
        if state:
            self.controller.packet_handler.is_run_by_step = True
        else:
            self.controller.packet_handler.is_run_by_step = False
    
    def step(self) -> None:
        self.controller.packet_handler.is_paused = False

    def set_controller(self, controller: 'MainController') -> None:
        self.controller = controller

    def on_load_file(self) -> None:
        if self.controller:
            self.controller.load_file()

    def on_start_replay(self) -> None:
        if self.controller:
            self.controller.start_replay()

    def on_stop_replay(self) -> None:
        if self.controller:
            self.controller.stop_replay()

    def update_status(self, message) -> None:
        self.status_label.setText(f'Status: {message}')


class PacketHandler(QThread):
    sig_status = pyqtSignal(str)
    sig_finished = pyqtSignal()
    
    def __init__(self, src_ip, dst_ip, dst_port) -> None:
        super().__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.packet_file = None
        self.is_replaying = False
        self.sent_count = 0
        self.t_delay = 0.012
        self.new_packets = None
        self.is_paused = False
        self.is_run_by_step = False

    def load_file(self, pcap_file) -> None:
        self.packet_file = pcap_file
        print('Loading file...')
        self.packets = scapy.rdpcap(pcap_file)
        print('File loaded')

    def run(self) -> None:
        if not self.packet_file:
            print('No packet file loaded.')
            return
        
        print('Preparing packets...')
        self.sig_status.emit('Preparing packets...')
        if self.new_packets is None:
            self.new_packets = []

            # Extract packets and prepare them for replay
            for packet in self.packets:
                if scapy.IP in packet and scapy.UDP in packet and self.is_replaying:
                    try:
                        if packet[scapy.IP].src == self.src_ip:
                            payload = bytes(packet[scapy.UDP].payload)
                            p = scapy.IP(src=self.src_ip, dst=self.dst_ip) / scapy.UDP(sport=packet[scapy.UDP].sport, dport=self.dst_port) / payload
                            self.new_packets.append(p)
                    except Exception as e:
                        print(f'Error processing packet: {e}')
            print('Packets ready, replaying')
        self.sig_status.emit('Packets loaded, replaying')
        # Replay packets
        start_time = time.perf_counter()
        for p in self.new_packets:
            if not self.is_replaying:
                print('Replay stopped.')
                self.sig_status.emit('Replay stopped.')
                break
            if self.is_run_by_step:
                self.is_paused = True
            while self.is_replaying and self.is_paused and self.is_run_by_step:
                time.sleep(0.1)
            time.sleep(self.t_delay)
            scapy.send(p, iface='\\Device\\NPF_Loopback', verbose=False)
        self.sig_status.emit('Done!')
        print(f'Elapsed time: {time.perf_counter() - start_time}')
        self.finished.emit()

    def stop_replay(self) -> None:
        self.is_replaying = False


class MainController:
    def __init__(self, mainwindow: MainWindow) -> None:
        self.packet_handler = PacketHandler(src_ip=SOURCE_IP_ADDRESS, dst_ip=DESTINATION_IP_ADDRESS, dst_port=DESTINATION_PORT)
        self.mw = mainwindow
        self.mw.set_controller(self)
        self.packet_handler.sig_status.connect(self.mw.update_status)
        self.mw.delay_lineedit.valueChanged.connect(self.set_delay)

    def set_delay(self, value) -> None:
        self.packet_handler.t_delay = value

    def load_file(self) -> None:
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(None, 'Open PCAP File', '', 'PCAP Files (*.pcapng *.pcap)')
        if file_path:
            self.packet_handler.load_file(file_path)
            self.mw.update_status(f'File loaded: {file_path}')

    def start_replay(self) -> None:
        if not self.packet_handler.packet_file:
            self.mw.update_status('No file loaded.')
            return
        self.packet_handler.is_replaying = True
        self.packet_handler.start()

    def stop_replay(self) -> None:
        self.packet_handler.stop_replay()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    controller = MainController(window)
    window.show()
    sys.exit(app.exec())
