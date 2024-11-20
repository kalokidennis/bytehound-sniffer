import sys
from PyQt5.QtWidgets import (
    QApplication, QLabel, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QToolBar, QAction, QFileDialog, QMainWindow,
    QMessageBox, QDialog, QLineEdit, QComboBox
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
from sniffer_backend import PacketSnifferThread  # Ensure this imports the updated backend
from analysis_module import PacketAnalysisWindow  # Import the new analysis window

FILTER_OPTIONS = [
    "All Traffic",
    "HTTP Traffic",
    "TCP Traffic",
    "UDP Traffic",
    "ICMP Traffic",
    "By IP Address"
]

class PacketSnifferUI(QMainWindow):  # Correct class name
    def __init__(self):
        super().__init__()
        self.sniffer_thread = None
        self.captured_packets = []  # This will hold the captured packets for analysis
        self.pending_packets = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('ByteHound 🐾')
        self.setWindowIcon(QIcon("/path/to/icon.png"))  # Replace with actual path to your ByteHound icon
        self.setGeometry(100, 100, 1000, 600)

        # Set background color to cream
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(255, 253, 208))
        self.setPalette(palette)

        # Title label
        title_label = QLabel('ByteHound 🐾')
        title_label.setFont(QFont('Arial', 24))
        title_label.setAlignment(Qt.AlignCenter)

        # Toolbar
        toolbar = QToolBar(self)
        self.addToolBar(toolbar)
        self.add_toolbar_actions(toolbar)

        # Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setStyleSheet("background-color: white; color: black;")
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels([
            'Source MAC', 'Destination MAC', 'Source IP', 'Destination IP',
            'Source Port', 'Destination Port', 'Protocol', 'Summary'
        ])
        self.packet_table.horizontalHeader().setStyleSheet(
            "QHeaderView::section { background-color: lightgrey; color: black; font-weight: bold; }"
        )
        self.packet_table.horizontalHeader().setStretchLastSection(True)

        # Start, Stop, and Clear buttons
        self.start_button = QPushButton('Start')
        self.stop_button = QPushButton('Stop')
        self.clear_button = QPushButton('Clear Data')
        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.clear_button.clicked.connect(self.clear_table)

        # Filter section
        self.filter_combobox = QComboBox(self)
        self.filter_combobox.addItems(FILTER_OPTIONS)
        self.filter_combobox.setCurrentIndex(0)  # Default to "All Traffic"

        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter custom filter (e.g., 'ip host 192.168.1.1')")

        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.clear_button)

        # Filter layout
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Select Filter:"))
        filter_layout.addWidget(self.filter_combobox)
        filter_layout.addWidget(QLabel("Custom Filter:"))
        filter_layout.addWidget(self.filter_input)

        # Main layout
        central_widget = QWidget()
        layout = QVBoxLayout(central_widget)
        layout.addWidget(title_label)
        layout.addLayout(filter_layout)
        layout.addWidget(self.packet_table)
        layout.addLayout(button_layout)
        self.setCentralWidget(central_widget)

        # Timer to batch update packets to the table
        self.update_timer = QTimer()
        self.update_timer.setInterval(1000)  # Update every 1 second
        self.update_timer.timeout.connect(self.flush_pending_packets)

    def add_toolbar_actions(self, toolbar):
        actions = [
            ('Open...', self.open_file_dialog),
            ('Go to Packet', self.go_to_packet),
            ('Packet List', self.view_packet_list),
            ('Start Capture', self.start_sniffing),
            ('Stop Capture', self.stop_sniffing),
            ('Wireless Settings', self.wireless_settings),
            ('Analyze', self.analyze_packets),  # Ensure this action is correctly tied to the method
        ]
        for action_name, action_method in actions:
            action = QAction(action_name, self)
            action.triggered.connect(action_method)
            toolbar.addAction(action)

    def start_sniffing(self):
        if self.sniffer_thread is None or not self.sniffer_thread.isRunning():
            self.sniffer_thread = PacketSnifferThread()
            self.sniffer_thread.packet_captured.connect(self.buffer_packet)
            
            selected_filter = self.filter_combobox.currentText()
            custom_filter = self.filter_input.text()
            filter_expression = self.get_filter_expression(selected_filter, custom_filter)

            self.sniffer_thread.set_filter(filter_expression)
            try:
                self.sniffer_thread.start()
                self.update_timer.start()
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(True)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to start packet sniffer: {e}")

    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.sniffer_thread = None
        self.update_timer.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def buffer_packet(self, packet_info):
        self.pending_packets.append(packet_info)
        self.captured_packets.append(packet_info)  # Append to captured packets as well

    def flush_pending_packets(self):
        while self.pending_packets:
            packet_info = self.pending_packets.pop(0)
            row_position = self.packet_table.rowCount()
            self.packet_table.insertRow(row_position)
            self.packet_table.setItem(row_position, 0, QTableWidgetItem(packet_info.get('eth_src', 'N/A')))
            self.packet_table.setItem(row_position, 1, QTableWidgetItem(packet_info.get('eth_dst', 'N/A')))
            self.packet_table.setItem(row_position, 2, QTableWidgetItem(packet_info.get('ip_src', 'N/A')))
            self.packet_table.setItem(row_position, 3, QTableWidgetItem(packet_info.get('ip_dst', 'N/A')))
            self.packet_table.setItem(row_position, 4, QTableWidgetItem(str(packet_info.get('sport', 'N/A'))))
            self.packet_table.setItem(row_position, 5, QTableWidgetItem(str(packet_info.get('dport', 'N/A'))))
            self.packet_table.setItem(row_position, 6, QTableWidgetItem(packet_info.get('protocol', 'N/A')))
            self.packet_table.setItem(row_position, 7, QTableWidgetItem(packet_info.get('summary', 'N/A')))

    def clear_table(self):
        self.packet_table.setRowCount(0)

    def analyze_packets(self):
        if not self.captured_packets:
            QMessageBox.warning(self, "Warning", "No packets to analyze!")
            return

        self.analysis_window = PacketAnalysisWindow(self.captured_packets)
        self.analysis_window.exec_()

    def get_filter_expression(self, selected_filter, custom_filter):
        if selected_filter == "All Traffic":
            return None
        elif selected_filter == "HTTP Traffic":
            return "tcp port 80"
        elif selected_filter == "TCP Traffic":
            return "tcp"
        elif selected_filter == "UDP Traffic":
            return "udp"
        elif selected_filter == "ICMP Traffic":
            return "icmp"
        elif selected_filter == "By IP Address":
            return f"ip host {custom_filter}" if custom_filter else "ip"
        return custom_filter

    def open_file_dialog(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Capture File", "", "All Files (*);;PCAP Files (*.pcap)", options=options)
        if file_name:
            if self.sniffer_thread:
                self.sniffer_thread.load_pcap_file(file_name)

    def go_to_packet(self):
        row = self.packet_table.currentRow()
        if row >= 0:
            packet_info = {
                'Source MAC': self.packet_table.item(row, 0).text(),
                'Destination MAC': self.packet_table.item(row, 1).text(),
                'Source IP': self.packet_table.item(row, 2).text(),
                'Destination IP': self.packet_table.item(row, 3).text(),
                'Source Port': self.packet_table.item(row, 4).text(),
                'Destination Port': self.packet_table.item(row, 5).text(),
                'Protocol': self.packet_table.item(row, 6).text(),
                'Summary': self.packet_table.item(row, 7).text(),
            }
            msg = QMessageBox()
            msg.setWindowTitle("Packet Information")
            msg.setText("Selected Packet Information:")
            msg.setInformativeText(str(packet_info))
            msg.exec_()
        else:
            QMessageBox.warning(self, "Warning", "No packet selected!")

    def view_packet_list(self):
        pass

    def wireless_settings(self):
        pass

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PacketSnifferUI()
    window.show()
    sys.exit(app.exec_())
