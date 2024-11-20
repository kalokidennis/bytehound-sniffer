from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QMessageBox, QSizePolicy
from PyQt5.QtCore import Qt


class PacketAnalysisWindow(QDialog):
    def __init__(self, packets, parent=None):
        super().__init__(parent)
        self.packets = packets
        self.setWindowTitle("Packet Analysis Window")  # Title of the window
        self.setMinimumSize(600, 400)  # Set minimum size to ensure the window is not too small
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint)  # Enable minimize and maximize buttons
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Title label
        title_label = QLabel("Captured Packets Analysis")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        # Table to display captured packets
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(9)  # Including "Safe" column
        self.packet_table.setHorizontalHeaderLabels([
            'Source MAC', 'Destination MAC', 'Source IP', 'Destination IP',
            'Source Port', 'Destination Port', 'Protocol', 'Summary', 'Safe'
        ])
        self.packet_table.setRowCount(len(self.packets))  # Set rows based on captured packets
        self.populate_table()

        # Set the table size policy to expand in both directions
        self.packet_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Ensure the horizontal header stretches
        self.packet_table.horizontalHeader().setStretchLastSection(True)

        # After populating the table, adjust column widths
        self.adjust_column_widths()

        # Add the table to the layout
        layout.addWidget(self.packet_table)

        # Analyze button
        analyze_button = QPushButton("Analyze Packets")
        analyze_button.clicked.connect(self.analyze_packets)
        layout.addWidget(analyze_button)

        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)

        self.setLayout(layout)

    def populate_table(self):
        """Populate the table with packet data."""
        for row_index, packet in enumerate(self.packets):
            self.packet_table.setItem(row_index, 0, QTableWidgetItem(packet.get('eth_src', 'Unknown')))
            self.packet_table.setItem(row_index, 1, QTableWidgetItem(packet.get('eth_dst', 'Unknown')))
            self.packet_table.setItem(row_index, 2, QTableWidgetItem(packet.get('ip_src', 'Unknown')))
            self.packet_table.setItem(row_index, 3, QTableWidgetItem(packet.get('ip_dst', 'Unknown')))
            self.packet_table.setItem(row_index, 4, QTableWidgetItem(str(packet.get('sport', '-'))))
            self.packet_table.setItem(row_index, 5, QTableWidgetItem(str(packet.get('dport', '-'))))
            self.packet_table.setItem(row_index, 6, QTableWidgetItem(packet.get('protocol', 'Unknown')))
            self.packet_table.setItem(row_index, 7, QTableWidgetItem(packet.get('summary', 'No summary available')))
            self.packet_table.setItem(row_index, 8, QTableWidgetItem('Yes' if packet.get('safe', True) else 'No'))

    def analyze_packets(self):
        """Analyze captured packets and show results."""
        try:
            print("Analyze button clicked")  # Debugging log
            print(f"Captured packets: {self.packets}")  # Debugging log

            if not self.packets:
                QMessageBox.warning(self, "Warning", "No packets to analyze!")
                return

            # Perform the packet analysis
            analysis_result = self.perform_analysis()
            QMessageBox.information(self, "Analysis Result", analysis_result)
        except Exception as e:
            print(f"Error during analysis: {e}")  # Debugging log
            QMessageBox.critical(self, "Error", f"An error occurred during analysis: {e}")

    def perform_analysis(self):
        """Perform analysis on captured packets and check for potential safety risks."""
        total_packets = len(self.packets)
        safe_packets = sum(1 for packet in self.packets if packet.get('safe', True))
        unsafe_packets = total_packets - safe_packets

        analysis_result = (
            f"Total Packets Captured: {total_packets}\n"
            f"Safe Packets: {safe_packets} ({(safe_packets / total_packets) * 100:.2f}%)\n"
            f"Unsafe Packets: {unsafe_packets} ({(unsafe_packets / total_packets) * 100:.2f}%)"
        )

        return analysis_result

    def is_safe(self, packet):
        """Check whether a packet is safe based on various criteria."""
        unsafe_ips = {'192.168.1.100', '10.0.0.1'}  # Example unsafe IPs
        unsafe_ports = {4444, 23}  # Example unsafe ports (e.g., remote access)

        # Check for suspicious IP addresses or ports
        if packet.get('ip_src') in unsafe_ips or packet.get('ip_dst') in unsafe_ips:
            return False
        if packet.get('sport') in unsafe_ports or packet.get('dport') in unsafe_ports:
            return False

        # Further checks can be added here, such as detecting known attack signatures
        return True

    def closeEvent(self, event):
        """Ensure only the analysis window closes without affecting the parent."""
        event.accept()

    def adjust_column_widths(self):
        """Make the 'Summary' column 4 times its current size and 'Source MAC' and 'Destination MAC' columns 2 times their size, by removing space from the 'Safe' column."""
        summary_column_width = self.packet_table.columnWidth(7)  # Get current width of the 'Summary' column
        safe_column_width = self.packet_table.columnWidth(8)  # Get current width of the 'Safe' column
        source_mac_column_width = self.packet_table.columnWidth(0)  # Get current width of the 'Source MAC' column
        dest_mac_column_width = self.packet_table.columnWidth(1)  # Get current width of the 'Destination MAC' column

        # Calculate how much space to transfer
        width_to_transfer = (summary_column_width * 3)  # 3 times the current width of the Summary column
        mac_columns_width_increase = (source_mac_column_width + dest_mac_column_width)  # Double the current size of MAC columns

        # Set new width for the 'Summary' column
        self.packet_table.setColumnWidth(7, summary_column_width + width_to_transfer)

        # Set new width for the 'Source MAC' and 'Destination MAC' columns (doubling their size)
        self.packet_table.setColumnWidth(0, source_mac_column_width + mac_columns_width_increase // 2)
        self.packet_table.setColumnWidth(1, dest_mac_column_width + mac_columns_width_increase // 2)

        # Set new width for the 'Safe' column, reducing it by the transferred width
        self.packet_table.setColumnWidth(8, safe_column_width - width_to_transfer - mac_columns_width_increase)
