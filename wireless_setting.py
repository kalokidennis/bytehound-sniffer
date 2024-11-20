import subprocess
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit, QMessageBox, QHeaderView, QInputDialog, QHBoxLayout, QProgressBar

class WirelessSettingsWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Wireless Settings")
        self.setMinimumSize(700, 450)  # Increased the window size for better usability
        self.setWindowIcon(QIcon("wifi-icon.png"))  # Add a window icon
        self.networks = []  # List to hold available networks
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Title label
        title_label = QLabel("Available Wi-Fi Networks")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #333;")
        layout.addWidget(title_label)

        # Table to display networks
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(3)
        self.network_table.setHorizontalHeaderLabels(["SSID", "Signal Strength", "Security"])
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.network_table.setAlternatingRowColors(True)  # Alternating row colors for better readability
        self.network_table.setStyleSheet("""
            QTableWidget {
                font-size: 14px;
                background-color: #f9f9f9;
                border: 1px solid #ddd;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #ddd;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.network_table)

        # Horizontal layout for buttons
        button_layout = QHBoxLayout()

        # Connect button with icon
        connect_button = QPushButton("Connect")
        connect_button.setIcon(QIcon("connect-icon.png"))  # Add icon to connect button
        connect_button.clicked.connect(self.connect_to_network)
        button_layout.addWidget(connect_button)

        # Refresh button with icon
        refresh_button = QPushButton("Refresh Networks")
        refresh_button.setIcon(QIcon("refresh-icon.png"))  # Add icon to refresh button
        refresh_button.clicked.connect(self.scan_networks)
        button_layout.addWidget(refresh_button)

        layout.addLayout(button_layout)

        # Progress bar for scanning networks
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("QProgressBar { background-color: #f0f0f0; }")
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)
        self.scan_networks()  # Initial scan for networks

    def scan_networks(self):
        """Scan for available Wi-Fi networks using `nmcli`."""
        self.progress_bar.setVisible(True)  # Show progress bar while scanning
        try:
            # Run the nmcli command to list Wi-Fi networks
            result = subprocess.run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi"], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, 
                                     text=True)
            if result.returncode != 0:
                raise Exception(result.stderr.strip())

            # Parse the output and update the table
            self.networks = []
            self.network_table.setRowCount(0)
            for line in result.stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) == 3:
                    ssid, signal, security = parts
                    self.networks.append({"SSID": ssid, "Signal": signal, "Security": security})
                    row_position = self.network_table.rowCount()
                    self.network_table.insertRow(row_position)
                    self.network_table.setItem(row_position, 0, QTableWidgetItem(ssid))
                    self.network_table.setItem(row_position, 1, QTableWidgetItem(signal))
                    self.network_table.setItem(row_position, 2, QTableWidgetItem(security))

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to scan networks: {e}")
        finally:
            self.progress_bar.setVisible(False)  # Hide progress bar after scanning is done

    def connect_to_network(self):
        """Connect to the selected Wi-Fi network."""
        selected_row = self.network_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Warning", "Please select a network to connect.")
            return

        ssid = self.network_table.item(selected_row, 0).text()
        security = self.network_table.item(selected_row, 2).text()

        if "WPA" in security or "WEP" in security:  # Secure network
            password, ok = QInputDialog.getText(self, "Network Password", 
                                                f"Enter password for '{ssid}':", 
                                                QLineEdit.Password)
            if not ok or not password:
                return
        else:
            password = None

        try:
            # Construct the nmcli command to connect
            if password:
                connect_cmd = ["nmcli", "dev", "wifi", "connect", ssid, "password", password]
            else:
                connect_cmd = ["nmcli", "dev", "wifi", "connect", ssid]

            result = subprocess.run(connect_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                raise Exception(result.stderr.strip())

            QMessageBox.information(self, "Success", f"Connected to '{ssid}' successfully!")
            self.parent().set_active_network(ssid)  # Notify the parent to restrict sniffing to this network
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to '{ssid}': {e}")
