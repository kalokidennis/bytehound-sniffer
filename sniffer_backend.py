from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, Ether, IP, ARP, TCP, UDP, ICMP, DNS

class PacketSnifferThread(QThread):
    # Signal to emit captured packet information to the UI
    packet_captured = pyqtSignal(dict)

    def __init__(self, parent=None):
        super(PacketSnifferThread, self).__init__(parent)
        self.running = False
        self.filter_expression = None

    def set_filter(self, filter_expression):
        """Set the filter expression for capturing packets."""
        self.filter_expression = filter_expression

    def run(self):
        """Run the packet sniffer in a separate thread."""
        self.running = True
        try:
            sniff(filter=self.filter_expression, prn=self.process_packet, stop_filter=self.should_stop)
        except Exception as e:
            print(f"Error during packet sniffing: {e}")

    def process_packet(self, packet):
        """Process each packet and emit its information."""
        if not self.running:
            return

        packet_info = {}

        # Extract Ethernet layer information
        if Ether in packet:
            packet_info['eth_src'] = packet[Ether].src
            packet_info['eth_dst'] = packet[Ether].dst

        # Extract IP layer information
        if IP in packet:
            packet_info['ip_src'] = packet[IP].src
            packet_info['ip_dst'] = packet[IP].dst

        # Extract protocol-specific information
        if TCP in packet:
            packet_info['sport'] = packet[TCP].sport
            packet_info['dport'] = packet[TCP].dport
            packet_info['protocol'] = "TCP"
        elif UDP in packet:
            packet_info['sport'] = packet[UDP].sport
            packet_info['dport'] = packet[UDP].dport
            packet_info['protocol'] = "UDP"
        elif ICMP in packet:
            packet_info['protocol'] = "ICMP"
        elif ARP in packet:
            packet_info['protocol'] = "ARP"
        elif DNS in packet:
            packet_info['protocol'] = "DNS"
        else:
            packet_info['protocol'] = "Other"

        # Add a summary of the packet
        packet_info['summary'] = packet.summary()

        # Only include fields that are non-empty
        packet_info = {k: v for k, v in packet_info.items() if v}

        # Emit the packet information to the frontend
        self.packet_captured.emit(packet_info)

    def should_stop(self, packet):
        """Check if the sniffer should stop."""
        return not self.running

    def stop(self):
        """Stop the packet sniffer."""
        self.running = False
