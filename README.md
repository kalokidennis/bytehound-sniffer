# ByteHound Packet Sniffer

Description
ByteHound is a Python-based packet sniffer designed for network analysis and monitoring. It features a user-friendly GUI for capturing, filtering, and analyzing network packets in real-time.
Features

    Real-time Packet Capture: Captures network traffic in real-time.
    Filtering: Allows users to filter packets using custom expressions.
    Analysis Module: Opens a separate window for detailed analysis of captured packets, including safety checks.

Prerequisites

    Python 3.8 or higher
    Basic understanding of networking concepts
    Administrator or root privileges to access network interfaces
    Installation
Step 1: Clone the Repository

    Download the source code or clone the repository using:

    git clone https://github.com/your-username/bytehound-sniffer.git  
    cd bytehound-sniffer  

Step 2: Set Up Virtual Environment (Linux Recommended)

    Create a virtual environment:

python3 -m venv venv  

Activate the virtual environment:

    On Linux:

source venv/bin/activate  
 

Step 3: Install Required Dependencies

    Install the dependencies:

    pip install -r requirements.txt  

Usage
Run the Application

    Launch the sniffer application by running:

    sudo python3 sniffer_frontend.py  

User Guide

    Start Capturing Packets: Click the "Start" button. The packets will populate the table in real-time.
    Set Filter Expression: Enter a valid filter (e.g., tcp port 80) in the filter field and click "Apply Filter."
    Analyze Packets: Click the "Analyze" button to open the analysis window and review packet safety.

Notes

    Root Privileges: Ensure you run the application as an administrator or root user for proper network access.
    Dependencies: Check the requirements.txt for required Python libraries.

Troubleshooting

    Permission Errors: Run the application with elevated privileges using sudo.
    Missing Dependencies: Reinstall the dependencies using pip install -r requirements.txt.
