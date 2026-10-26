# Real_Time_Distributed_Firewall
A real-time distributed firewall and CIDR blacklisting system using a Binary Radix Tree for efficient IP prefix matching and a Circular Queue for real-time telemetry and event management.

# Threat Intelligence Radix Engine (Distributed Firewall)

A modular, Software-Defined Networking (SDN) firewall implementing a highly optimized Binary Radix Tree for true 32-bit Longest Prefix Matching (LPM). This system is designed to ingest network traffic, compare it against active Threat Intelligence CIDR blocklists, and log telemetry in a memory-efficient Circular Queue.

## Features

*   True 32-Bit Bitwise Radix Engine: Evaluates packets against CIDR subnets using algorithmic bit-by-bit traversal.
*   Longest Prefix Matching (LPM): Accurately resolves overlapping supernets and subnets.
*   O(1) Telemetry Ring Buffer: Circular queue implementation ensuring constant memory footprint for threat logging.
*   Real-Time Dashboard: Visualizes the entire radix tree topology, packet trace paths, and live ingestion streams.
*   Multi-Protocol Support: Listens on HTTP (Port 8080) and UDP (Port 9999) simultaneously.

## Modular Architecture

The project has been architected into four equally balanced domains to ensure clean separation of concerns and easy collaboration:

### 1. core_data_structures.py (The Data Plane)
Contains the core memory models: `TrieNode`, `BinaryRadixTree`, `LogEvent`, `CircularQueue`, and `Packet`. This file handles the high-performance packet routing logic and memory-bounded telemetry logging.

### 2. rules_and_sim.py (The Control Plane)
Contains `CIDRParser`, `RuleLoader`, and `TrafficSimulator`. Responsible for validating IPv4 addresses, parsing complex CIDR blocks into raw binary strings, managing the active rule state, and generating synthetic attack traffic for testing.

### 3. firewall_orchestrator.py (The Orchestrator)
Contains the `FirewallController` and network packet processing logic. It acts as the brain of the operation, stitching the Data Plane and Control Plane together. It tracks microsecond latency, overall packet counts, and triggers log events for dropped threats.

### 4. main_server.py (The Network Interfaces)
The main execution loop. It launches concurrent daemon threads for the HTTP Gateway, the UDP Socket Listener, and the Dashboard UI Server. It also defines all the REST API endpoints that the web frontend relies on to fetch real-time telemetry.

## Installation and Usage

1. Clone the repository to your local machine.
2. Ensure all Python files, along with `dashboard.html` and `blacklist_rules.txt`, are located in the same root directory.
3. Start the firewall by running the main server script:
   ```bash
   python main_server.py
   ```
4. Open the management dashboard in your web browser:
   `http://localhost:5000`
5. Test the firewall by interacting with the dashboard, running the built-in simulator, or sending manual HTTP/UDP requests to ports 8080 and 9999 respectively.

## How the Radix Tree Engine Works

Unlike linear firewall lists that check rules one by one, this engine converts every CIDR blocklist into a binary string and maps it onto a tree. When a packet arrives, its IP is converted to 32-bit binary. The engine walks down the tree bit-by-bit. If the traversal terminates at a banned node, the packet is instantly dropped. By recording the deepest banned node encountered, the system flawlessly handles Longest Prefix Matching, allowing specific exceptions to override broad subnet bans.
