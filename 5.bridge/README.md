Here's a high-level object structure diagram for the provided C++ code. This diagram captures the main objects and their relationships, giving a visual overview of how the code components interact with each other:

### Diagram Key
- **Classes** are represented as rectangles.
- **Arrows** indicate relationships (e.g., "uses", "contains").
- **Methods** and **attributes** are mentioned inside the class boxes where relevant.

---

```plaintext
+--------------------+
|      Application   |
+--------------------+
| - interface_prim   |
| - interface_secn   |
| - filter           |
| - count            |
| - stats_manager    |
| - primary_session  |
| - secondary_session|
+--------------------+
| + run(argc, argv)  |
| + stop()           |
| + parseArguments() |
+--------------------+
         |
         v
+----------------------+
|   CaptureSession     |
+----------------------+
| - interface_name     |
| - sniff_handle       |
| - packet_handler     |
| - stop_flag          |
+----------------------+
| + startCapture()     |
| + stopCapture()      |
| + getStats()         |
| + getPacketHandler() |
+----------------------+
         |
         v
+--------------------+
|   PacketHandler    |
+--------------------+
| - injection_handle |
| - interface_name   |
| - stats_manager    |
| - injection_failures|
| - packets_processed |
+--------------------+
| + handle()         |
| + packetCallback() |
| + print()          |
+--------------------+
         |
         v
+--------------------+
|  StatisticsManager |
+--------------------+
| - ip_statistics    |
+--------------------+
| + update()         |
| + print()          |
+--------------------+
         ^
         |
+--------------------+
|      IpStats       |
+--------------------+
| - packets_sent     |
| - bytes_sent       |
| - interface        |
+--------------------+
| + (constructor)    |
+--------------------+

Other Supporting Components:
----------------------------
+--------------------+
| Unique Pcap Handle |
+--------------------+
| Wrapper for pcap_t |
+--------------------+

+--------------------+
| Signal Handling    |
+--------------------+
| Handles SIGINT,    |
| SIGTERM, SIGQUIT   |
+--------------------+

+--------------------+
| PCAP Library       |
+--------------------+
| Used for packet    |
| capture, filtering,|
| injection, etc.    |
+--------------------+
```

---

### Explanation of Relationships:
1. **Application**:
   - Manages the overall program.
   - Uses **CaptureSession** objects for primary and secondary interfaces.
   - Has a **StatisticsManager** to collect and display IP statistics.

2. **CaptureSession**:
   - Encapsulates a network interface and a packet capture handle (`sniff_handle`).
   - Utilizes a **PacketHandler** to manage captured packets.
   - Uses static utility methods for creating PCAP handles.

3. **PacketHandler**:
   - Processes packets and updates the **StatisticsManager** with packet data.
   - Handles packet injection and keeps track of injection success/failure.

4. **StatisticsManager**:
   - Maintains a map of **IpStats**, which hold per-IP statistics (packets sent, bytes sent, etc.).
   - Provides functionality to update and print IP-level statistics.

5. **IpStats**:
   - Represents statistics for a specific IP address.
   - Contains attributes like `packets_sent`, `bytes_sent`, and the interface name.

6. **PCAP Library**:
   - Interfaced through methods like `pcap_open_live`, `pcap_inject`, `pcap_loop`, and others.
   - Used extensively in **CaptureSession** and **PacketHandler**.

7. **Signal Handling**:
   - Ensures graceful termination of the application when signals like SIGINT are received.
   - Links directly to the global **Application** instance.

This diagram and explanation capture the primary relationships and workflows in your code. Let me know if you'd like a visual rendering of this structure!


