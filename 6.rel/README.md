```plaintext
+--------------------+
|      Interface   |
+--------------------+
| - name             |
| - ip_stat<ip,(packet, byte)|
| - injection_failure        |
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
```

![[photo_2024-11-14_13-00-37.jpg]]