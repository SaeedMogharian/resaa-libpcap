Structural Design:

```plaintext
+----------------------------+
|          Interface         |
+----------------------------+
| - name                     |
| - ip_stat<ip,(packet, byte)|
| - injection_failure        |
+----------------------------+
| + run(argc, argv)          |
| + stop()                   |
| + parseArguments()         |
+----------------------------+
         |
         v
+----------------------+
|      Connection      |
+----------------------+
| - primary            |
| - secondary          |
+----------------------+
| + sniff()            |
| + inject()           |
+----------------------+


(LibPcapWrapper)
```
