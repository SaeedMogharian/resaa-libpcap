
  #include <cstdio>
  #include <cstring>
  #include <pcap/pcap.h>

  int main() {
    const char* version = pcap_lib_version();
    const char* prefix = "libpcap version ";
    if (strncmp(version, prefix, strlen(prefix)) == 0) {
        version += strlen(prefix);
    }
    printf("%s", version);
    return 0;
  }
  