# httpcap
Parse and display http traffic from network device or pcap file. This is a go version of origin pcap-parser, thanks to gopacket project, this tool has simpler code base and is more efficient.

# Dependency

httpcap uses libpcap, a system-independent interface for user-level packet capture,Before use httpcap, you must first install libpcap

for ubuntu/debian:

```
sudo apt install libpcap-dev
```

for centos/redhat/fedora:

```
sudo yum install libpcap-devel
```

# Usage

