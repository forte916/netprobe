#!/bin/sh

if [ "$1" == "" ]; then
  echo "usage: $0 pcap_file_name"
  exit 1
fi
INPUT="$1"


echo ""
echo "===== http ====="
echo "| src ip | dst ip | dst port | dst host |"
FILTER="http"tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport ip.dst_host | sort | uniq


echo ""
echo "===== ssl ====="
echo "| src ip | dst ip | dst port | dst host |"
FILTER="ssl"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport ip.dst_host | sort | uniq


echo ""
echo "===== Other tcp ====="
echo "| src ip | dst ip | dst port | dst host |"
FILTER="tcp && !http && !ssl"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport ip.dst_host | sort | uniq


echo ""
echo "===== DNS ====="
echo "| src ip | dst ip | dst port | dst host |"
FILTER="dns"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport ip.dst_host | sort | uniq


echo "" 
echo "===== QUIC ====="
echo "| src ip | dst ip | dst port | dst host |"
FILTER="quic"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport ip.dst_host | sort | uniq


echo ""
echo "===== Other UDP ====="
echo "| src ip | dst ip | dst port | dst host |"
FILTER="udp && !dns && !quic"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport ip.dst_host | sort | uniq




echo "===== Finished ====="