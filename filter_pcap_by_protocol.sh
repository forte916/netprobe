#!/bin/sh

#
# - Filter pcap by each protocols.
# - Not support ipv6 currently.
#

if [ "$1" == "" ]; then
  echo "usage: $0 pcap_file_name"
  exit 1
elif [ ! -f "$1" ]; then
  echo "$1 NOT found."
  exit 1
fi
INPUT="$1"


echo ""
echo "===== DNS ====="
echo "| src ip | dst ip | dst port | dns qery name |"
FILTER="dns.flags.response == 0"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e udp.dstport -e dns.qry.name | sort | uniq


echo ""
echo "===== http ====="
echo "| src ip | dst ip | dst port | hostname | url |"
FILTER="http.request"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport -e http.host -e http.request.uri | sort | uniq


echo ""
echo "===== ssl ====="
echo "| src ip | dst ip | dst port | ssl version | hostname |"
FILTER="ssl.handshake.type == 1"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e tcp.dstport -e ssl.record.version -e ssl.handshake.extensions_server_name | sort | uniq


echo ""
echo "===== Other tcp ====="
echo "| src ip | dst ip | protocol |"
FILTER="tcp && !http && !ssl"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e frame.protocols | sort | uniq


echo ""
echo "===== QUIC ====="
echo "| src ip | dst ip | dst port | quic version | hostname |"
FILTER="quic.tag"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e udp.dstport -e quic.version -e quic.tag.sni | sort | uniq


echo ""
echo "===== Other UDP ====="
echo "| src ip | dst ip | dst port | protocol |"
FILTER="udp && !dns && !quic && !icmp"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e frame.protocols | sort | uniq


echo ""
echo "===== ICMP ====="
echo "| src ip | dst ip | dst port | protocol |"
FILTER="icmp"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e frame.protocols | sort | uniq


echo ""
echo "===== Finished ====="
