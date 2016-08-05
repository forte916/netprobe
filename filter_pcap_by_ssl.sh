#!/bin/sh

if [ "$1" == "" ]; then
  echo "usage: $0 pcap_file_name"
  exit 1
fi
INPUT="$1"

echo "===== Does client use SSLv2/SSLv3 version? ====="
echo "| ssl version | handshake type | handshake version | ciphersuite (decimal) | src ip | src port | dst ip | dst port | dst host |"

FILTER="ssl.record.version == 0x0002 || ssl.record.version == 0x0300"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ssl.record.version -e ssl.handshake.type -e ssl.handshake.version -e ssl.handshake.ciphersuite -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssl.handshake.extensions_server_name


echo ""
echo "===== Cipher Suites by decimal ====="
echo "| ssl version | handshake type | handshake version | ciphersuite (decimal) | src ip | src port | dst ip | dst port | dst host |"

FILTER="ssl.handshake.ciphersuite"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ssl.record.version -e ssl.handshake.type -e ssl.handshake.version -e ssl.handshake.ciphersuite -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssl.handshake.extensions_server_name


echo ""
echo "===== Cipher Suites by name ====="
FILTER="ssl.handshake.ciphersuite"
tshark -2 -V -n -r "$1" -R "$FILTER" | grep "Cipher Suite:" | sort | uniq > "$1"_cipher_suite.txt
cat "$1"_cipher_suite.txt


echo ""
echo "===== Accessed hosts ====="

FILTER="ssl.handshake.type == 0x01"
tshark -2 -V -n -r "$1" -R "$FILTER" -T fields -e ip.dst -e tcp.dstport | sort | uniq | sed -e 's/[[:space:]]/:/'  > "$1"_accessed.txt
cat "$1"_accessed.txt



echo ""
echo "===== SSLv2/SSLv3 Support test ====="
cat "$1"_accessed.txt | while read line
do
  echo ">> Connecting with SSLv2 for " $line
  openssl s_client -connect $line -ssl2 < /dev/null
  echo ""

  echo ">> Connecting with SSLv3 for " $line
  openssl s_client -connect $line -ssl3 < /dev/null
  echo ""
done


echo "===== Finished ====="
