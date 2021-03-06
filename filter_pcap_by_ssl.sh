#!/bin/sh

#
# - Filter pcap by SSL protocols.
#   + Show SSL/TLS version.
#   + Show cipher suite names in `Client Hello`
#   + Show accessed hosts
#   + Check if server supports SSLv2 or SSLv3
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
echo "===== Does client use SSLv2/SSLv3 version? ====="
echo "| ssl version | handshake type | handshake version | ciphersuite (decimal) | src ip | src port | dst ip | dst port | dst host |"

FILTER="ssl.record.version == 0x0002 || ssl.record.version == 0x0300"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ssl.record.version -e ssl.handshake.type -e ssl.handshake.version -e ssl.handshake.ciphersuite -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssl.handshake.extensions_server_name


#echo ""
#echo "===== Cipher Suites by decimal ====="
#echo "| ssl version | handshake type | handshake version | ciphersuite (decimal) | src ip | src port | dst ip | dst port | dst host |"
#
#FILTER="ssl.handshake.ciphersuite"
#tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ssl.record.version -e ssl.handshake.type -e ssl.handshake.version -e ssl.handshake.ciphersuite -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssl.handshake.extensions_server_name


echo ""
echo "===== Cipher Suites Determination Sequence ====="
FILTER="ssl.handshake.ciphersuite"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" | grep -E "(Cipher Suite:|Version:|Handshake Type:)"

echo ""
echo "===== Cipher Suites by name ====="
FILTER="ssl.handshake.ciphersuite"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" | grep "Cipher Suite:" | sort | uniq > ${INPUT%.*}_cipher_suite.txt
cat ${INPUT%.*}_cipher_suite.txt


echo ""
echo "===== Accessed hosts ====="

FILTER="ssl.handshake.type == 0x01"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.dst -e tcp.dstport | sort | uniq | sed -e 's/[[:space:]]/:/'  > ${INPUT%.*}_ssl_accessed.txt
cat ${INPUT%.*}_ssl_accessed.txt



echo ""
echo "===== SSLv2/SSLv3 Support test ====="
cat ${INPUT%.*}_ssl_accessed.txt | while read line
do
  echo ">> Connecting with SSLv2 for " $line
  openssl s_client -connect $line -ssl2 < /dev/null
  echo ""

  echo ">> Connecting with SSLv3 for " $line
  openssl s_client -connect $line -ssl3 < /dev/null
  echo ""
done

rm -f ${INPUT%.*}_ssl_accessed.txt

echo ""
echo "===== Finished ====="
