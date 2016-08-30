#!/bin/sh

#
# - Filter pcap by http.
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
echo "===== http request ====="
echo "| src ip | hostname | method | uri | version |"
FILTER="http.request"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e http.host -e http.request.method -e http.request.uri -e http.request.version | sort | uniq

echo ""
echo "===== http response ====="
echo "| src ip | dst ip | version | code | phrase |"
FILTER="http.response"
tshark -2 -V -n -r "$INPUT" -R "$FILTER" -T fields -e ip.src -e ip.dst -e http.request.version -e http.response.code -e http.response.phrase | sort | uniq


echo ""
echo "===== http Set-Cookie ====="
tshark -2 -V -n -r "$INPUT" | grep "Set-Cookie" | sort | uniq

echo ""
echo "===== http Cookie pair ====="
tshark -2 -V -n -r "$INPUT" | grep "Cookie pair" | sort | uniq

echo ""
echo "===== http User-Agent ====="
tshark -2 -V -n -r "$INPUT" | grep "User-Agent" | sort | uniq

echo ""
echo "===== http POST Form item ====="
tshark -2 -V -n -r "$INPUT" | grep "Form item" | sort | uniq


echo ""
echo "===== Finished ====="
