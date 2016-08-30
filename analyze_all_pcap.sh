#!/bin/bash

#
# - Analyze all pcap files.
# - Not support ipv6 currently.
#

SCRIPT_PATH=.

if [ "$1" == "" ]; then
  echo "usage: $0 /path/to/dir_of_pcap_files"
  exit 1
elif [ ! -d "$1" ]; then
  echo "$1 NOT found."
  exit 1
fi

pcaps=`ls "$1" | grep "pcapng$"`

for item in $pcaps; do
  #echo "${item}"

  basename=${item##*/}
  #echo "basename: $basename"

  filename=${basename%.*}
  #echo "filename: $filename"

  extension=${basename##*.}
  #echo "extension: $extension"

  ${SCRIPT_PATH}/filter_pcap_by_protocol.sh "$item" > "$filename"_protocol.txt 2>&1
  ${SCRIPT_PATH}/filter_pcap_by_ssl.sh "$item" > "$filename"_ssl.txt 2>&1
done


echo "===== Finished ====="

