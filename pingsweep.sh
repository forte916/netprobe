#!/bin/bash

# ping sweep cheat sheet

echo "--- 1 ping sweep"
for ip in {1..254}; do
	ping -c 1 -W 100 192.168.1.$ip | grep 'time=';
done

echo "--- 2 ping sweep"
for ip in 192.168.1.{1..254}; do
	ping -t 1 $ip > /dev/null && echo "${ip} is up"
done

# ping sweep by nmap
echo "--- 3 ping sweep"
namp -sn -oG alived_ip.txt 192.168.1.1-255


