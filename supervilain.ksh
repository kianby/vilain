#!/bin/ksh

if [ $# != 1 ]; then
   echo "Usage: $0 logfile"
   exit 1
fi

regex="^IP ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[ ]*: ([0-9]+)"

file=${1--} # POSIX-compliant; ${1:--} can be used either.
while IFS= read -r line; do

   if [[ "$line" =~ "^IP " ]]; then
     ipend="${line##+(IP )}"
     ip="${ipend%%+(+(\s):\s+(\d))}"
     count="${ipend##+(*:\s)}"
     if [ "$count" -gt "2" ]; then
       echo "ban supervilain ${ip} (${count})"
       `pfctl -t supervilain  -T add ${ip}`
     fi
   fi
done <"$file"
