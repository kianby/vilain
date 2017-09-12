#!/bin/ksh

if [ $# != 1 ]; then
   echo "Usage: $0 logfile"
   exit 1
fi

regex="^IP ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[ ]*: ([0-9]+)"

file=${1--} # POSIX-compliant; ${1:--} can be used either.
while IFS= read -r line; do
   #echo $line
   if [[ $line = *@^IP*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)*:*([0-9]+) ]];
   then
     ip="${BASH_REMATCH[1]}"
     count="${BASH_REMATCH[2]}"
     if [ "$count" -gt "2" ]; then
       echo "ban supervilain ${ip} (${count})"
       #`pfctl -t supervilain  -T add ${ip}`
     fi
   fi
done <"$file"
