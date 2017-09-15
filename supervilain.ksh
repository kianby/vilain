#!/bin/ksh

if [ $# != 1 ]; then
  echo "Usage: $0 logfile"
  exit 1
fi

file=${1--}
while read line
do
  line=`echo $line | tr -d '\r'`
  if [[ $line = IP* ]]; then
    ipend="${line##+(IP )}"
    ip="${ipend%%+( ):*}"
    count="${ipend##*\: }"
    if [ "$count" -gt "3" ]; then
      echo "Ban supervilain ${ip} (${count})"
      `pfctl -t supervilain  -T add ${ip}`
    fi
  fi
done <"$file"
