#!/bin/bash
PORT=$1
TMPFILE="/tmp/socklimit_$$.txt"
CRITICAL=5
WARNING=3
# Do ipv4 and ipv6 IPs
netstat -antu --inet | grep ":$PORT\b" | grep ESTABLISHED | awk '{print $5}'| cut -d: -f1| sort | uniq -c | sort -rn  | sed 's/^[ \t]*//g' > $TMPFILE
netstat -antu --inet6 | grep ":$PORT\b" | grep ESTABLISHED | awk '{print $5}'| cut -d: -f4 | sort | uniq -c | sort -rn  | sed 's/^[ \t]*//g' >> $TMPFILE

MAX_CONNECTION=$(cat $TMPFILE  | sort -rn | head -1 | cut -d' ' -f1)
if [ ! -z $MAX_CONNECTION ] && [ $MAX_CONNECTION -ge $CRITICAL ]; then
    echo "Socket Connection Limit [Thresh=$CRITICAL, Highest=$MAX_CONNECTION] - FAILED"
    cat $TMPFILE
    exit 2
elif [ ! -z $MAX_CONNECTION ] && [ $MAX_CONNECTION -ge $WARNING ]; then
    echo "Socket Connection Limit [Thresh=$WARNING, Highest=$MAX_CONNECTION] - FAILED"
    cat $TMPFILE
else
    echo "Socket Connection Limit [Current Highest=$MAX_CONNECTION] - OK"
    cat $TMPFILE
    exit 0
fi