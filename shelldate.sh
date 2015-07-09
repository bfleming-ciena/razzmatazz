#!/bin/bash
function time_between {
mydate=$1
from=$2
to=$3

from_num=$(date --date="$from" +%s)
to_num=$(date --date="$to" +%s)
mydate_num=$(date --date="$mydate" +%s)

diff=$(( ${to_num} - ${from_num} ))

if [ ${mydate_num} -le ${to_num} -a ${mydate_num} -ge ${from_num} ]; then
   echo 1
else
   echo 0
fi

}

result=$(time_between "07/05/2015 10:30:00pm" "07/01/2015 10:30:00pm" "07/09/2015 10:30:00pm")
echo $result
