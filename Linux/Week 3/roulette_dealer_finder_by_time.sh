#!/bin/bash



cat $1_Dealer_schedule | grep "$2"| awk '{print "'"$1"'", $1, $2, $5, $6}'

#$1=date $2=time
#cat date_Dealer_schedule | grep 'time AM/PM'| awk '{print "'"date"'", $1, $2, $5, $6}'
#date, for example 0310 (March 10)
#time AM/PM, 08:00:00 AM
