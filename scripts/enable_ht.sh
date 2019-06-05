#!/bin/bash
for i in {2..31}; do
   echo "Enabling logical HT core $i."
   echo 1 > /sys/devices/system/cpu/cpu${i}/online;
done

grep -H . /sys/devices/system/cpu/cpu*/topology/thread_siblings_list
