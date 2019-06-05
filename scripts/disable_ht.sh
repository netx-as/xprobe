#!/bin/bash
for i in {16..31}; do
   echo "Disabling logical HT core $i."
   echo 0 > /sys/devices/system/cpu/cpu${i}/online;
done

grep -H . /sys/devices/system/cpu/cpu*/topology/thread_siblings_list

cpupower frequency-set --governor performance

