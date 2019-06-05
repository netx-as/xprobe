#!/bin/bash

INT=fge11


echo "NUMA Node: "; cat /sys/class/net/$INT/device/numa_node


echo "CPU frequency:"; grep -E '^model name|^cpu MHz' /proc/cpuinfo




