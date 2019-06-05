#!/bin/bash

INT=eno4
IRQRATE=2
cpu=4


echo "NUMA Node: "; cat /sys/class/net/$INT/device/numa_node

sysctl -p scripts/xdp-sysctl-values


#ifdown $INT
ethtool -L $INT combined 2

for i in rx tx tso gso gro tx sg txvlan rxvlan ntuple highdma rxhash hw-tc-offload rx-vlan-filter; do
       /sbin/ethtool -K $INT  $i off 2>&1 > /dev/null;
	echo $i
done

service irqbalance stop
service tuned stop

# Turn off adaptive interrupt moderation
ethtool -C $INT adaptive-rx off
ethtool -C $INT adaptive-tx off

# Fixed interrupt rate
ethtool -C $INT  rx-usecs $IRQRATE
ethtool -C $INT  tx-usecs $IRQRATE

# Turn off flow control
ethtool -A $INT off rx off tx off


echo 200 > /sys/class/net/$INT/queues/rx-0/rps_cpus 
echo 400 > /sys/class/net/$INT/queues/rx-1/rps_cpus
echo 800 > /sys/class/net/$INT/queues/rx-2/rps_cpus
echo 1600> /sys/class/net/$INT/queues/rx-3/rps_cpus

#echo 2 > /sys/class/net/$INT/queues/tx-0/rps_cpus


n=0
ncpus=2
for irq in `ls /sys/class/net/eno4/device/msi_irqs/`
do
    echo $irq
    f="/proc/irq/$irq/smp_affinity"
    test -r "$f" || continue
    cpu=$[$ncpus - ($n % $ncpus) - 1]
    if [ $cpu -ge 0 ]
            then
                mask=`printf %x $[2 ** $cpu]`
                #mask=1
		echo "Assign SMP affinity: $dev queue $n, irq $irq, cpu $cpu, mask 0x$mask"

                echo "$mask" > "$f"
                let n+=1
    fi2
done


#ifup $INT 

