#!/bin/bash
if [ "$EUID" -ne 0 ]; then
	echo "Please run with sudo"
	exit
fi

sysctl -w kernel.shm_rmid_forced=1
sysctl -w kernel.shmmax=18446744073692774399
sysctl -w vm.hugetlb_shm_group=27
sysctl -w vm.max_map_count=16777216
sysctl -w net.core.somaxconn=3072

echo 4096 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

for n in /sys/devices/system/node/node[1-9]; do
	if [ -d $n ]; then
		echo 0 > $n/hugepages/hugepages-2048kB/nr_hugepages
	fi
done

echo "Binding nic"
ip link set enp6s0 down
modprobe uio
insmod ./dpdk/build/kmod/igb_uio.ko
python3 ./dpdk/usertools/dpdk-devbind.py -b igb_uio 06:00.0
python3 ./dpdk/usertools/dpdk-devbind.py -s
