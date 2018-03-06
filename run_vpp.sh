#!/bin/bash
DPDK_DIR="/opt/dpdk/lib"
T=`pwd`/build-root/install-vpp-native/vpp
/bin/rm -f /dev/shm/db /dev/shm/global_vm /dev/shm/vpe-api || return
#LD_LIBRARY_PATH=$DPDK_DIR gdb --args $T/bin/vpp -c `pwd`/startup.conf
LD_LIBRARY_PATH=$DPDK_DIR $T/bin/vpp -c `pwd`/startup.conf
