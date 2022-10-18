#!/bin/bash
KERNEL_VERSION=`uname  -r`

if [[ ! -e include/mount.h ]]; then
	echo "Please copy Kernel v${KERNEL_VERSION} to include/mount.h"
	exit -1
fi
