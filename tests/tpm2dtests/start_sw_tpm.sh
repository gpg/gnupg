#!/bin/bash

# remove any prior TPM contents
rm -f NVChip h*.bin *.permall
if [ -x "${SWTPM}" ]; then
    ${SWTPM} socket --tpm2 --server type=tcp,port=2321 \
         --ctrl type=tcp,port=2322 --tpmstate dir=`pwd` &
else
    ${TPMSERVER} > /dev/null 2>&1  &
fi
pid=$!
##
# This powers on the tpm and starts it
# then we derive the RSA version of the storage seed and
# store it permanently at handle 81000001 and flush the transient
##
a=0; while [ $a -lt 10 ]; do
    if [ -x "${SWTPM_IOCTL}" ]; then
	${SWTPM_IOCTL} --tcp 127.0.0.1:2322 -i > /dev/null 2>&1
    else
	tsspowerup > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
	break;
    fi
    sleep 1
    a=$[$a+1]
done
if [ $a -eq 10 ]; then
    echo "Waited 10s for tpm_server to come up; exiting"
    exit 1
fi

tssstartup || exit 1
echo -n $pid
