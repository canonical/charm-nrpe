#!/bin/bash

# Copyright (c) 2014 Canonical, Ltd
# Author: Brad Marshall <brad.marshall@canonical.com>

# Checks if a network namespace is responding by doing an ip a in each one.

. /usr/lib/nagios/plugins/utils.sh

check_ret_value() {
    RET=$1
    if [[ $RET -ne 0 ]];then
        echo "CRIT: $2"
        exit $STATE_CRIT
    fi
}

check_netns_create() {
    RET_VAL=$(ip netns add nrpe-check 2>&1)
    check_ret_value $? "$RET_VAL"
    RET_VAL=$(ip netns delete nrpe-check 2>&1)
    check_ret_value $? "$RET_VAL"
}


netnsok=()
netnscrit=()

for ns in $(ip netns list | egrep -v '^nrpe-check$'); do
    output=$(ip netns exec $ns ip a 2>/dev/null)
    err=$?
    if [ $err -eq 0 ]; then
        netnsok=("${netnsok[@]}" $ns)
    else
        netnscrit=("${netnscrit[@]}" $ns)
    fi
done

if [ ${#netnscrit[@]} -eq 0 ]; then
    if [ ${#netnsok[@]} -eq 0 ]; then
        check_netns_create
        echo "OK: no namespaces defined"
        exit $STATE_OK
    else
        echo "OK: ${netnsok[@]} are responding"
        exit $STATE_OK
    fi
else
    echo "CRIT: ${netnscrit[@]} aren't responding"
    exit $STATE_CRIT
fi

