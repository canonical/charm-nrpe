# Common settings/trap for nrpe hooks
if [ -n "${JUJU_REMOTE_UNIT:-''}" ] ; then
    unit_name=${JUJU_REMOTE_UNIT//\//-}
else
    unit_name=""
fi

live_config=/etc/nagios/nrpe.d/allowed.hosts.cfg
datadir="data/allowed"

new_file=""
cleanup() {
    if [ -n "$new_file" ] ; then
        rm -f $new_file
    fi
}
trap cleanup EXIT

regen_allowed() {
    new_file=$(mktemp $(dirname $live_config)/.$(basename $live_config).XXXXXX)
    local addresses=$(cat $datadir/*|sed -e 's/,$//')
    echo allowed_hosts=$addresses > $new_file
    if [ -e $live_config ] ; then
        mv -f $live_config $live_config.bak
    fi
    mv -f $new_file $live_config
}
