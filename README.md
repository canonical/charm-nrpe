Introduction
============

This subordinate charm is used to configure nrpe (Nagios Remote Plugin
Executor). It can be related to the nagios charm via the monitors relation and
will pass a monitors yaml to nagios informing it of what checks to monitor.

Principal Relations
===================

This charm can be attached to any principal charm (via the juju-info relation)
regardless of whether it has implemented the local-monitors or
nrpe-external-master relations. For example:

    juju deploy ubuntu
    juju deploy nrpe
    juju deploy nagios
    juju add-relation ubuntu nrpe
    juju add-relation nrpe:monitors nagios:monitors

If joined via the juju-info relation the default checks are configured and
additional checks can be added via the monitors config option (see below).

The local-monitors relations allows the principal to request checks to be setup
by passing a monitors yaml and listing them in the 'local' section. It can
also list checks that is has configured by listing them in the remote nrpe
section and finally it can request external monitors are setup by using one of
the other remote types. See "Monitors yaml" below.

Other Subordinate Charms
========================

If another subordinate charm deployed to the same principal has a
local-monitors or nrpe-external-master relation then it can also be related to
the local nrpe charm. For example:

    echo -e "glance:\n  vip: 10.5.106.1" > glance.yaml
    juju deploy -n3 --config glance.yaml glance
    juju deploy hacluster glance-hacluster
    juju deploy nrpe glance-nrpe
    juju deploy nagios
    juju add-relation glance glance-hacluster
    juju add-relation glance-nrpe:monitors nagios:monitors
    juju add-relation glance glance-nrpe
    juju add-relation glance-hacluster glance-nrpe

The glance-hacluster charm will pass monitoring information to glance-nrpe
which will amalgamate all monitor definitions before passing them to nagios.

Check sources
=============

Check definitions can come from three places:

Default Checks
--------------

This charm creates a base set of checks in /etc/nagios/nrpe.d, including
check\_load, check\_users, check\_disk\_root. All of the options for these are
configurable but sensible defaults have been set in config.yaml.
For example to increase the alert threshold for number of processes:

    juju config nrpe load="-w 10,10,10 -c 25,25,25"

Default checks maybe disabled by setting them to the empty string.

Principal Requested Checks
--------------------------

Monitors passed to this charm by the principal charm via the local-monitors
or nrpe-external-master relation. The principal charm can write its own
check definition into */etc/nagios/nrpe.d* and then inform this charm via the
monitors setting. It can also request a direct external check of a service
without using nrpe. See "Monitors yaml" below for examples.

User Requested Checks
---------------------

This works in the same way as the Principal requested except the monitors yaml
is set by the user via the monitors config option. For example to add a monitor
for the rsyslog process:

    juju config nrpe monitors="
    monitors:
        local:
            procrunning:
                rsyslogd:
                    min: 1
                    max: 1
                    executable: rsyslogd
    "



External Nagios 
===============

If the nagios server is not deployed in the juju environment then the charm can
be configured, via the export\_nagios\_definitions, to write out nagios config
fragments to /var/lib/nagios/export. Rsync is then configured to allow a host
(specified by nagios\_master) to collect the fragments. An rsync stanza is created
allowing the Nagios server to pick up configs from /var/lib/nagios/export (as
a target called "external-nagios"), which will also be configured to allow
connections from the hostname or IP address as specified for the
"nagios\_master" variable.

It is up to you to configure the Nagios master to pull the configs needed, which
will then cause it to connect back to the instances in question to run the nrpe
checks you have defined.

Monitors yaml
=============

The list of monitors past down the monitors relation is an amalgamation of the
lists provided via the principal, the user and the default checks.

The monitors yaml is of the following form:

     
    # Version of the spec, mostly ignored but 0.3 is the current one
    version: '0.3'
    # Dict with just 'local' and 'remote' as parts
    monitors:
        # local monitors need an agent to be handled. See nrpe charm for
        # some example implementations
        local:
            # procrunning checks for a running process named X (no path)
            procrunning:
                # Multiple procrunning can be defined, this is the "name" of it
                nagios3:
                    min: 1
                    max: 1
                    executable: nagios3
        # Remote monitors can be polled directly by a remote system
        remote:
            # do a request on the HTTP protocol
            http:
                nagios:
                    port: 80
                    path: /nagios3/
                    # expected status response (otherwise just look for 200)
                    status: 'HTTP/1.1 401'
                    # Use as the Host: header (the server address will still be used to connect() to)
                    host: www.fewbar.com
            mysql:
                # Named basic check
                basic:
                    username: monitors
                    password: abcdefg123456
            nrpe:
                apache2:
                    command: check_apache2



Before a monitor is added it is checked to see if it is in the 'local' section.
If it is this charm needs to convert it into an nrpe checks. Only a small
number of check types are currently supported (see below) .These checks can
then be called by the nagios charm via the nrpe service. So for each check
listed in the local section:

1.  The definition is read and a check definition it written /etc/nagios/nrpe.d
2.  The check is defined as a remote nrpe check in the yaml passed to nagios

In the example above a check\_proc\_nagios3\_user.cfg file would be written
out which contains:

    # Check process nagios3 is running (user)
    command[check_proc_nagios3_user]=/usr/lib/nagios/plugins/check_procs -w 1 -c 1 -C nagios3

And the monitors yaml passed to nagios would include:

    monitors:
        nrpe:
	    check_proc_nagios3_user:
	        command: check_proc_nagios3_user

The principal charm, or the user via the monitors config option, can request an
external check by adding it to the remote section of the monitors yaml. In the
example above direct checks of a webserver and of mysql are being requested.
This charm passes those on to nagios unaltered.

Local check types
-----------------

Supported nrpe checks are:

    procrunning:
      min: Minimum number of 'executable' processes
      max: Maximum number of 'executable' processes
      executable: Name of executable to look for in process list
    processcount:
      min: Minimum total number processes
      max: Maximum total number processes
      executable: Name of executable to look for in process list
    disk:
      path: Directory to monitor space usage of
    custom:
      check: the name of the check to execute
      plugin_path: (optional) Absolute path to the directory containing the 
                   custom plugin. Default value is /var/lib/nagios/plugins
      description: (optional) Description of the check
      params: (optional) Parameters to pass to the check on invocation

Remote check types
------------------

Supported remote types:
    http, mysql, nrpe, tcp, rpc, pgsql
    (See Nagios charm for up-to-date list and options)

Spaces
======

By defining 'monitors' binding, you can influence which nrpe's IP will be reported
back to Nagios. This can be very handy if nrpe is placed on machines with multiple
IPs/networks.

Actions
=======

The charm defines 2 actions, 'list-nrpe-checks' that gives a list of all the
nrpe checks defined for this unit and what commands they use.  The other is
run-nrpe-check, which allows you to run a specified nrpe check and get the
output.  This is useful to confirm if an alert is actually resolved.
