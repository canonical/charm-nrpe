"""Nrpe helpers module."""

import glob
import ipaddress
import json
import os
import socket
import subprocess

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charmhelpers.core.host import is_container
from charmhelpers.core.services import helpers

import yaml


NETLINKS_ERROR = False

pkg_plugin_dir = "/usr/lib/nagios/plugins/"
local_plugin_dir = "/usr/local/lib/nagios/plugins/"

DB_KEY_KNOWN_REBOOT_TIME = "known_reboot_time"
db = unitdata.kv()


def get_cmd_output(cmd):
    """Get shell command output in unicode string."""
    return subprocess.check_output(cmd).decode("utf8").strip()


def set_known_reboot_time():
    """Set current reboot time in db and return it."""
    uptime_since = get_cmd_output(["uptime", "--since"])
    db.set(DB_KEY_KNOWN_REBOOT_TIME, uptime_since)
    db.flush()
    return uptime_since


def unset_known_reboot_time():
    """Unset current reboot time in db.

    This will remove the key and value from db.
    Useful when we need to disable and re-enable this check to refresh
    known reboot time for all machines, e.g. in a power outage.
    """
    db.unset(DB_KEY_KNOWN_REBOOT_TIME)
    db.flush()


def get_known_reboot_time():
    """Get known reboot time from db."""
    return db.get(DB_KEY_KNOWN_REBOOT_TIME)


def get_check_reboot_context(known_reboot_time=None):
    """Get check_reboot context info for nrpe check, for both add or remove.

    Make this a function because:

    - cmd_params is dynamic
    - reuse in action ack-reboot

    NOTE: when known_reboot_time is not provided, the check will be removed.

    """
    if known_reboot_time:
        # add quotes around the time since it has space in it
        # e.g.: 2022-02-04 10:53:50
        cmd_params = '"{}"'.format(known_reboot_time)
    else:
        # set to empty will remove/disable this check
        cmd_params = ""
    return {
        "description": "System reboot time",
        "cmd_name": "check_reboot",
        "cmd_exec": local_plugin_dir + "check_reboot.py",
        "cmd_params": cmd_params,
    }


class InvalidCustomCheckException(Exception):
    """Custom exception for Invalid nrpe check."""

    pass


class Monitors(dict):
    """List of checks that a remote Nagios can query."""

    def __init__(self, version="0.3"):
        """Build monitors structure."""
        self["monitors"] = {"remote": {"nrpe": {}}}
        self["version"] = version

    def add_monitors(self, mdict, monitor_label="default"):
        """Add monitors passed in mdict."""
        if not mdict or not mdict.get("monitors"):
            return

        for checktype in mdict["monitors"].get("remote", []):
            check_details = mdict["monitors"]["remote"][checktype]
            if self["monitors"]["remote"].get(checktype):
                self["monitors"]["remote"][checktype].update(check_details)
            else:
                self["monitors"]["remote"][checktype] = check_details

        for checktype in mdict["monitors"].get("local", []):
            check_details = self.convert_local_checks(
                mdict["monitors"]["local"],
                monitor_label,
            )
            self["monitors"]["remote"]["nrpe"].update(check_details)

    def add_nrpe_check(self, check_name, command):
        """Add nrpe check to remote monitors."""
        self["monitors"]["remote"]["nrpe"][check_name] = command

    def convert_local_checks(self, monitors, monitor_src):
        """Convert check from local checks to remote nrpe checks.

        monitors -- monitor dict
        monitor_src -- Monitor source principal, subordinate or user
        """
        mons = {}
        for checktype in monitors.keys():
            for checkname in monitors[checktype]:
                try:
                    check_def = NRPECheckCtxt(
                        checktype,
                        monitors[checktype][checkname],
                        monitor_src,
                    )
                    mons[check_def["cmd_name"]] = {"command": check_def["cmd_name"]}
                except InvalidCustomCheckException as e:
                    hookenv.log(
                        "Error encountered configuring local check "
                        '"{check}": {err}'.format(check=checkname, err=str(e)),
                        hookenv.ERROR,
                    )
        return mons


def get_ingress_address(binding, external=False):
    """Get ingress IP address for a binding.

    Returns a local IP address for incoming requests to NRPE.

    :param binding: name of the binding, e.g. 'monitors'
    :param external: bool, if True return the public address if charm config requests
                     otherwise return the local address which would be used for incoming
                     nrpe requests.
    """
    # using network-get to retrieve the address details if available.
    hookenv.log("Getting ingress IP address for binding %s" % binding)
    if hookenv.config("nagios_address_type").lower() == "public" and external:
        return hookenv.unit_get("public-address")

    ip_address = None
    try:
        network_info = hookenv.network_get(binding)
        if network_info is not None and "ingress-addresses" in network_info:
            try:
                ip_address = network_info["bind-addresses"][0]["addresses"][0][
                    "address"
                ]
                hookenv.log("Using ingress-addresses, found %s" % ip_address)
            except KeyError:
                hookenv.log("Using primary-addresses")
                ip_address = hookenv.network_get_primary_address(binding)

    except (NotImplementedError, FileNotFoundError) as e:
        hookenv.log(
            "Unable to determine inbound IP address for binding {} with {}".format(
                binding, e
            ),
            level=hookenv.ERROR,
        )

    return ip_address


class MonitorsRelation(helpers.RelationContext):
    """Define a monitors relation."""

    name = "monitors"
    interface = "monitors"

    def __init__(self, *args, **kwargs):
        """Build superclass and principal relation."""
        self.principal_relation = PrincipalRelation()
        super(MonitorsRelation, self).__init__(*args, **kwargs)

    def is_ready(self):
        """Return true if the principal relation is ready."""
        return self.principal_relation.is_ready()

    def get_subordinate_monitors(self):
        """Return default monitors defined by this charm."""
        monitors = Monitors()
        for check in SubordinateCheckDefinitions()["checks"]:
            if check["cmd_params"]:
                monitors.add_nrpe_check(check["cmd_name"], check["cmd_name"])
        return monitors

    def get_user_defined_monitors(self):
        """Return monitors defined by monitors config option."""
        monitors = Monitors()
        monitors.add_monitors(yaml.safe_load(hookenv.config("monitors")), "user")
        return monitors

    def get_principal_monitors(self):
        """Return monitors passed by relation with principal."""
        return self.principal_relation.get_monitors()

    def get_monitor_dicts(self):
        """Return all monitor dicts."""
        monitor_dicts = {
            "principal": self.get_principal_monitors(),
            "subordinate": self.get_subordinate_monitors(),
            "user": self.get_user_defined_monitors(),
        }
        return monitor_dicts

    def get_monitors(self):
        """Return monitor dict.

        All monitors merged together and local
        monitors converted to remote nrpe checks.
        """
        all_monitors = Monitors()
        monitors = [
            self.get_principal_monitors(),
            self.get_subordinate_monitors(),
            self.get_user_defined_monitors(),
        ]
        for mon in monitors:
            all_monitors.add_monitors(mon)
        return all_monitors

    def egress_subnets(self, relation_data):
        """Return egress subnets.

        This behaves the same as charmhelpers.core.hookenv.egress_subnets().
        If it can't determine the egress subnets it will fall back to
        ingress-address or finally private-address.
        """
        if "egress-subnets" in relation_data:
            return relation_data["egress-subnets"]
        if "ingress-address" in relation_data:
            return relation_data["ingress-address"]
        return relation_data["private-address"]

    def get_data(self):
        """Get relation data."""
        super(MonitorsRelation, self).get_data()
        if not hookenv.relation_ids(self.name):
            return
        # self['monitors'] comes from the superclass helpers.RelationContext
        # and contains relation data for each 'monitors' relation (to/from
        # Nagios).
        subnets = [self.egress_subnets(info) for info in self["monitors"]]
        self["monitor_allowed_hosts"] = ",".join(subnets)

    def provide_data(self):
        """Return relation info."""
        # get the address to send to Nagios for host definition
        address = get_ingress_address("monitors", external=True)

        relation_info = {
            "target-id": self.principal_relation.nagios_hostname(),
            "monitors": self.get_monitors(),
            "private-address": address,
            "ingress-address": address,
            "target-address": address,
            "machine_id": os.environ["JUJU_MACHINE_ID"],
            "model_id": hookenv.model_uuid(),
        }
        return relation_info


class PrincipalRelation(helpers.RelationContext):
    """Define a principal relation."""

    def __init__(self, *args, **kwargs):
        """Set name and interface."""
        if hookenv.relations_of_type("nrpe-external-master"):
            self.name = "nrpe-external-master"
            self.interface = "nrpe-external-master"
        elif hookenv.relations_of_type("general-info"):
            self.name = "general-info"
            self.interface = "juju-info"
        elif hookenv.relations_of_type("local-monitors"):
            self.name = "local-monitors"
            self.interface = "local-monitors"
        super(PrincipalRelation, self).__init__(*args, **kwargs)

    def is_ready(self):
        """Return true if the relation is connected."""
        if self.name not in self:
            return False
        return "__unit__" in self[self.name][0]

    def nagios_hostname(self):
        """Return the string that nagios will use to identify this host."""
        host_context = hookenv.config("nagios_host_context")
        if host_context:
            host_context += "-"
        hostname_type = hookenv.config("nagios_hostname_type")

        # Detect bare metal hosts
        if hostname_type == "auto":
            is_metal = "none" in subprocess.getoutput("/usr/bin/systemd-detect-virt")
            if is_metal:
                hostname_type = "host"
            else:
                hostname_type = "unit"

        if hostname_type == "host" or not self.is_ready():
            nagios_hostname = "{}{}".format(host_context, socket.gethostname())
            return nagios_hostname
        else:
            principal_unitname = hookenv.principal_unit()
            # Fallback to using "primary" if it exists.
            if not principal_unitname:
                for relunit in self[self.name]:
                    if relunit.get("primary", "False").lower() == "true":
                        principal_unitname = relunit["__unit__"]
                        break
            nagios_hostname = "{}{}".format(host_context, principal_unitname)
            nagios_hostname = nagios_hostname.replace("/", "-")
            return nagios_hostname

    def get_monitors(self):
        """Return monitors passed by services on the self.interface relation."""
        if not self.is_ready():
            return
        monitors = Monitors()
        for rel in self[self.name]:
            if rel.get("monitors"):
                monitors.add_monitors(yaml.safe_load(rel["monitors"]), "principal")
        return monitors

    def provide_data(self):
        """Return nagios hostname and nagios host context."""
        # Provide this data to principals because get_nagios_hostname expects
        # them in charmhelpers/contrib/charmsupport/nrpe when writing principal
        # service__* files
        return {
            "nagios_hostname": self.nagios_hostname(),
            "nagios_host_context": hookenv.config("nagios_host_context"),
        }


class NagiosInfo(dict):
    """Define a NagiosInfo dict."""

    def __init__(self):
        """Set principal relation and dict values."""
        self.principal_relation = PrincipalRelation()
        self["external_nagios_master"] = "127.0.0.1"
        if hookenv.config("nagios_master") != "None":
            self["external_nagios_master"] = "{},{}".format(
                self["external_nagios_master"], hookenv.config("nagios_master")
            )
        self["nagios_hostname"] = self.principal_relation.nagios_hostname()

        # export_host.cfg.tmpl host definition for Nagios
        self["nagios_ipaddress"] = get_ingress_address("monitors", external=True)
        # Address configured for NRPE to listen on
        self["nrpe_ipaddress"] = get_ingress_address("monitors")

        self["dont_blame_nrpe"] = "1" if hookenv.config("dont_blame_nrpe") else "0"
        self["debug"] = "1" if hookenv.config("debug") else "0"


class RsyncEnabled(helpers.RelationContext):
    """Define a relation context for rsync enabled relation."""

    def __init__(self):
        """Set export_nagios_definitions."""
        self["export_nagios_definitions"] = hookenv.config("export_nagios_definitions")
        if (
            hookenv.config("nagios_master")
            and hookenv.config("nagios_master") != "None"
        ):
            self["export_nagios_definitions"] = True

    def is_ready(self):
        """Return true if relation is ready."""
        return self["export_nagios_definitions"]


class NRPECheckCtxt(dict):
    """Convert a local monitor definition.

    Create a dict needed for writing the nrpe check definition.
    """

    def __init__(self, checktype, check_opts, monitor_src):
        """Set dict values."""
        plugin_path = "/usr/lib/nagios/plugins"
        if checktype == "procrunning":
            self["cmd_exec"] = plugin_path + "/check_procs"
            self["description"] = "Check process {executable} is running".format(
                **check_opts
            )
            self["cmd_name"] = "check_proc_" + check_opts["executable"]
            self["cmd_params"] = "-w {min} -c {max} -C {executable}".format(
                **check_opts
            )
        elif checktype == "processcount":
            self["cmd_exec"] = plugin_path + "/check_procs"
            self["description"] = "Check process count"
            self["cmd_name"] = "check_proc_principal"
            if "min" in check_opts:
                self["cmd_params"] = "-w {min} -c {max}".format(**check_opts)
            else:
                self["cmd_params"] = "-c {max}".format(**check_opts)
        elif checktype == "disk":
            self["cmd_exec"] = plugin_path + "/check_disk"
            self["description"] = "Check disk usage " + check_opts["path"].replace(
                "/", "_"
            )
            self["cmd_name"] = "check_disk_principal"
            self["cmd_params"] = "-w 20 -c 10 -p " + check_opts["path"]
        elif checktype == "custom":
            custom_path = check_opts.get("plugin_path", plugin_path)
            if not custom_path.startswith(os.path.sep):
                custom_path = os.path.join(os.path.sep, custom_path)
            if not os.path.isdir(custom_path):
                raise InvalidCustomCheckException(
                    'Specified plugin_path "{}" does not exist or is not a '
                    "directory.".format(custom_path)
                )
            check = check_opts["check"]
            self["cmd_exec"] = os.path.join(custom_path, check)
            self["description"] = check_opts.get("desc", "Check %s" % check)
            self["cmd_name"] = check
            self["cmd_params"] = check_opts.get("params", "") or ""
        self["description"] += " ({})".format(monitor_src)
        self["cmd_name"] += "_" + monitor_src


class SubordinateCheckDefinitions(dict):
    """Return dict of checks the charm configures."""

    def __init__(self):  # noqa: C901
        """Set dict values."""
        self.procs = self.proc_count()
        load_thresholds = self._get_load_thresholds()
        proc_thresholds = self._get_proc_thresholds()
        disk_root_thresholds = self._get_disk_root_thresholds()

        checks = [
            {
                "description": "Number of Zombie processes",
                "cmd_name": "check_zombie_procs",
                "cmd_exec": pkg_plugin_dir + "check_procs",
                "cmd_params": hookenv.config("zombies"),
            },
            {
                "description": "Number of processes",
                "cmd_name": "check_total_procs",
                "cmd_exec": pkg_plugin_dir + "check_procs",
                "cmd_params": proc_thresholds,
            },
            {
                "description": "Number of Users",
                "cmd_name": "check_users",
                "cmd_exec": pkg_plugin_dir + "check_users",
                "cmd_params": hookenv.config("users"),
            },
            {
                "description": "Connnection tracking table",
                "cmd_name": "check_conntrack",
                "cmd_exec": local_plugin_dir + "check_conntrack.sh",
                "cmd_params": hookenv.config("conntrack"),
            },
            {
                "description": "Number of bad state systemd scopes",
                "cmd_name": "check_systemd_scopes",
                "cmd_exec": local_plugin_dir + "check_systemd_scopes.py",
                "cmd_params": hookenv.config("systemd_scopes"),
            },
        ]

        if hookenv.config("cis_audit_enabled"):
            cmd_params = "-p '{}' {}".format(
                hookenv.config("cis_audit_profile"),
                hookenv.config("cis_audit_score"),
            )
            cis_audit_check = {
                "description": "Check CIS audit",
                "cmd_name": "check_cis_audit",
                "cmd_exec": local_plugin_dir + "check_cis_audit.py",
                "cmd_params": cmd_params,
            }
            checks.append(cis_audit_check)

        if not is_container():
            checks.extend(
                [
                    {
                        "description": "Root disk",
                        "cmd_name": "check_disk_root",
                        "cmd_exec": pkg_plugin_dir + "check_disk",
                        "cmd_params": disk_root_thresholds,
                    },
                    {
                        "description": "System Load",
                        "cmd_name": "check_load",
                        "cmd_exec": pkg_plugin_dir + "check_load",
                        "cmd_params": load_thresholds,
                    },
                    {
                        "description": "Swap",
                        "cmd_name": "check_swap",
                        "cmd_exec": pkg_plugin_dir + "check_swap",
                        "cmd_params": hookenv.config("swap").strip(),
                    },
                    # Note: check_swap_activity *must* be listed after check_swap, else
                    # check_swap_activity will be removed during installation of
                    # check_swap.
                    {
                        "description": "Swap Activity",
                        "cmd_name": "check_swap_activity",
                        "cmd_exec": local_plugin_dir + "check_swap_activity",
                        "cmd_params": hookenv.config("swap_activity"),
                    },
                    {
                        "description": "Memory",
                        "cmd_name": "check_mem",
                        "cmd_exec": local_plugin_dir + "check_mem.pl",
                        "cmd_params": hookenv.config("mem"),
                    },
                    {
                        "description": "XFS Errors",
                        "cmd_name": "check_xfs_errors",
                        "cmd_exec": local_plugin_dir + "check_xfs_errors.py",
                        "cmd_params": hookenv.config("xfs_errors"),
                    },
                    {
                        "description": "ARP cache entries",
                        "cmd_name": "check_arp_cache",
                        "cmd_exec": os.path.join(
                            local_plugin_dir, "check_arp_cache.py"
                        ),
                        "cmd_params": hookenv.config("arp_cache"),
                    },
                    {
                        "description": "Readonly filesystems",
                        "cmd_name": "check_ro_filesystem",
                        "cmd_exec": os.path.join(
                            local_plugin_dir, "check_ro_filesystem.py"
                        ),
                        "cmd_params": (
                            "-e {}".format(hookenv.config("ro_filesystem_excludes"))
                            if hookenv.config("ro_filesystem_excludes")
                            else ""
                        ),
                    },
                ]
            )

            # setup the partitions / block devices for disk space_check
            space_check = yaml.safe_load(hookenv.config("space_check"))

            # create the override map with mountpoint: params
            override_map = {}
            for mp in space_check.get("overrides", []):
                override_map[mp["mountpoint"]] = mp["params"]

            for mountpoint in get_partitions_to_check():
                params = "-u GB -w 25% -c 20% -K 5%"
                if "auto_params" in space_check:
                    params = space_check["auto_params"]
                if mountpoint in override_map:
                    params = override_map[mountpoint]
                cmd_params = "{} -p {}".format(params, mountpoint)
                # the root partition is only a slash, so add a meaningful name
                check_path = mountpoint.replace("/", "_")
                if check_path == "_":
                    check_path = "_root"
                checks.append(
                    {
                        "description": "Check disk space on {}".format(mountpoint),
                        "cmd_name": "check_space{}".format(check_path),
                        "cmd_exec": pkg_plugin_dir + "check_disk",
                        "cmd_params": (
                            cmd_params
                            if space_check["check"].strip() != "disabled"
                            else ""
                        ),
                    }
                )

            if hookenv.config("lacp_bonds").strip():
                for bond_iface in hookenv.config("lacp_bonds").strip().split():
                    if os.path.exists("/sys/class/net/{}".format(bond_iface)):
                        description = "LACP Check {}".format(bond_iface)
                        cmd_name = "check_lacp_{}".format(bond_iface)
                        cmd_exec = local_plugin_dir + "check_lacp_bond.py"
                        cmd_params = "-i {}".format(bond_iface)
                        lacp_check = {
                            "description": description,
                            "cmd_name": cmd_name,
                            "cmd_exec": cmd_exec,
                            "cmd_params": cmd_params,
                        }
                        checks.append(lacp_check)

            if hookenv.config("netlinks"):
                ifaces = yaml.safe_load(hookenv.config("netlinks"))
                cmd_exec = local_plugin_dir + "check_netlinks.py"
                if hookenv.config("netlinks_skip_unfound_ifaces"):
                    cmd_exec += " --skip-unfound-ifaces"
                d_ifaces = self.parse_netlinks(ifaces)
                for iface in d_ifaces:
                    description = "Netlinks status ({})".format(iface)
                    cmd_name = "check_netlinks_{}".format(iface)
                    cmd_params = d_ifaces[iface]
                    netlink_check = {
                        "description": description,
                        "cmd_name": cmd_name,
                        "cmd_exec": cmd_exec,
                        "cmd_params": cmd_params,
                    }
                    checks.append(netlink_check)

        # Checking if CPU governor is supported by the system and add nrpe check
        cpu_governor_supported = glob.glob(
            "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
        )
        cpu_governor_setting = hookenv.config("cpu_governor")
        if not cpu_governor_setting:
            principal_unit = hookenv.principal_unit()
            principal_charm_name = hookenv._metadata_unit(principal_unit).get("name")
            if principal_charm_name in [
                "nova-compute",
                "kubernetes-worker",
                "rabbitmq-server",
                "percona-cluster",
            ]:
                hookenv.log(
                    "Setting default cpu freq scaling governor to 'performance' \
                     for unit:[{}] with charm name:[{}]".format(
                        principal_unit, principal_charm_name
                    ),
                    level=hookenv.DEBUG,
                )
                cpu_governor_setting = "performance"

        if cpu_governor_setting and cpu_governor_supported:
            description = "Check CPU governor scaler"
            cmd_name = "check_cpu_governor"
            cmd_exec = local_plugin_dir + "check_cpu_governor.py"
            cmd_params = "--governor {}".format(cpu_governor_setting)
            cpu_governor_check = {
                "description": description,
                "cmd_name": cmd_name,
                "cmd_exec": cmd_exec,
                "cmd_params": cmd_params,
            }
            checks.append(cpu_governor_check)

        # add or remove reboot check, according to config
        enable_check_reboot = hookenv.config("reboot")  # boolean
        if enable_check_reboot:
            # read from db if exist, or set current uptime in db and use it
            known_reboot_time = get_known_reboot_time() or set_known_reboot_time()
            check_reboot_context = get_check_reboot_context(
                known_reboot_time=known_reboot_time
            )
        else:
            # set to None will disable/remove this check
            check_reboot_context = get_check_reboot_context(known_reboot_time=None)
            # also rm known reboot time key and value in db
            unset_known_reboot_time()
        checks.append(check_reboot_context)

        self["checks"] = []
        sub_postfix = str(hookenv.config("sub_postfix"))
        sub_postfix_sep = "###"
        # Automatically use _sub for checks shipped on a unit with the nagios
        # charm. Mostly for backwards compatibility.
        principal_unit = hookenv.principal_unit()
        if sub_postfix == "" and principal_unit:
            md = hookenv._metadata_unit(principal_unit)
            if md and md.pop("name", None) == "nagios":
                sub_postfix = "sub"
        nrpe_config_sub_tmpl = "/etc/nagios/nrpe.d/{}{}*.cfg".format(
            "{}", sub_postfix_sep
        )
        nrpe_config_tmpl = "/etc/nagios/nrpe.d/{}.cfg"
        disable_system_checks = hookenv.config("disable_system_checks")
        for check in checks:
            # This can be used to clean up old files before rendering the new
            # ones
            nrpe_configfiles_sub = nrpe_config_sub_tmpl.format(check["cmd_name"])
            nrpe_configfiles = nrpe_config_tmpl.format(check["cmd_name"])
            check["matching_files"] = glob.glob(nrpe_configfiles_sub)
            check["matching_files"].extend(glob.glob(nrpe_configfiles))
            check["description"] += " (sub)"
            if sub_postfix:
                check["cmd_name"] += sub_postfix_sep + sub_postfix
            check["cmd_params"] = (
                check["cmd_params"] if not disable_system_checks else ""
            )
            self["checks"].append(check)

    def _get_proc_thresholds(self):
        """Return suitable processor thresholds."""
        if hookenv.config("procs") == "auto":
            proc_thresholds = "-k -w {} -c {}".format(
                25 * self.procs + 100, 50 * self.procs + 100
            )
        else:
            proc_thresholds = hookenv.config("procs")
        return proc_thresholds

    def _get_load_thresholds(self):
        """Return suitable load thresholds."""
        if hookenv.config("load") == "auto":
            # Give 1min load alerts higher thresholds than 15 min load alerts
            warn_multipliers = (4, 2, 1)
            crit_multipliers = (8, 4, 2)
            load_thresholds = ("-w %s -c %s") % (
                ",".join([str(m * self.procs) for m in warn_multipliers]),
                ",".join([str(m * self.procs) for m in crit_multipliers]),
            )
        else:
            load_thresholds = hookenv.config("load")
        return load_thresholds

    def _get_disk_root_thresholds(self):
        """Return suitable disk thresholds."""
        if hookenv.config("disk_root"):
            disk_root_thresholds = hookenv.config("disk_root") + " -p / "
            hookenv.log(
                "disk_root config option is now deprecated in favour of space_check ",
                level=hookenv.ERROR,
            )
        else:
            disk_root_thresholds = ""
        return disk_root_thresholds

    def proc_count(self):
        """Return number number of processing units."""
        return int(subprocess.check_output(["nproc", "--all"]))

    def parse_netlinks(self, ifaces):
        """Parse a list of strings, or a single string.

        Looks if the interfaces exist and configures extra parameters (or
        properties) -> ie. ['mtu:9000', 'speed:1000', 'op:up']
        """
        iface_path = "/sys/class/net/{}"
        props_dict = {"mtu": "-m {}", "speed": "-s {}", "op": "-o {}"}
        if isinstance(ifaces, str):
            ifaces = [ifaces]

        d_ifaces = {}
        for iface in ifaces:
            iface_props = iface.strip().split()
            # no ifaces defined; SKIP
            if len(iface_props) == 0:
                continue

            target = iface_props[0]
            try:
                matches = match_cidr_to_ifaces(target)
            except Exception as e:
                # Log likely unintentional errors and set flag for blocked status,
                # if appropriate.
                if isinstance(e, ValueError) and "has host bits set" in e.args[0]:
                    hookenv.log(
                        "Error parsing netlinks: {}".format(e.args[0]),
                        level=hookenv.ERROR,
                    )
                    set_netlinks_error()
                # Treat target as explicit interface name
                matches = [target]

            iface_devs = [
                target
                for target in matches
                if os.path.exists(iface_path.format(target))
            ]
            # no ifaces found; SKIP
            if not iface_devs:
                continue

            # parse extra parameters (properties)
            del iface_props[0]
            extra_params = ""
            for prop in iface_props:
                # wrong format (key:value); SKIP
                if prop.find(":") < 0:
                    continue

                # only one ':' expected
                kv = prop.split(":")
                if len(kv) == 2 and kv[0].lower() in props_dict:
                    extra_params += " "
                    extra_params += props_dict[kv[0].lower()].format(kv[1])

            for iface_dev in iface_devs:
                d_ifaces[iface_dev] = "-i {}{}".format(iface_dev, extra_params)
        return d_ifaces


def is_valid_partition(device):
    """Check if a partition is valid for disk space check."""
    ignored_devices = {"loop", "tmpfs", "devtmpfs", "squashfs"}
    if device.get("type") in ignored_devices:
        return False
    return True


def process_block_devices(devices):
    """Recursively process all sections in lsblk output."""
    partitions_to_check = set()

    for dev in devices:
        # Jammy returns a list of "mountpoints" instead of a single value
        # in the key "mountpoint"
        mountpoints = dev.get("mountpoints", []) or [dev.get("mountpoint")]
        if is_valid_partition(dev):
            partitions_to_check.update(mountpoints)
        children = dev.get("children", [])
        partitions_to_check.update(process_block_devices(children))

    return partitions_to_check


def is_valid_mountpoint(mountpoint):
    """Check if mountpoint is not a K8s PV or system partition but valid mountpoint."""
    skipped_partitions = [None, "[SWAP]", "/boot/efi"]

    path = "/var/lib/kubelet/pods"

    # Filtering mountpoints related to various Kubernetes PVs and system partition.
    # ex- in MicroK8s, prefix "/var/snap/microk8s/common/" is appended to the mount path
    return mountpoint not in skipped_partitions and path not in mountpoint


def get_partitions_to_check():
    """Get a list of partitions to be checked by check_disk."""
    lsblk_cmd = "lsblk -J".split()
    lsblk_output = subprocess.check_output(lsblk_cmd).decode("UTF-8")
    block_devices = json.loads(lsblk_output).get("blockdevices", [])

    partitions_to_check = process_block_devices(block_devices)

    partitions_to_check = set(filter(is_valid_mountpoint, partitions_to_check))

    return partitions_to_check


def match_cidr_to_ifaces(cidr):
    """Use CIDR expression to search for matching network adapters.

    Returns a list of adapter names.
    """
    import netifaces  # Avoid import error before this dependency gets installed

    network = ipaddress.IPv4Network(cidr)
    matches = []
    for adapter in netifaces.interfaces():
        ipv4_addr_structs = netifaces.ifaddresses(adapter).get(netifaces.AF_INET, [])
        addrs = [
            ipaddress.IPv4Address(addr_struct["addr"])
            for addr_struct in ipv4_addr_structs
        ]
        if any(addr in network for addr in addrs):
            matches.append(adapter)
    return matches


def has_netlinks_error():
    """Return True in case of netlinks related errors."""
    return NETLINKS_ERROR


def set_netlinks_error():
    """Set the flag indicating a netlinks related error."""
    global NETLINKS_ERROR
    NETLINKS_ERROR = True
