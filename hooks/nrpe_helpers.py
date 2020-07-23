"""Nrpe helpers module."""
import glob
import os
import socket
import subprocess

from charmhelpers.core import hookenv
from charmhelpers.core.host import is_container
from charmhelpers.core.services import helpers

import yaml


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
                mdict["monitors"]["local"], monitor_label,
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
                        checktype, monitors[checktype][checkname], monitor_src,
                    )
                    mons[check_def["cmd_name"]] = {"command": check_def["cmd_name"]}
                except InvalidCustomCheckException as e:
                    hookenv.log(
                        "Error encountered configuring local check "
                        '"{check}": {err}'.format(check=checkname, err=str(e)),
                        hookenv.ERROR,
                    )
        return mons


def get_local_ingress_address(binding):
    """Get ingress IP address for a binding.

    binding - e.g. 'monitors'
    """
    # using network-get to retrieve the address details if available.
    hookenv.log("Getting ingress IP address for binding %s" % binding)
    try:
        network_info = hookenv.network_get(binding)
        if network_info is not None and "ingress-addresses" in network_info:
            hookenv.log("Using ingress-addresses")
            ip_address = network_info["ingress-addresses"][0]
            hookenv.log(ip_address)
            return ip_address
    except (NotImplementedError, FileNotFoundError):
        # We'll fallthrough to the Pre 2.3 code below.
        pass

    # Pre 2.3 output
    try:
        ip_address = hookenv.network_get_primary_address(binding)
        hookenv.log("Using primary-addresses")
    except NotImplementedError:
        # pre Juju 2.0
        ip_address = hookenv.unit_private_ip()
        hookenv.log("Using unit_private_ip")
    hookenv.log(ip_address)
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
        address = get_local_ingress_address("monitors")

        relation_info = {
            "target-id": self.principal_relation.nagios_hostname(),
            "monitors": self.get_monitors(),
            "private-address": address,
            "ingress-address": address,
            "machine_id": os.environ["JUJU_MACHINE_ID"],
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
                monitors.add_monitors(yaml.load(rel["monitors"]), "principal")
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

        address = None
        if hookenv.config("nagios_address_type").lower() == "public":
            address = hookenv.unit_get("public-address")
        elif hookenv.config("nagios_master") != "None":
            # Try to work out the correct interface/IP. We can't use both
            # network-get nor 'unit-get private-address' because both can
            # return the wrong IP on systems with more than one interface
            # (LP: #1736050).
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((hookenv.config("nagios_master").split(",")[0], 80))
            address = s.getsockname()[0]
            s.close()
        # Fallback to unit-get private-address
        if not address:
            address = hookenv.unit_get("private-address")

        self["nagios_ipaddress"] = address
        self["nrpe_ipaddress"] = get_local_ingress_address("monitors")

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

    def __init__(self):
        """Set dict values."""
        procs = self.proc_count()

        if hookenv.config("procs") == "auto":
            proc_thresholds = "-k -w {} -c {}".format(
                25 * procs + 100, 50 * procs + 100
            )
        else:
            proc_thresholds = hookenv.config("procs")

        if hookenv.config("load") == "auto":
            # Give 1min load alerts higher thresholds than 15 min load alerts
            warn_multipliers = (4, 2, 1)
            crit_multipliers = (8, 4, 2)
            load_thresholds = ("-w %s -c %s") % (
                ",".join([str(m * procs) for m in warn_multipliers]),
                ",".join([str(m * procs) for m in crit_multipliers]),
            )
        else:
            load_thresholds = hookenv.config("load")

        if hookenv.config("disk_root"):
            disk_root_thresholds = hookenv.config("disk_root") + " -p / "
        else:
            disk_root_thresholds = ""

        pkg_plugin_dir = "/usr/lib/nagios/plugins/"
        local_plugin_dir = "/usr/local/lib/nagios/plugins/"
        checks = [
            {
                "description": "Root disk",
                "cmd_name": "check_disk_root",
                "cmd_exec": pkg_plugin_dir + "check_disk",
                "cmd_params": disk_root_thresholds,
            },
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
                "description": "System Load",
                "cmd_name": "check_load",
                "cmd_exec": pkg_plugin_dir + "check_load",
                "cmd_params": load_thresholds,
            },
            {
                "description": "Number of Users",
                "cmd_name": "check_users",
                "cmd_exec": pkg_plugin_dir + "check_users",
                "cmd_params": hookenv.config("users"),
            },
            {
                "description": "Swap",
                "cmd_name": "check_swap",
                "cmd_exec": pkg_plugin_dir + "check_swap",
                "cmd_params": hookenv.config("swap"),
            },
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
                "description": "Connnection tracking table",
                "cmd_name": "check_conntrack",
                "cmd_exec": local_plugin_dir + "check_conntrack.sh",
                "cmd_params": hookenv.config("conntrack"),
            },
            {
                "description": "XFS Errors",
                "cmd_name": "check_xfs_errors",
                "cmd_exec": local_plugin_dir + "check_xfs_errors.py",
                "cmd_params": hookenv.config("xfs_errors"),
            },
        ]

        if not is_container():
            arp_check = {
                "description": "ARP cache entries",
                "cmd_name": "check_arp_cache",
                "cmd_exec": os.path.join(local_plugin_dir, "check_arp_cache.py"),
                # Specify params here to enable the check, not required otherwise.
                "cmd_params": "-w 60 -c 80",
            }
            checks.append(arp_check)
            ro_filesystem_excludes = hookenv.config("ro_filesystem_excludes")
            if ro_filesystem_excludes == "":
                # specify cmd_params = '' to disable/remove the check from nrpe
                check_ro_filesystem = {
                    "description": "Readonly filesystems",
                    "cmd_name": "check_ro_filesystem",
                    "cmd_exec": os.path.join(
                        local_plugin_dir, "check_ro_filesystem.py"
                    ),
                    "cmd_params": "",
                }
            else:
                check_ro_filesystem = {
                    "description": "Readonly filesystems",
                    "cmd_name": "check_ro_filesystem",
                    "cmd_exec": os.path.join(
                        local_plugin_dir, "check_ro_filesystem.py"
                    ),
                    "cmd_params": "-e {}".format(
                        hookenv.config("ro_filesystem_excludes")
                    ),
                }
            checks.append(check_ro_filesystem)

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
            d_ifaces = self.parse_netlinks(ifaces)
            for iface in d_ifaces:
                description = "Netlinks status ({})".format(iface)
                cmd_name = "check_netlinks_{}".format(iface)
                cmd_exec = local_plugin_dir + "check_netlinks.py"
                cmd_params = d_ifaces[iface]
                netlink_check = {
                    "description": description,
                    "cmd_name": cmd_name,
                    "cmd_exec": cmd_exec,
                    "cmd_params": cmd_params,
                }
                checks.append(netlink_check)

        self["checks"] = []
        sub_postfix = str(hookenv.config("sub_postfix"))
        # Automatically use _sub for checks shipped on a unit with the nagios
        # charm. Mostly for backwards compatibility.
        principal_unit = hookenv.principal_unit()
        if sub_postfix == "" and principal_unit:
            md = hookenv._metadata_unit(principal_unit)
            if md and md.pop("name", None) == "nagios":
                sub_postfix = "_sub"
        nrpe_config_sub_tmpl = "/etc/nagios/nrpe.d/{}_*.cfg"
        nrpe_config_tmpl = "/etc/nagios/nrpe.d/{}.cfg"
        for check in checks:
            # This can be used to clean up old files before rendering the new
            # ones
            nrpe_configfiles_sub = nrpe_config_sub_tmpl.format(check["cmd_name"])
            nrpe_configfiles = nrpe_config_tmpl.format(check["cmd_name"])
            check["matching_files"] = glob.glob(nrpe_configfiles_sub)
            check["matching_files"].extend(glob.glob(nrpe_configfiles))
            check["description"] += " (sub)"
            check["cmd_name"] += sub_postfix
            self["checks"].append(check)

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
        if type(ifaces) == str:
            ifaces = [ifaces]

        d_ifaces = {}
        for iface in ifaces:
            iface_props = iface.strip().split()
            # no ifaces defined; SKIP
            if len(iface_props) == 0:
                continue

            # non-existing iface; SKIP
            iface_dev = iface_props[0]
            if not os.path.exists(iface_path.format(iface_dev)):
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

            d_ifaces[iface_dev] = "-i {}{}".format(iface_dev, extra_params)
        return d_ifaces
