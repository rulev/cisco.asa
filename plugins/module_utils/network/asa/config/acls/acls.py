#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The asa_acls class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import copy
from difflib import Differ

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.cisco.asa.plugins.module_utils.network.asa.facts.facts import Facts
from ansible_collections.cisco.asa.plugins.module_utils.network.asa.rm_templates.acls import (
    AclsTemplate,
)


class Acls(ResourceModule):
    """
    The asa_acls class
    """

    gather_subset = ["!all", "!min"]

    gather_network_resources = ["acls"]

    def __init__(self, module):
        super(Acls, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="acls",
            tmplt=AclsTemplate(),
        )

    def execute_module(self):
        """Execute the module
        :rtype: A dictionary
        :returns: The result from module execution
        """
        self.gen_config()
        self.run_commands()
        return self.result

    def gen_config(self):
        """Select the appropriate function based on the state provided
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        if self.want:
            temp = {}
            for entry in self.want["acls"]:
                temp.update({(entry["name"]): entry})
            wantd = temp
        else:
            wantd = {}
        if self.have:
            temp = {}
            for entry in self.have["acls"]:
                temp.update({(entry["name"]): entry})
            haved = temp
        else:
            haved = {}

        for k, want in iteritems(wantd):
            h_want = haved.get(k, {})
            if want.get("aces"):
                for each in want["aces"]:
                    if h_want.get("aces"):
                        for e_have in h_want.get("aces"):
                            if e_have.get("source") == each.get("source") and e_have.get(
                                "destination",
                            ) == each.get(
                                "destination",
                            ):
                                if each.get("protocol") == e_have.get("protocol"):
                                    if not each.get(
                                        "protocol_options",
                                    ) and e_have.get("protocol_options"):
                                        del e_have["protocol_options"]
                                        break
                                elif each.get("protocol_options") == e_have.get("protocol_options"):
                                    if not each.get(
                                        "protocol",
                                    ) and e_have.get("protocol"):
                                        del e_have["protocol"]
                                        break

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            # to append line number from have to want
            # if want ace config matches have ace config
            temp_have = copy.deepcopy(haved)
            for k, v in iteritems(wantd):
                h_item = temp_have.pop(k, {})
                if not h_item:
                    continue
                if v.get("aces"):
                    for each in v["aces"]:
                        if "line" in each:
                            continue
                        else:
                            for each_have in h_item["aces"]:
                                if each_have.get("line"):
                                    have_line = each_have.pop("line")
                                    if each == each_have:
                                        each.update({"line": have_line})
                                        break
                                    each_have.update({"line": have_line})
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            temp = {}
            for k, v in iteritems(haved):
                if k in wantd or not wantd:
                    temp.update({k: v})
            haved = temp
            wantd = {}

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            for k, have in iteritems(haved):
                if k not in wantd:
                    self._compare(want={}, have=have)

        temp = []
        for k, want in iteritems(wantd):
            if want.get("rename") and want.get("rename") not in temp:
                self.commands.extend(
                    ["access-list {name} rename {rename}".format(**want)],
                )
            elif k in haved:
                temp.append(k)
            self._compare(want=want, have=haved.pop(k, {}))
        if self.state in ["replaced", "overridden", "deleted"]:
            config_cmd = [cmd for cmd in self.commands if cmd.startswith("no ")][::-1]
            config_cmd.extend(
                [cmd for cmd in self.commands if not cmd.startswith("no ")],
            )
            self.commands = config_cmd

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Ospf_interfaces network resource.
        """

        # the idea is to render want and have access lists
        # and compare text representations using difflib
        want_cmds = []
        if want.get("aces"):
            for ace in want.get("aces"):
                if self.state in ["overridden", "deleted", "replaced"] and ace.get("line"):
                    del ace["line"]
                ace.update(
                    {
                        "name": want.get("name"),
                        "acl_type": want.get("acl_type"),
                    },
                )
                want_cmds.extend(self._tmplt.render({"aces": ace}, "aces", False))

        have_cmds = []
        if have.get("aces"):
            for ace in have.get("aces"):
                if self.state in ["overridden", "deleted", "replaced"] and ace.get("line"):
                    del ace["line"]
                ace.update(
                    {
                        "name": have.get("name"),
                        "acl_type": have.get("acl_type"),
                    },
                )
                have_cmds.extend(self._tmplt.render({"aces": ace}, "aces", False))

        d = Differ()
        diff = list(d.compare(have_cmds, want_cmds))

        line_no = 1
        for cmd in diff:
            tokens = cmd.split(" ")
            if tokens[0] == "-":
                if "line" in cmd:
                    self.commands.append("no {}".format(" ".join(tokens[1:])))
                else:
                    self.commands.append("no {} {} line {} {}".format(*tokens[1:3], line_no, " ".join(tokens[3:])))
                line_no += 1
            elif tokens[0] == '':
                line_no += 1

        line_no = 1
        for cmd in diff:
            tokens = cmd.split(" ")
            if tokens[0] == "+":
                if "line" in cmd:
                    self.commands.append(" ".join(tokens[1:]))
                else:
                    self.commands.append("{} {} line {} {}".format(*tokens[1:3], line_no, " ".join(tokens[3:])))
                line_no += 1
            elif tokens[0] == '':
                line_no += 1
