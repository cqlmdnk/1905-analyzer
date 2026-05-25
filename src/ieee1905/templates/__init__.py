# SPDX-License-Identifier: GPL-2.0-or-later
"""YAML-driven CMDU templates for one-shot injection.

A template is a small YAML document that names a message type and a
list of TLVs to encode. Variables enclosed in ``${...}`` are
substituted from a user-supplied mapping at instantiation time. The
resulting CMDU is round-trippable through the regular codec, so the
analyzer / fixtures see exactly the same bytes that go on the wire.

The built-in templates live in :mod:`ieee1905.templates` package data
(directory ``templates/builtin/``) and are discovered automatically by
:func:`builtin_templates`.

Example YAML::

    name: topology_discovery
    description: Basic IEEE 1905.1 Topology Discovery
    message_type: 0x0000
    tlvs:
      - class: AlMacAddress
        al_mac: "${al_mac}"
      - class: MacAddress
        mac: "${interface_mac}"

Then::

    from ieee1905.templates import load_template
    tpl = load_template(path)
    cmdu = tpl.build({"al_mac": "02:aa:bb:cc:dd:01",
                      "interface_mac": "02:aa:bb:cc:ee:01"})
    wire = cmdu.to_bytes()
"""

from ieee1905.templates.loader import (
    Template,
    TemplateError,
    builtin_templates,
    builtin_templates_dir,
    load_template,
    load_template_dict,
)

__all__ = [
    "Template",
    "TemplateError",
    "builtin_templates",
    "builtin_templates_dir",
    "load_template",
    "load_template_dict",
]
