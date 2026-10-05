#!/usr/bin/env python3
"""
test_entrypoints_read_config_arg.py — the service entrypoints must honor the
config path passed on the command line.

The systemd units invoke each service as `python3 src/<module>.py config.yaml`.
An earlier version hardcoded run("config.yaml") in the __main__ block and
ignored argv entirely — so a non-default install dir or an alternate config
was silently discarded. This locks in that argv[1] is read.
"""
import os
import re

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")

ENTRYPOINTS = {
    "backend_server.py": "run_backend",
    "honeypot.py":       "S7Proxy",
    "snmp_agent.py":     "SNMPAgent",
    "web_portal.py":     "run",
}


def test_entrypoints_pass_argv_to_run():
    for fname, _callee in ENTRYPOINTS.items():
        src = open(os.path.join(_SRC, fname)).read()
        # find the __main__ block
        idx = src.find('__name__ == "__main__"')
        assert idx != -1, f"{fname}: no __main__ block"
        main_block = src[idx:]
        # it must reference sys.argv[1] with a config.yaml fallback, not a
        # bare hardcoded "config.yaml"
        assert "sys.argv[1]" in main_block, \
            f"{fname}: __main__ does not read sys.argv[1] — config arg ignored"
        assert re.search(r'argv\[1\].*if.*len\(sys\.argv\).*>.*1.*else', main_block), \
            f"{fname}: argv[1] not guarded with a fallback"
    print("\u2713 all entrypoints read argv[1] with a config.yaml fallback")


if __name__ == "__main__":
    test_entrypoints_pass_argv_to_run()
    print("\nEntrypoint config-arg test passed.")
