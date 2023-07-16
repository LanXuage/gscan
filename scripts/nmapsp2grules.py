#!/bin/env python3

import re
import io
import requests

# https://nmap.org/book/vscan-fileformat.html
nmap_service_probe_download_url = (
    "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes"
)

resp = requests.get(url=nmap_service_probe_download_url)

data = io.BytesIO(resp.content)

probes = {
    "TCP": [],
    "UDP": [],
}

probe_key = None
probe_name = None
for l in data.readlines():
    l = l.strip()
    if not l or l.startswith(b"#"):
        continue
    if l.startswith(b"Probe"):
        m = re.search(rb"Probe\s+?(TCP|UDP)\s+?(\w+?)\s", l)
        if m != None:
            probe_key = m.group(1).decode()
            probe_name = m.group(2).decode()
    elif l.startswith(b"match"):
        complex_key = "{} {}".format(probe_key, probe_name)
        tmp = probes.get(complex_key)
        if tmp == None:
            probes[complex_key] = [l]
        else:
            tmp.append(l)

for k, v in probes.items():
    print(k, len(v))

# for l in probes["TCP NULL"]:
    # print(l)
