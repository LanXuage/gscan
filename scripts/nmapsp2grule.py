#!/bin/env python3
import re
import io
import json
import requests 

nmap_service_probe_download_url = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes"

resp = requests.get(url=nmap_service_probe_download_url)
data = io.BytesIO(resp.content)

i = 0
j = 0
probes = {
    "Probe TCP": [],
    "Probe UDP": []
}
probe_key = None
r1 = re.compile(rb"(match)\s+?([\w\-\/\.]*?)\s+?(m(?:\|.+?\||=.+?=|%.+?%|\/.+?\/)[si]?)(.*?$)")
r2 = re.compile(rb"([piho]|cpe:)(\|.+?\||=.+?=|%.+?%|\/.+?\/)(a)?")
rules = []
for l in data.readlines():
    l = l.strip()
    if l.startswith(b"#") or not l:
        continue
    if probe_key and l.startswith(b"match"):
        i += 1
        # print(l)
        m = r1.search(l)
        if m:
            j += 1
            mre = m.group(3).decode()
            if mre[0] != "m":
                continue
            precursor = mre[1]
            if mre[-1] == mre[1]:
                mre = mre[2:-1]
            elif mre[-1] == "i":
                tmp = ""
                preb = ""
                for b in mre[2:-2]:
                    if b in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" and preb != "\\":
                        tmp += "[" + b.lower() + b.upper() + "]"
                    else:
                        tmp += b
                mre = tmp
            elif mre[-1] == "s":
                mre = mre[2:-2].replace(".", "(?:.|\n)")
            match_rule = {
                "protocol": m.group(2).decode(),
                "match": mre,
            }
            # print(m.groups())
            if m.group(4) != None:
                for p in r2.findall(m.group(4)):
                    if p[0] == b"p":
                        match_rule["product"] = p[1].decode().strip("/").strip("|").strip("%")
                    else:
                        match_rule[p[0].decode().strip(":")] = p[1].decode().strip("/").strip("|").strip("%")
            print(match_rule)
            rules.append(match_rule)
        else:
            print("###", l)
    if l.startswith(b"Probe TCP NULL"):
        probe_key = True
    elif l.startswith(b"Probe"):
        break

with open('rules.json', 'w') as f:
    json.dump(rules, f)
print(i)
print(j)

