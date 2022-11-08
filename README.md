# CloudVision Portal to Arista Test Cloud Exporter
This script allows your topology and node information to exported from either an on-prem or CVaaS instance of CloudVision Portal to a YAML file that can be imported into Arista Test Cloud.

The generated topology file will match the CVP release to that of the cvp release it was exported from. Likewise the software release will be matched per node.

Any nodes identified, that are not in the CVP inventory will be created as generic linux devices

## How to use
The defaults are reasonbly sensible, but you mist provide either an API `--token` (mandatory for CVaaS), or a `--username` for authentication. On-premises CVP can also use API tokens but this is not mandatory. 

If the `--password` is not provided you will be prompted

Script arguments:
```
  -h, --help            show this help message and exit
  -t, --test            If --test is set, we will not connect to CVP but instead try and use local json files as our
                        source data. Disabled by default.
  --export              Store the responses from CVP as json data locally, for later testing. Disabled by default.
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Output file name, default is: generated_act_topology.yaml
  --streaming           Only add nodes that are actively streaming from the CVP inventory. Any nodes (and their links)
                        that are not streaming, will not be created. Disabled by default.
  --create-generic      If there are non-CVP nodes whose presence is inferred from the link data, create them as
                        generic linux hosts. *Enabled* by default
  -u USERNAME, --username USERNAME
                        username if using on-prem user accounts
  --token TOKEN         API token, required if on CVaaS
  --cvp CVP             Hostname(s) or IP(s) of the CVP instance to connect to
  -p PASSWORD, --password PASSWORD
                        Password for connecting to CVP, when not using API tokens
```

### Sample Output
```yaml
cvp:
  username: root
  password: cvproot
  version: 2021.3.1
  instance: singleinstance

generic:
  version: CentOS-8-8.2.2004
  username: ansible
  password: ansible

nodes:
- do398:
    ip_addr: 192.168.0.7
    node_type: veos
    version: 4.28.1F
    neighbors: []
- hs319:
    ip_addr: 192.168.0.8
    node_type: veos
    version: 4.25.6M
    neighbors:
    - neighborDevice: AVD-LEAF3A
      neighborPort: Ethernet1
      port: Ethernet1
    - neighborDevice: AVD-LEAF3A
      neighborPort: Ethernet2
      port: Ethernet2
- ld357:
    ip_addr: 192.168.0.9
    node_type: veos
    version: 4.23.6M
    neighbors: []
```

## Caveats (READ THIS SECTION)
* The management IPs are updated to match the pool required within Arista Test Cloud [ATC] (192.168.0.0/24)
* QSFP, broken out ports, or Modular system ports e.g. `Ethernet25/1`, `Ethernet6/23/1` are not remapped to flat interfaces e.g. `Ethernet55`

# TODO
* Check exactly the reserved IPs within ATC managemnet network that are in use for services
* Remap interfaces until ACT supports `Arbitrary Interface Mapping on vEOS & cEOS - RFE 552331`