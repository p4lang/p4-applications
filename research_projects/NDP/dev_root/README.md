# ndp.p4

This repo contains TNA P4 code for running NDP with trimming.

* ndp.p4 contains the P4 source code
* setup_ndp.py contains the control-plane code which populates
NDP's tables
* samples/ - contains configuration samples for Tofino

## Compiling

`ndp.p4` was tested against version `9.2.0` of the Intel SDE
(formerly `bf-sde`). We assume that the following environment variables are set prior to building and running: `$SDE`, `$SDE_INSTALL`.

```
make
```
The output of this command is `$SDE_INSTALL/ndp.tofino/`

## Running
Deploying the P4 switch on hardware:
```
$SDE/run_switchd.sh -p ndp -c $SDE_INSTALL/ndp.tofino/ndp.conf
```

## Control plane
The control plane consists of the script `setup_ndp.py`
which takes as input a configuration file and populates
the entries for NDP. The current configuration is static
(i.e. no dynamic routing, no ARP etc.).

`setup_ndp.py` works in two modes:
* single-pipe: no extra CLI arguments - the input is a *single-pipe* json - it will set all tables as symmetric (see below)
* multi-pipe: requires `-multi-pipe` CLI option. Expects as input a
multi-pipe json file which consists of a dictionary where keys are
strings representing pipe_ids and values are objects with the sole
attribute "file" whose value points to the single-pipe input json
for the particular pipe_id. The *single-pipe* input format is
described below

The *single-pipe* input to `setup_ndp.py` is a json file with the following contents:
- arp - the contents of the ARP table of the switch (maps IPv4 -> MAC) - a dictionary of **arp entry** objects key IPv4 address, value MAC address
- rates - a list of **rate** objects with the following attributes:
  - eg_port - dev_port for which the following attributes apply
  - rate_kbps - int - meter speed in kbps (required)
  - burst_kbits - int - meter "buffer" (burst size) - in kBits (required)
  - shaper_rate_kbps - int - meter speed in kbps (optional: default to rate_kbps) - NB: shaper_rate_kbps = 0 ==> shaper is disabled for given port
  - shaper_burst_kbits - int - burst size of shaper (optional: defaults to shaper_burst_kbits)
  - port_speed - str - one of 10G, 25G, 40G, 50G, 100G (required)
  - port_bufsize - int
  - fec - str - one of NONE, RS (required)
- entries - a list of **entry** objects with the following attributes (all of them are required):
  - smac - source MAC of outgoing port
  - dip - destination IPv4
  - eg_port - dev_port - outgoing device port
  - nhop - IPv4 of next hop or 0 if the destination IP subnet is directly connected
- allow_pessimism - bool - optional: default True. Disables optimistic/pessimistic modes and only considers optimistic meter

## Examples

First of all, set up the PYTHONPATH
```
PYTHONPATH=$SDE_INSTALL/lib/python2.7/site-packages/:$SDE_INSTALL/lib/python2.7/site-packages/tofino
```
* multi-pipe
```
python setup_ndp.py -multi-pipe samples/multi_pipe/r1.json
```

* single-pipe
```
 python setup_ndp.py samples/single_pipe/r0_config.json
```

* troubleshooting
If running the script fails with something like `google.protobuf.internal`
not found, run the following (assuming original python site-packages is in /usr/local/lib/python2.7/site-packages)
```
cp -r /usr/local/lib/python2.7/site-packages/protobuf*/google/protobuf/ $SDE_INSTALL/lib/python2.7/site-packages/google/
```

Changing the running mode (single-pipe vs multi-pipe) between two
consecutive runs may sometimes lead to errors. If this is the case,
re-deploying ndp.p4 on the switch should solve the issue.

## How it works

Check out the original [NDP SIGCOMM'17 paper](https://dl.acm.org/doi/10.1145/3098822.3098825).

### Current implementation
 * on ingress

   0) the packet undergoes regular ipv4 forwarding with fwd decision to port egport
   1) if packet is ndp control => output packet to HIGH_PRIORITY_QUEUE
   2) if packet is ndp data => pass packet through meter[egport]

      2.1) if meter color is GREEN => output packet to LOW_PRIORITY_QUEUE

      2.2) if meter color != GREEN => clone packet to sid where (sid maps to egport, HIGH_PRIORITY_QUEUE,
          packet length = 80B)
   3) if packet is not ndp => proceed with forwarding on OTHERS_QUEUE

 * on egress:
     1) if packet is ndp data and comes in from DoD port (dropped due to congestion)
     2) when trimmed or normal packets come in => do rewrites (mac src and dst addresses) and set ndp trim flags
     3) when clone packet back to egress to sesssion esid (esid maps to recirculation port, HIGH_PRIORITY_QUEUE, packet length = 80B)
     4) when packet comes back from egress clone => forward as-is (i.e. recirculate back into ingress) and notify all pipelines
        to transition into pessimistic mode

 ### NDP modes:
 * Each egress port works in 3 modes:
   - optimistic
   - pessimistic
   - "halftimistic"

The mode decides what meter will be used for NDP packets going out on the given port

  * In optimistic, we use meter_optimistic (line-rate)

  * In pessimistic, we use meter_pessimistic (1/4 * line-rate)

  * In halftimistic, we use meter_halftimistic (1/2 * line-rate)

 Initially, the switch starts in optimistic mode for all ports.

 Whenever a DoD packet is received in egress => all ingress pipelines are notified to
 trim more aggressively (i.e. transition into pessimistic mode).

 A port remains in pessimistic mode for T0 ns if no extra DoDs occur.
 After T0 ns, the port transitions into halftimistic mode.

 A port remains in halftimistic mode for T1 ns if no other DoDs occur.
 After T1 ns, the port transitions back into optimistic mode.

 NB: T0 and T1 are hardcoded into ndp.p4 and are currently set
 to 6us and 24us respectively.