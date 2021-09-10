# NDP trimming switch

This directory hosts the `ndp.p4` trimming switch
implementation targetting the TNA architecture. 
For more details, see our paper [Re-architecting datacenter networks and stacks for low latency and high performance](http://nets.cs.pub.ro/~costin/files/ndp.pdf).

The p4 code, table population scripts and instructions for building and running
NDP for the Tofino switch are in the `dev_root/` directory.

# How it works

To summarize, `ndp.p4` keeps an under-approximation of
the buffer occupancy for each port in ingress (by means of a
three-color meter). Whenever the meter turns red, it means
that the buffer is full and packet undergoes trimming. To achieve
that, we mark the packet to be cloned to egress and setup
the clone session to truncate the packet in such way as to
only keep the packet headers.

Since Tofino is keeping per-pipeline meter state, we may
end up in the situation where multiple ingress pipelines are
flooding a single output port without any of the meters turning
red. To solve this situation, we devise a three-level meter
strategy and make use of the Deflect-on-Drop capabilities
on the Tofino to make ingress meters trim more aggressively for
the port which is experiencing drops. After a pre-defined
interval, the meters switch to an intermediate level of trimming
and after even more time, when the incast has passed, to their original trim rate.

A more detailed description of the implementation:

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

