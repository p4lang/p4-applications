# NDP trimming switch

This directory hosts the `ndp.p4` trimming switch
implementation targetting the TNA architecture. 
For more details, see our paper [Re-architecting datacenter networks and stacks for low latency and high performance](http://nets.cs.pub.ro/~costin/files/ndp.pdf).

The p4 code, table population scripts and instructions for building and running
NDP for the Tofino switch are in the `dev_root/` directory. In
[](dev_root/README.md#how-it-works), we describe the architecture and
implementation details behind `ndp.p4`. 

# How it works
To summarize, `ndp.p4` keeps an under-approximation of
the buffer occupancy for each port in ingress (by means of a
three-color meter). Whenever the meter turns red, it means
that the buffer is full and trimming follows. We mark the packet
to be cloned to egress and setup the clone session to truncate
the packet in such way as to only keep the packet headers.

Since Tofino is keeping per-pipeline meter state, we may
end up in the situation where multiple ingress pipelines are
flooding a single output port without any of the meters turning
red. To cater for this situation, we devise a three-level meter
strategy and make use of the Deflect-on-Drop capabilities
on the Tofino to make ingress meters trim more aggressively for
the port which is experiencing drops. After a pre-defined
interval (24us), the meters switch back to their original trim rate.
