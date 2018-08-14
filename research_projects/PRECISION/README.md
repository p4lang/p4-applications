# Reference Implementation of the PRECISION heavy-hitter algorithm

This dirctory hosts a reference implementation of PRECISION algorithm running on the BMV2 v1model.

See our paper [Efficient Measurement on Programmable Switches Using Probabilistic Recirculation](https://arxiv.org/abs/1808.03412) for more details regarding the design and evaluation of PRECISION.

## Goal

PRECISION algorithm attempts to maintain packet counters for heavy-hitter flows, by recording several "heavy-hitter flow tables" (register arrays). Each pair of register arrays contains pairs of `(flow ID, packet Count)`. A packet will inspect one location in each array, similar to what happens in Counting Bloom Filter / HashPipe.

When a packet arrives, if it belongs to a heavy flow that's already tracked in one of the register array, we simply increment the counter. Otherwise, we locate an entry in the array that has a small count, and probabilistically replace that entry using packet recirculation. We expect packets from new heavy flows will arrive over and over again and will eventually be tracked.

This demo maintains d=3 tables using 6 register arrays. Depending on hardware capability, actual implementaion may include 2 to 8 tables.


## How to run
TODO: we may want to adopt the makefile from P4 tutorials to make running experiment easier (e.g. `make run`).

This example uses SrcIP/DstIP pair as flow ID, but you're more than welcome to change to other flow ID definition.

The program does not incldue routing logic and will act as a repeater or reflector. You may add your own forwarding logic in the ingress pipeline.

## Where's the measurement result?
It's in the Source MAC Address of ethernet header. You may also pull the latest statistics from the register arrays.

For the untracked flows, the estimated flow size is always zero. (See paper for more detail.)

## Contact & Citations

If you use PRECISION in your research, please cite:

	@article{Ran2018,
		author = {Ran Ben Basat and Xiaoqi Chen and Gil Einziger and Ori Rottenstreich},
		title = {Efficient Measurement on Programmable Switches Using Probabilistic Recirculation},
		journal = {arXiv preprint arXiv:1808.03412},
		year = {2018}
	}


Authors of PRECISION algorithm:
- Ran Ben Basat, Technion
- Xiaoqi Chen, Princeton
- Gil Einziger, Nokia Bell Labs
- Ori Rottenstreich, Technion

For technical questions regarding the P4 implementation, please contact Xiaoqi Chen at `xiaoqic at cs dot princeton dot edu`.
