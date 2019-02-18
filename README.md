# ukbpf
ubpf for unikraft

This is the initial merge of ubpf for unikraft as a proof of compile and run.

The unikraft part conists of a modified version of the test-netdev app to use the latest unikraft framework.
Especially `uk_netdev_rx_one` was adopted accordingly and the automatic buffer allocation `alloc_rxpkts` is configured as a callback.

The actual ebpf code is currently built-in as a hex array in `bpf-binary.h`
and is loaded and verified at the start in `main`, and executed for each incoming pkt
in the receive call `uk_netdev_rx_one`.
The maps integration and the corresponding relocation when loading the elf will follow shortly.




