# ukbpf
ubpf for unikraft

This is the initial merge of ubpf for unikraft as a proof of compile and run.

The unikraft part conists of a modified version of the test-netdev app to use the latest unikraft framework.
Especially `uk_netdev_rx_one` was adopted accordingly and the automatic buffer allocation `alloc_rxpkts` is configured as a callback.

The actual ebpf code is currently built-in as a hex array in `bpf-binary.h`
and is loaded, verified, and executed only once at the start in `main`.
In the upcoming update the execution call is to be placed into the receive call `uk_netdev_rx_one` back to make sense.
The maps integration will follow shortly.




