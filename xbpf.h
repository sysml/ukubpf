
extern struct ubpf_vm *ebpf_vm;

extern struct xbpf_map xbpf_map;

void show_stats();
struct ubpf_vm * do_prepare_ebpf();
int do_exec_ebpf(struct ubpf_vm *vm, void *mem, size_t mem_len);
int fix_ip_checksum(void* vdata, size_t length);
