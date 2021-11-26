#ifndef VM_SWAP_H
#define VM_SWAP_H
typedef uint32_t swap_index_t;
void vm_swap_init(void);
void vm_swap_free(swap_index_t swap_index);
void vm_swap_in(swap_index_t swap_index, void *page);
swap_index_t vm_swap_out(void *page);
#endif

