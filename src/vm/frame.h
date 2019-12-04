#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "list.h"
#include "vm/page.h"
#include "devices/block.h"

struct frame_entry {
    bool is_swap;
    void *physical_address;
    struct page_entry *page;
    block_sector_t block_offset;

    struct list_elem elem;
};

void recover_swap_frame(struct frame_entry *frame);
struct frame_entry* get_new_frame(void);

#endif