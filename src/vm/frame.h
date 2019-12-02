#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "list.h"
#include "vm/page.h"

struct frame_entry {
    size_t uid;
    bool is_accessed;
    struct page_entry *page;

    void *physical_address;
    struct list_elem elem;
};

struct frame_entry* get_new_frame(void);

#endif