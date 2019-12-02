#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"
#include "filesys/off_t.h"

struct frame_entry;

struct page_entry {
    void *virtual_address;
    struct frame_entry *frame;

    bool is_swap;
    bool is_writable;
    bool is_pinned;
    
    struct hash_elem hash;
    
    struct file *file;
    off_t file_offset;

    size_t zero_bytes;
};

void page_table_init(void);

#endif