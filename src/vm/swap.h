#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"

void swap_init(void);
block_sector_t swap_get_sector(void);
void swap_return_sector(block_sector_t);

#endif