#include "vm/swap.h"
#include "threads/vaddr.h"
#include <bitmap.h>

static struct bitmap *swap_frames;

void
swap_init()
{
  swap_frames = bitmap_create(8192);
}

block_sector_t 
swap_get_sector()
{
  block_sector_t new_sector_num = bitmap_scan_and_flip (swap_frames, 0, PGSIZE / BLOCK_SECTOR_SIZE, false);
  return new_sector_num;
}

void 
swap_return_sector(block_sector_t block_num)
{
  bitmap_set_multiple(swap_frames, block_num, PGSIZE / BLOCK_SECTOR_SIZE, false);
}