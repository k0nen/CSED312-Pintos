#include "frame.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include <string.h>

static struct frame_entry*
select_evicted_frame(struct frame_entry *dest)
{
  struct list *list = &thread_current()->frames;
  struct list_elem *here;
  for(here = list_back(list);; here = list_prev(here))
  {
    struct frame_entry *evicted_frame = list_entry(here, struct frame_entry, elem);
    if(!evicted_frame->is_swap && evicted_frame != dest)
    {
      return evicted_frame;
    }

    if(here == list_front(list))
      break;
  }

  return NULL;
}

static void 
eviction(struct frame_entry *frame)
{
  struct thread *t = thread_current();
  struct block *swap = block_get_role(BLOCK_SWAP);
  struct frame_entry *evicted_frame = select_evicted_frame(frame);

  // printf("evicted frame %p\n", evicted_frame);
  ASSERT(evicted_frame != NULL);
  ASSERT(!evicted_frame->is_swap);

  frame->physical_address = evicted_frame->physical_address;
  evicted_frame->is_swap = true;
  evicted_frame->page->is_dirty = pagedir_is_dirty(t->pagedir, evicted_frame->page->virtual_address);

  if(!frame->is_swap)
  {
    evicted_frame->block_offset = swap_get_sector();
  }
  else
  {
    evicted_frame->block_offset = frame->block_offset;
    frame->block_offset = -1;
    frame->is_swap = false;
  }

  void *temp = palloc_get_page(PAL_ZERO | PAL_ASSERT);

  for(int i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
  {
    off_t offset = i * BLOCK_SECTOR_SIZE;
    block_read(swap, evicted_frame->block_offset + i, temp + offset);
    block_write(swap, evicted_frame->block_offset + i, frame->physical_address + offset);
  }  

  memcpy(frame->physical_address, temp, PGSIZE);

  evicted_frame->physical_address = NULL;
  evicted_frame->page->is_swap = true;  
  palloc_free_page(temp);
  pagedir_clear_page(t->pagedir, evicted_frame->page->virtual_address);
}

void 
recover_swap_frame(struct frame_entry *frame)
{
  ASSERT(frame != NULL);
  ASSERT(frame->is_swap);

  eviction(frame);
  frame->page->is_swap = false;
}

struct frame_entry* 
get_new_frame()
{
  struct thread *t = thread_current();
  struct frame_entry *new_frame;

  new_frame = malloc(sizeof(struct frame_entry));
  new_frame->is_swap = false;
  new_frame->page = NULL;
  new_frame->block_offset = -1;
  new_frame->physical_address = palloc_get_page(PAL_USER);
  list_push_back(&t->frames, &new_frame->elem);

  if(new_frame->physical_address == NULL)
  {
    eviction(new_frame);
  }

  return new_frame;
}