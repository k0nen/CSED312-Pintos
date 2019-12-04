#include "frame.h"
#include "threads/thread.h"
#include "threads/palloc.h"

struct frame_entry* 
get_new_frame()
{
    struct thread *t = thread_current();
    struct frame_entry *new_frame;

    new_frame = malloc(sizeof(struct frame_entry));
    new_frame->is_accessed = true;
    new_frame->physical_address = palloc_get_page(PAL_USER);

    list_push_back(&t->frames, &new_frame->elem);

    return new_frame;
}