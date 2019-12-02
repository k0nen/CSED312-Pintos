#include "page.h"
#include "threads/thread.h"

static unsigned 
page_hash_hash_func(const struct hash_elem *element, void *aux)
{
    struct page_entry *entry = hash_entry(element, struct page_entry, hash);
    return hash_int((int) entry->virtual_address);
}

static bool 
page_hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
    struct page_entry *page1 = hash_entry(a, struct page_entry, hash);
    struct page_entry *page2 = hash_entry(b, struct page_entry, hash);

    return page1->virtual_address < page2->virtual_address;
}

void
page_table_init()
{
    hash_init(&thread_current()->page_table, page_hash_hash_func, page_hash_less_func, NULL);
}