#include <stdio.h>
#include <sys/mman.h>
#include <stddef.h>
#include <unistd.h>
#include "myalloc.h"

int statusno; // Define the statusno variable

void* _arena_start;
size_t _arena_size;
node_t* free_list;

int myinit(size_t size) {
    if (size <= 0 || size > MAX_ARENA_SIZE) {
        statusno = ERR_BAD_ARGUMENTS;
        return statusno;
    }

    size_t page_size = sysconf(_SC_PAGESIZE);

    // Adjust the requested size to be a multiple of the page size
    size_t adjusted_size = (size + page_size - 1) & ~(page_size - 1);

    _arena_start = mmap(NULL, adjusted_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (_arena_start == MAP_FAILED) {
        statusno = ERR_SYSCALL_FAILED;
        return statusno;
    }

    _arena_size = adjusted_size;

    // Initialize the free list
    free_list = (node_t*)_arena_start;
    free_list->size = adjusted_size - sizeof(node_t);
    free_list->is_free = 1;
    free_list->fwd = NULL;
    free_list->bwd = NULL;

    printf("Initializing arena:\n...requested size %zu bytes\n...pagesize is %zu bytes\n...adjusting size with page boundaries\n...adjusted size is %zu bytes\n...mapping arena with mmap()\n...arena starts at %p\n...arena ends at %p\n",
           size, page_size, adjusted_size, _arena_start, _arena_start + adjusted_size);

    statusno = 0;
    return adjusted_size; // Return the adjusted size
}


int mydestroy() {
    if (_arena_start == NULL) {
        statusno = ERR_UNINITIALIZED;
        return statusno;
    }

    if (munmap(_arena_start, _arena_size) == -1) {
        statusno = ERR_SYSCALL_FAILED;
        return statusno;
    }

    _arena_start = NULL;
    _arena_size = 0;
    free_list = NULL;

    printf("Destroying Arena:\n...unmapping arena with munmap()\n");

    statusno = 0;
    return 0;
}


void* myalloc(size_t size) {
    if (_arena_start == NULL) {
        statusno = ERR_UNINITIALIZED;
        return NULL;
    }

    if (size <= 0) {
        statusno = ERR_BAD_ARGUMENTS;
        return NULL;
    }

    node_t* current = free_list;
    while (current != NULL) {
        if (current->is_free && current->size >= size) {
            if (current->size > size + sizeof(node_t)) {
                // Split the block
                node_t* new_node = (node_t*)((char*)current + sizeof(node_t) + size);
                new_node->size = current->size - size - sizeof(node_t);
                new_node->is_free = 1;
                new_node->fwd = current->fwd;
                new_node->bwd = current;

                if (current->fwd != NULL) {
                    current->fwd->bwd = new_node;
                }

                current->fwd = new_node;
                current->size = size;
            }
            current->is_free = 0;
            printf("Allocating memory:\n...allocation starts at %p\n", (void*)((char*)current + sizeof(node_t)));
            return (void*)((char*)current + sizeof(node_t));
        }
        current = current->fwd;
    }

    statusno = ERR_OUT_OF_MEMORY;
    return NULL;
}

void myfree(void* ptr) {
    if (!ptr) {
        statusno = ERR_BAD_ARGUMENTS;
        return;
    }

    if (_arena_start == NULL) {
        statusno = ERR_UNINITIALIZED;
        return;
    }

    node_t* current = (node_t*)((char*)ptr - sizeof(node_t));
    current->is_free = 1;

    // Coalesce with next block if it's free
    if (current->fwd != NULL && current->fwd->is_free) {
        current->size += sizeof(node_t) + current->fwd->size;
        current->fwd = current->fwd->fwd;
        if (current->fwd != NULL) {
            current->fwd->bwd = current;
        }
    }

    // Coalesce with previous block if it's free
    if (current->bwd != NULL && current->bwd->is_free) {
        current->bwd->size += sizeof(node_t) + current->size;
        current->bwd->fwd = current->fwd;
        if (current->fwd != NULL) {
            current->fwd->bwd = current->bwd;
        }
    }

    printf("Freeing allocated memory:\n...supplied pointer %p\n", ptr);
    statusno = 0;
}
