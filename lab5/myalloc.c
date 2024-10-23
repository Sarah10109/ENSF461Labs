#include <stdio.h>
#include <sys/mman.h>
#include <stddef.h>
#include <unistd.h>
#include "myalloc.h"

int statusno; // Define the statusno variable to track error status

void* _arena_start; // Define the start of the memory arena
size_t _arena_size; // Define the sie of the memory arena
node_t* free_list; // Define th free list of memory blocks


/* Function to initialize the memory arena
 * size: The size of the memory arena to allocate
 * Returns the adjusted size of the memory arena or an error code */
int myinit(size_t size) {
    // Check for invalid size arguments
    if (size <= 0 || size > MAX_ARENA_SIZE) {
        statusno = ERR_BAD_ARGUMENTS;
        return statusno;
    }

    // Get the system's page size
    size_t page_size = sysconf(_SC_PAGESIZE);

    // Adjust the requested size to be a multiple of the page size
    size_t adjusted_size = (size + page_size - 1) & ~(page_size - 1);

    // Allocate memory for the arena using mmap
    _arena_start = mmap(NULL, adjusted_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (_arena_start == MAP_FAILED) {
        statusno = ERR_SYSCALL_FAILED;
        return statusno;
    }

    _arena_size = adjusted_size; // Set the size of the memory arena

    // Initialize the free list with the entire arena as a single free block
    free_list = (node_t*)_arena_start;
    free_list->size = adjusted_size - sizeof(node_t);
    free_list->is_free = 1;
    free_list->fwd = NULL;
    free_list->bwd = NULL;

    // Print initialization details
    printf("Initializing arena:\n...requested size %zu bytes\n...pagesize is %zu bytes\n...adjusting size with page boundaries\n...adjusted size is %zu bytes\n...mapping arena with mmap()\n...arena starts at %p\n...arena ends at %p\n",
           size, page_size, adjusted_size, _arena_start, _arena_start + adjusted_size);

    // Set the status to 0 (success) and return the adjusted size
    statusno = 0;
    return adjusted_size; // Return the adjusted size
}


// Function to destroy the memory arena and release resources
// Returns 0 on success, or an error code
int mydestroy() {
    // Check if the arena is uninitialized
    if (_arena_start == NULL) {
        statusno = ERR_UNINITIALIZED;
        return statusno;
    }

    // Unmap the memory arena using munmap
    if (munmap(_arena_start, _arena_size) == -1) {
        statusno = ERR_SYSCALL_FAILED;
        return statusno;
    }

    // Reset the arena start pointer and size
    _arena_start = NULL;
    _arena_size = 0;
    free_list = NULL; // Reset the free list pointer

    // Print destruction details
    printf("Destroying Arena:\n...unmapping arena with munmap()\n");

    // Set the status to 0 (success) and return 0
    statusno = 0;
    return 0;
}


/* Function to allocate memory from the arena
 * size: The size of the memory to allocate
 * Returns a pointer to the allocated memory, or NULL on failure  */
void* myalloc(size_t size) {
    // Check if the arena is uninitialized
    if (_arena_start == NULL) {
        statusno = ERR_UNINITIALIZED;
        return NULL;
    }

    // Check for invalid size arguments
    if (size <= 0) {
        statusno = ERR_BAD_ARGUMENTS;
        return NULL;
    }

    node_t* current = free_list; // Start from the beginning of the free list

    // Traverse the free list to find a suitable block
    while (current != NULL) {
        // Check if the current block is free and large enough
        if (current->is_free && current->size >= size) {
            if (current->size > size + sizeof(node_t)) {
                // If the block is larger than needed, split it
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
            // Mark the block as allocated
            current->is_free = 0;
            printf("Allocating memory:\n...allocation starts at %p\n", (void*)((char*)current + sizeof(node_t)));
            return (void*)((char*)current + sizeof(node_t));
        }
        current = current->fwd; // Move to the next block in the free list
    }

    // If no suitable block is found, return NULL
    statusno = ERR_OUT_OF_MEMORY;
    return NULL;
}


// Function to free allocated memory and coalesce free blocks
// ptr: Pointer to the memory to free
void myfree(void* ptr) {
    // Check if the supplied pointer is NULL
    if (!ptr) {
        statusno = ERR_BAD_ARGUMENTS;
        return;
    }


    // Check if the arena is uninitialized
    if (_arena_start == NULL) {
        statusno = ERR_UNINITIALIZED;
        return;
    }

    // Get the block to be freed by moving back to the start of the block header
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

    // Print details about the memory being freed
    printf("Freeing allocated memory:\n...supplied pointer %p\n", ptr);
    statusno = 0;
}
