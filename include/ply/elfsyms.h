#ifndef __ELFSYMS_H
#define __ELFSYMS_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct symbol {
    const char *name;
    intptr_t offset;
    size_t size;
};

struct elfsyms {
    int fd;
    void *data;
    off_t size;
    char *build_id;

    struct symbol *symbols;
    size_t nsymbols;
};

const struct symbol *elfsyms_lookup(struct elfsyms* es, const char *name);
struct elfsyms *elfsyms_open(const char *file);
void elfsyms_free(struct elfsyms* elf);

#endif	/* __ELFSYMS_H */
