#include <ply/elfsyms.h>
#include <ply/ply.h>
#include <ply/utils.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <elf.h>

#if ULONG_MAX == 0xffffffff
typedef Elf32_Ehdr Ehdr;
typedef Elf32_Shdr Shdr;
typedef Elf32_Nhdr Nhdr;
typedef Elf32_Sym Sym;
#else
typedef Elf64_Ehdr Ehdr;
typedef Elf64_Shdr Shdr;
typedef Elf64_Nhdr Nhdr;
typedef Elf64_Sym Sym;
#endif

static int symbol_cmp(const void *a, const void *b)
{
	const struct symbol *syma = a;
    const struct symbol *symb = b;

	return strcmp(syma->name, symb->name);
}

const struct symbol *elfsyms_lookup(struct elfsyms* es, const char *name)
{
    struct symbol key = { .name = name };

    if (!es || !es->symbols || !es->nsymbols)
        return NULL;
    
    return bsearch(&key, es->symbols, es->nsymbols, sizeof(struct symbol), symbol_cmp);
}

static void read_build_id(struct elfsyms *es, const Shdr *note)
{
    const Nhdr *data = es->data + note->sh_offset;
    const uint8_t *id;
    size_t i;

    if (data->n_descsz != 20 || data->n_namesz != 4 || data->n_type != NT_GNU_BUILD_ID)
        return;

    id = es->data + note->sh_offset + sizeof(Nhdr) + 4;
    es->build_id = xcalloc(1, 2*20 + 1);
    for (i = 0; i < 20; i++)
        sprintf(es->build_id + (i*2), "%02x", id[i]);
    _d("elf build id: %s\n", es->build_id);
}

static int read_symbols_table(struct elfsyms *es, const Shdr *symtab,
                const Shdr *strtab)
{
    const Sym *syms = es->data + symtab->sh_offset;
    const char *strs = es->data + strtab->sh_offset;
    const size_t nsyms = symtab->sh_size / sizeof(Sym);
    size_t i;

    es->symbols = xcalloc(nsyms, sizeof(struct symbol));
    for (i = 0; i < nsyms; i++) {
        const Sym *sym = syms + i;
        struct symbol *res;
        
        if (!sym->st_name || !sym->st_value || !sym->st_size)
            continue;
        res = es->symbols + es->nsymbols++;
        res->name = strs + sym->st_name;
        res->offset = sym->st_value;
        res->size = sym->st_size;
    }

    return 0;
}

static int read_symbols(struct elfsyms *es)
{
    const Ehdr *hdr = es->data;
    int ret = 0;
    const Shdr *dynsym = NULL, *dynstr = NULL;
    const Shdr *symtab = NULL, *strtab = NULL;
    const Shdr *shstrtab;
    size_t i;

    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG))
        return -EINVAL;
    if (sizeof(Shdr) != hdr->e_shentsize)
        return -EINVAL;

    shstrtab = es->data + hdr->e_shoff + (hdr->e_shstrndx * hdr->e_shentsize);
    for (i = 0; i < hdr->e_shnum; i++) {
        const Shdr *shdr = es->data + hdr->e_shoff + (i * hdr->e_shentsize);
        const char *sname = es->data + shstrtab->sh_offset + shdr->sh_name;

        if (shdr->sh_type == SHT_DYNSYM) {
            dynsym = shdr;
        } else if (shdr->sh_type == SHT_SYMTAB) {
            symtab = shdr;
        } else if (shdr->sh_type == SHT_STRTAB) {
            if (strcmp(sname, ".dynstr") == 0)
                dynstr = shdr;
            else if (strcmp(sname, ".strtab") == 0)
                strtab = shdr;
        } else if (shdr->sh_type == SHT_NOTE) {
            if (strcmp(sname, ".note.gnu.build-id") == 0)
                read_build_id(es, shdr);
        }
    }
    
    if (symtab && strtab)
        ret = read_symbols_table(es, symtab, strtab);
    else if (dynsym && dynstr)
        ret = read_symbols_table(es, dynsym, dynstr);

    if (!ret && es->nsymbols) {
        qsort(es->symbols, es->nsymbols, sizeof(struct symbol), symbol_cmp);
    }
    return ret;
}

struct elfsyms *elfsyms_open(const char *file)
{
    struct elfsyms *es;
    struct stat st;

    _d("opening elf %s\n", file);
    if (stat(file, &st))
        return NULL;

    es = xcalloc(1, sizeof(*es));
    es->fd = open(file, O_RDONLY);
    es->size = st.st_size;
    if (es->fd < 0)
        goto err;
    es->data = mmap(NULL, es->size, PROT_READ, MAP_SHARED, es->fd, 0);
    if (es->data == MAP_FAILED)
        goto err;

    if (read_symbols(es))
        goto err;
    return es;

    err:
    if (es->data)
        munmap(es->data, es->size);
    if (es->fd)
        close(es->fd);
    free(es);
    return NULL;
}

void elfsyms_free(struct elfsyms* es)
{
    munmap(es->data, es->size);
    close(es->fd);
    free(es);
}
