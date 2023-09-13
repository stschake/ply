#include <assert.h>
#include <errno.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <ply/ply.h>
#include <ply/internal.h>
#include <ply/elfsyms.h>

#include "xprobe.h"
#include "kprobe.h"

struct uprobe {
	struct xprobe xp;
	struct elfsyms *es;
};

static struct tfield f_1arg[] = {
	{ .type = &t_void },
	{ .type = NULL }
};

struct type t_uptr_func = {
	.ttype = T_FUNC,
	.func = { .type = &t_void, .args = f_1arg },
};

static int uptr_ir_post(const struct func *func, struct node *n,
		       struct ply_probe *pb)
{
	struct node *child = n->expr.args;

	ir_init_sym(pb->ir, n->sym);
	ir_emit_sym_to_sym(pb->ir, n->sym, child->sym);
    n->sym->irs.hint.user = 1;
	return 0;
}

static int uptr_type_infer(const struct func *func, struct node *n)
{
    struct node *arg = n->expr.args;

    n->sym->type = arg->sym->type;
    return 0;
}

struct func uprobe_uptr_func = {
	.name = "uptr",
	.type = &t_uptr_func,
	.type_infer = uptr_type_infer,
	.ir_post = uptr_ir_post,
};

static int uprobe_sym_alloc(struct ply_probe *pb, struct node *n)
{
    const struct func *func = NULL;
    int err;

    if (n->ntype == N_EXPR) {
        if (is_arg_identifier(n->expr.func)) {
            func = &kprobe_arg_func;
        } else if (!strcmp(n->expr.func, "regs")) {
            func = &kprobe_regs_func;
            n->expr.ident = 1;
        } else if (!strcmp(n->expr.func, "uptr")) {
            func = &uprobe_uptr_func;
        }
    }

    if (!func)
        return -ENOENT;
    err = func_static_validate(func, n);
    if (err)
        return err;
    n->sym = sym_alloc(&pb->locals, n, func);
    if (func->static_ret)
        n->sym->type = func_return_type(func);
    return 0;
}

int uprobe_probe_type(struct ply_probe *pb, char type)
{
    struct uprobe *up;
	char *file = NULL;
	char *symbol = NULL;
	char *pattern;

	file = strchr(pb->probe, ':');
	assert(file);
	file++;
	pattern = strdup(file);
	symbol = strchr(file, ':');
	assert(symbol);
	*symbol++ = '\0';

    up = xcalloc(1, sizeof(*up));
	if (strncmp(symbol, "0x", 2)) {
		const struct symbol *elfsym;
		
		up->es = elfsyms_open(file);
		if (up->es == NULL) {
			_e("could not load symbols from file %s\n", file);
			free(up);
			return -ENOENT;
		}
		
		elfsym = elfsyms_lookup(up->es, symbol);
		if (!elfsym) {
			_e("could not resolve symbol %s in %s\n", symbol, file);
			elfsyms_free(up->es);
			free(up);
			return -ENOENT;
		}
		// we need to replace the pattern with the symbol name
		// with one that has the offset
		free(pattern);
		pattern = malloc(strlen(file) + 20);
		snprintf(pattern, strlen(file) + 20, "%s:0x%lx", file, elfsym->offset);
		_d("resolved symbol %s to offset 0x%lx\n", symbol, elfsym->offset);
	}

    up->xp.type = type;
    up->xp.ctrl_name = "uprobe_events";
    up->xp.pattern = pattern;
	// to stay compatible with the xprobe_ functions
    pb->provider_data = &up->xp;
    return 0;
}

static int uprobe_probe(struct ply_probe *pb)
{
	return uprobe_probe_type(pb, 'p');
}

struct provider uprobe = {
	.name = "uprobe",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.sym_alloc = uprobe_sym_alloc,
	.probe     = uprobe_probe,

	.attach = xprobe_attach,
	.detach = xprobe_detach,
};
