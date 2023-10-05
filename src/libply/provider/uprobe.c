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

struct stack_priv {
	struct ksyms *ks;
	struct sym *sym;

	uint64_t bt[0];
};

static int stack_fprint(struct type *t, FILE *fp, const void *data)
{
	struct stack_priv *sp = t->priv;
	uint32_t stackid = *(uint32_t *)data;
	size_t i;

	if (bpf_map_lookup(sp->sym->mapfd, &stackid, sp->bt))
		return fprintf(fp, "<STACKID%u>", stackid);

	fputc('\n', fp);
	for (i = 0; i < ply_config.stack_depth; i++) {
		if (!sp->bt[i])
			break;

		fputc('\t', fp);
		int w = (int)(sizeof(uintptr_t) * 2);
		fprintf(fp, "<%*.*"PRIxPTR">", w, w, (uintptr_t)sp->bt[i]);
		fputc('\n', fp);
	}

	return 0;
}

static struct type t_stackid_t = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.type = &t_u32,
		.name = ":stackid",
	},

	.fprint = stack_fprint,
};

static struct func stackmap_func = {
	.name = ":stackmap",
};

// TODO use get_stack function with buildid + use mem_type_infer for array with ply_config.stack_depth size!
// see also str_ir_post

static int stack_ir_post(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	struct node *ctx, *map;

	ctx = n->expr.args;
	map  = ctx->next;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_sym_to_reg(pb->ir, BPF_REG_1, ctx->sym);
	ir_emit_ldmap(pb->ir, BPF_REG_2, map->sym);
	ir_emit_insn(pb->ir, MOV_IMM(BPF_F_USER_STACK), BPF_REG_3, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_stackid), 0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int stack_rewrite(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	struct node *nmap;
	struct type *tarray, *tmap;
	struct stack_priv *sp;
	size_t depth;

	if (n->expr.args)
		return 0;

	nmap = node_expr_ident(&n->loc, ":stackmap");
	nmap->sym = sym_alloc(&pb->ply->globals, nmap, &stackmap_func);

	if (!nmap->sym->type) {
		/* This is the first reference of `stack`, we need to
		 * setup associated the map and allocate space to hold
		 * a single backtrace to later in stack_fprint(). */
		tarray = type_array_of(&t_u64, ply_config.stack_depth);
		tmap = type_map_of(&t_u32, tarray, BPF_MAP_TYPE_STACK_TRACE, 0);
		nmap->sym->type = tmap;

		sp = xcalloc(1, sizeof(*sp) + type_sizeof(tarray));
		sp->ks = pb->ply->ksyms;
		sp->sym = nmap->sym;
		n->sym->type->priv = sp;
	}

	node_expr_append(&n->loc, n, node_expr_ident(&n->loc, "ctx"));
	node_expr_append(&n->loc, n, nmap);

	return 1;
}

static struct func uprobe_stack_func = {
	.name = "stack",
	.type = &t_stackid_t,
	.static_ret = 1,

	.rewrite = stack_rewrite,
	.ir_post = stack_ir_post,
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
        } else if (!strcmp(n->expr.func, "stack")) {
			func = &uprobe_stack_func;
			n->expr.ident = 1;
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
