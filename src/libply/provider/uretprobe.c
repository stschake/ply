#include "uprobe.h"
#include "xprobe.h"
#include "kprobe.h"
#include "kretprobe.h"

#include <errno.h>
#include <string.h>

#include <ply/internal.h>

static int uretprobe_sym_alloc(struct ply_probe *pb, struct node *n)
{
    const struct func *func = NULL;
    int err;

    if (n->ntype == N_EXPR) {
        if (is_arg_identifier(n->expr.func)) {
            func = &kprobe_arg_func;
        } else if (!strcmp(n->expr.func, "regs")) {
            func = &kprobe_regs_func;
            n->expr.ident = 1;
        } else if (!strcmp(n->expr.func, "retval")) {
            func = &kretprobe_retval_func;
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

static int uretprobe_probe(struct ply_probe *pb)
{
	return uprobe_probe_type(pb, 'r');
}

struct provider uretprobe = {
	.name = "uretprobe",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.sym_alloc = uretprobe_sym_alloc,
	.probe     = uretprobe_probe,

	.attach = xprobe_attach,
	.detach = xprobe_detach,
};
