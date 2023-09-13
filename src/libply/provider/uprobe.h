#ifndef _PLY_PROVIDER_UPROBE_H
#define _PLY_PROVIDER_UPROBE_H

#include <ply/ply.h>

extern const struct func uprobe_uptr_func;

/* probe either a normal (type 'p') or return probe (type 'r')*/
int uprobe_probe_type(struct ply_probe *pb, char type);

#endif	/* _PLY_PROVIDER_UPROBE_H */
