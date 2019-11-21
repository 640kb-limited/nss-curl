#ifndef _GROUP_H

struct grp_offset {
	int gr_name;
	int gr_passwd;
	gid_t gr_gid;
	int *gr_mem;
	int member_count;
};

struct group_data {
	struct grp_offset data;
	size_t len;
	size_t offset;
};

typedef struct group_data group_s;

#define _GROUP_H
#endif