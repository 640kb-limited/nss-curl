#ifndef _PASSWD_H

struct passwd_offset {
	int pw_name;
	int pw_passwd;
	uid_t pw_uid;
	gid_t pw_gid;
	time_t pw_change;
	int pw_class;
	int pw_gecos;
	int pw_dir;
	int pw_shell;
	time_t pw_expire;
};

struct user {
	struct passwd_offset data;
	size_t len;
	size_t sh_len;
	size_t offset;
};

typedef struct user user_s;

#define _PASSWD_H
#endif