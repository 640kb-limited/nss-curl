#include "passwd.h"
#include "group.h"
#include "nss_curl_conf.h"

int parse_settings(char *data, settings_s **settings_ref, char **raw_data_ref);
int parse_passwd(char *data, user_s **users_ref, char **raw_data_ref, int *user_count_rv);
int parse_group(char *data, group_s **groups_ref, char **raw_data_ref, int *group_count_rv);