#include "passwd.h"
#include "nss_curl_conf.h"

int parse_settings(char *data, settings_s **settings_ref, char **raw_data_ref);
int parse_passwd(char *data, user_s **users_ref, char **raw_data_ref, int *user_count_rv);