#ifndef _NSS_CURL_CONF_H

struct settings {
	char *cache_directory;
	int cache_valid;
	char *passwd;
	char *groups;
};

typedef struct settings settings_s;

settings_s* settings();

int cache_valid_sec();
char *cache_directory();

char *url_for(char *obj);

int init_settings();
void free_settings();

#define _NSS_CURL_CONF_H
#endif
