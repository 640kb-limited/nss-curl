#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include "json.h"
#include "nss_curl_conf.h"

settings_s *settings_data = NULL;
char *raw_data = NULL;
char null = '\0';

int cache_valid_sec(){
	if(settings_data == NULL) return 0;
	return settings_data->cache_valid;
}

char *cache_directory(){
	if(settings_data == NULL) return &null;
	return settings_data->cache_directory;
}

char *url_for(char *obj){
	if(strcmp(obj, "passwd") == 0) return settings_data->passwd;
	if(strcmp(obj, "groups") == 0) return settings_data->groups;
	if(strcmp(obj, "cache_directory") == 0) return settings_data->cache_directory;
	return "";
}

int init_settings(){
	FILE *file = fopen("/etc/nss_curl.conf", "r");
	if(!file) {
		syslog(LOG_DEBUG, "Can not open /etc/nss_curl.conf");
		return 0;
	}
	size_t total_bytes = 0;
	size_t chunk_size = 32*8192;
	char *data = NULL;
	
	while(!feof(file)){
		data = realloc(data, total_bytes + chunk_size);
		size_t count = fread(data + total_bytes, 1, chunk_size, file);
		total_bytes += count;
		if(count < chunk_size) {
			data = realloc(data, total_bytes + 1);
		}
		memset(data + total_bytes, 0, 1);
	}
	
	fclose(file);
	if(total_bytes) {
		parse_settings(data, &settings_data, &raw_data);
		if(!settings_data) {
			syslog(LOG_DEBUG, "Can not parse settings");
			return 0;
		};
		free(data);
		return 1;
	} else {
		if(data) free(data);
		return 0;
	}
}

void free_settings(){
	if(settings_data) free(settings_data);
	if(raw_data) free(raw_data);
	settings_data = NULL;
	raw_data = NULL;
}

