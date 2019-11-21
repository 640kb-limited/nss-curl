#include <nss.h>
#include <grp.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "nss_curl_conf.h"
#include "json.h"
#include "group.h"
#include "curl.h"

enum nss_status _nss_curl_setgrent (void){
	openlog("libnss_curl group",LOG_PID,LOG_USER);
	if(!init_settings()) return NSS_STATUS_UNAVAIL;
	syslog(LOG_DEBUG, "group started");
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_endgrent (void){
	closelog();
	free_settings();
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_getgrent_r (struct group *result, char *buffer, size_t buflen, int *errnop){
	char *json_data;
	size_t size;
	static int group_count = 0;
	static int current_index = 0;
	static char *raw_data;
	static group_s *groups;

	if(group_count == 0) {
		if(fetch_data(url_for("groups"), (void **)&json_data, &size) != CURLE_OK) return NSS_STATUS_UNAVAIL;
		if(!parse_group(json_data, &groups, &raw_data, &group_count)) return NSS_STATUS_UNAVAIL;
		free(json_data);
	}

	if(current_index >= group_count) {
		free(groups);
		free(raw_data);
		return NSS_STATUS_NOTFOUND;
	}

	if(buflen < groups[current_index].len + sizeof(char *) * (groups[current_index].data.member_count + 1)) return NSS_STATUS_TRYAGAIN;
	memset(buffer, 0, buflen);
	memcpy(buffer, &raw_data[groups[current_index].offset], groups[current_index].len);

	result->gr_name = &buffer[groups[current_index].data.gr_name];
	result->gr_passwd = &buffer[groups[current_index].data.gr_passwd];
	result->gr_gid = groups[current_index].data.gr_gid;
	int payload_size = strlen(result->gr_name) + 1 + strlen(result->gr_passwd) + 1;
	for(int i = 0; i < groups[current_index].data.member_count; i++){
		char *u_name = &buffer[groups[current_index].data.gr_mem[i]];
		payload_size += strlen(u_name) + 1;
	}
	result->gr_mem = (char **)&buffer[payload_size];
	int offset = 0;
	for(int i = 0; i < groups[current_index].data.member_count; i++){
		char *u_name = &buffer[groups[current_index].data.gr_mem[i]];
		result->gr_mem[i] = u_name;
	}
	free(groups[current_index].data.gr_mem);

	current_index ++;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_getgrgid_r (gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop){
	char *json_data = NULL;
	size_t size = 0;

	int group_count = 0;
	char *raw_data = NULL;
	group_s *groups = NULL;
	enum nss_status status_rv = NSS_STATUS_SUCCESS;

#define go_out(code) {status_rv=code; goto out;}

	if(!init_settings()) return NSS_STATUS_UNAVAIL;

	if(fetch_data(url_for("groups"), (void **)&json_data, &size) != CURLE_OK) go_out(NSS_STATUS_UNAVAIL);
	if(!parse_group(json_data, &groups, &raw_data, &group_count)) go_out(NSS_STATUS_UNAVAIL);
	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}

	status_rv = NSS_STATUS_NOTFOUND;
	
	for(int i=0; i<group_count; i++){
		if(groups[i].data.gr_gid == gid){
			if(buflen < groups[i].len + sizeof(char *) * (groups[i].data.member_count + 1)) {
				go_out(NSS_STATUS_TRYAGAIN);
			}
			memset(buffer, 0, buflen);
			memcpy(buffer, &raw_data[groups[i].offset], groups[i].len);

			result->gr_name = &buffer[groups[i].data.gr_name];
			result->gr_passwd = &buffer[groups[i].data.gr_passwd];
			result->gr_gid = groups[i].data.gr_gid;
			int payload_size = strlen(result->gr_name) + 1 + strlen(result->gr_passwd) + 1;
			for(int j = 0; j < groups[i].data.member_count; j++){
				char *u_name = &buffer[groups[i].data.gr_mem[j]];
				payload_size += strlen(u_name) + 1;
			}
			result->gr_mem = (char **) &buffer[payload_size];
			int offset = 0;
			for(int j = 0; j < groups[i].data.member_count; j++){
				char *u_name = &buffer[groups[i].data.gr_mem[j]];
				result->gr_mem[j] = u_name;
			}
			result->gr_mem[groups[i].data.member_count] = NULL;

			status_rv = NSS_STATUS_SUCCESS;
		}
		free(groups[i].data.gr_mem);
	}


	out:

	if(groups) {
		free(groups);
		groups = NULL;
	}
	if(raw_data) {
		free(raw_data);
		groups = NULL;
	}
	
	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}
	free_settings();
	return status_rv;
}

enum nss_status _nss_curl_getgrnam_r (const char *name, struct group *result, char *buffer, size_t buflen, int *errnop){
	char *json_data = NULL;
	size_t size = 0;

	int group_count = 0;
	char *raw_data = NULL;
	group_s *groups = NULL;
	enum nss_status status_rv = NSS_STATUS_SUCCESS;

#define go_out(code) {status_rv=code; goto out;}

	if(!init_settings()) return NSS_STATUS_UNAVAIL;

	if(fetch_data(url_for("groups"), (void **)&json_data, &size) != CURLE_OK) go_out(NSS_STATUS_UNAVAIL);
	if(!parse_group(json_data, &groups, &raw_data, &group_count)) go_out(NSS_STATUS_UNAVAIL);
	if(json_data){
		free(json_data);
		json_data = NULL;
	}

	status_rv = NSS_STATUS_NOTFOUND;
	
	for(int i=0; i<group_count; i++){
		if(strcmp(name, &raw_data[groups[i].offset + groups[i].data.gr_name]) == 0){
			if(buflen < groups[i].len + sizeof(char *) * (groups[i].data.member_count + 1)) {
				free(groups[i].data.gr_mem);
				go_out(NSS_STATUS_TRYAGAIN);
			}
			memset(buffer, 0, buflen);
			memcpy(buffer, &raw_data[groups[i].offset], groups[i].len);

			result->gr_name = &buffer[groups[i].data.gr_name];
			result->gr_passwd = &buffer[groups[i].data.gr_passwd];
			result->gr_gid = groups[i].data.gr_gid;
			int payload_size = strlen(result->gr_name) + 1 + strlen(result->gr_passwd) + 1;
			for(int j = 0; j < groups[i].data.member_count; j++){
				char *u_name = &buffer[groups[i].data.gr_mem[j]];
				payload_size += strlen(u_name) + 1;
			}
			result->gr_mem = (char **) &buffer[payload_size];
			int offset = 0;
			for(int j = 0; j < groups[i].data.member_count; j++){
				char *u_name = &buffer[groups[i].data.gr_mem[j]];
				result->gr_mem[j] = u_name;
			}
			result->gr_mem[groups[i].data.member_count] = NULL;

			status_rv = NSS_STATUS_SUCCESS;
		}
		free(groups[i].data.gr_mem);
	}


	out:

	if(groups) {
		free(groups);
		groups = NULL;
	}
	if(raw_data) {
		free(raw_data);
		groups = NULL;
	}
	
	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}
	free_settings();
	return status_rv;
}
