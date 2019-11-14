#include <nss.h>
#include <shadow.h>
#include <curl/curl.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include "nss_curl_conf.h"
#include "json.h"
#include "passwd.h"
#include "curl.h"

enum nss_status _nss_curl_setspent (void){
	openlog("libnss_curl shadow",LOG_PID,LOG_USER);
	if(!init_settings()) return NSS_STATUS_UNAVAIL;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_endspent (void){
	closelog();
	free_settings();
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_getspent_r (struct spwd *result, char *buffer, size_t buflen, int *errnop){
	char *json_data = NULL;
	size_t size = 0;
	static int user_count = 0;
	static int current_index = 0;
	static char *raw_data = NULL;
	static user_s *users = NULL;

	if(user_count == 0) {
		if(fetch_data(url_for("passwd"), (void **)&json_data, &size) != CURLE_OK) return NSS_STATUS_UNAVAIL;
		if(!parse_passwd(json_data, &users, &raw_data, &user_count)) return NSS_STATUS_UNAVAIL;
		if(json_data){ 
			free(json_data);
			json_data = NULL;
		}
	}

	if(current_index >= user_count) {
		free(users);
		free(raw_data);
		return NSS_STATUS_NOTFOUND;
	}

	if(buflen < users[current_index].sh_len) return NSS_STATUS_TRYAGAIN;
	memcpy(buffer, &raw_data[users[current_index].offset], users[current_index].sh_len);

	result->sp_namp = &buffer[users[current_index].data.pw_name];
	result->sp_pwdp = &buffer[users[current_index].data.pw_passwd];
	result->sp_min = 99998;
	result->sp_max = 99999;
	result->sp_warn = 0;
	result->sp_expire = -1;
	result->sp_inact = -1;
	current_index ++;

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_getspuid_r (uid_t uid, struct spwd *result, char *buffer, size_t buflen, int *errnop){
	char *json_data = NULL;
	size_t size = 0;

	int user_count = 0;
	int current_index = 0;
	char *raw_data = NULL;
	struct user *users = NULL;
	enum nss_status status_rv = NSS_STATUS_SUCCESS;

#define go_out(code) {status_rv=code; goto out;}

	if(!init_settings()) return NSS_STATUS_UNAVAIL;

	if(fetch_data(url_for("passwd"), (void **)&json_data, &size) != CURLE_OK) go_out(NSS_STATUS_UNAVAIL);
	if(!parse_passwd(json_data, &users, &raw_data, &user_count)) go_out(NSS_STATUS_UNAVAIL);
	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}

	for(int i=0; i<user_count; i++){
		if(users[i].data.pw_uid == uid){
			if(buflen < users[i].sh_len) go_out(NSS_STATUS_TRYAGAIN);
			memcpy(buffer, &raw_data[users[i].offset], users[i].sh_len);

			result->sp_namp = &buffer[users[i].data.pw_name];
			result->sp_pwdp = &buffer[users[i].data.pw_passwd];
			result->sp_min = 99998;
			result->sp_max = 99999;
			result->sp_expire = -1;
			result->sp_inact = -1;
			
			if(users) {
				free(users);
				users = NULL;
			}
			if(raw_data) {
				free(raw_data);
				users = NULL;
			}
			
			go_out(NSS_STATUS_SUCCESS);
		}
	}

	if(users) {
		free(users);
		users = NULL;
	}
	if(raw_data) {
		free(raw_data);
		users = NULL;
	}

	return NSS_STATUS_NOTFOUND;

	out:

	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}
	free_settings();
	return status_rv;
}

enum nss_status _nss_curl_getspnam_r (const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop){
	char *json_data = NULL;
	size_t size = 0;

	int user_count = 0;
	int current_index = 0;
	char *raw_data = NULL;
	struct user *users = NULL;
	enum nss_status status_rv = NSS_STATUS_SUCCESS;

#define go_out(code) {status_rv=code; goto out;}

	if(!init_settings()) return NSS_STATUS_UNAVAIL;

	if(fetch_data(url_for("passwd"), (void **)&json_data, &size) != CURLE_OK) go_out(NSS_STATUS_UNAVAIL);
	if(!parse_passwd(json_data, &users, &raw_data, &user_count)) go_out(NSS_STATUS_UNAVAIL);
	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}

	for(int i=0; i<user_count; i++){
		if(strcmp(&raw_data[users[i].offset + users[i].data.pw_name], name) == 0){
			if(buflen < users[i].sh_len) go_out(NSS_STATUS_TRYAGAIN);
			memcpy(buffer, &raw_data[users[i].offset], users[i].sh_len);

			result->sp_namp = &buffer[users[i].data.pw_name];
			result->sp_pwdp = &buffer[users[i].data.pw_passwd];
			result->sp_min = 99998;
			result->sp_max = 99999;
			result->sp_warn = 0;
			result->sp_expire = -1;
			result->sp_inact = -1;
			
			if(users) {
				free(users);
				users = NULL;
			}
			if(raw_data) {
				free(raw_data);
				users = NULL;
			}
			
			go_out(NSS_STATUS_SUCCESS);
		}
	}

	if(users) {
		free(users);
		users = NULL;
	}
	if(raw_data) {
		free(raw_data);
		users = NULL;
	}


	return NSS_STATUS_NOTFOUND;

	out:

	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}
	free_settings();
	return status_rv;
}
