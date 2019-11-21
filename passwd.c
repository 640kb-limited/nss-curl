#include <nss.h>
#include <pwd.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "nss_curl_conf.h"
#include "json.h"
#include "passwd.h"
#include "curl.h"

enum nss_status _nss_curl_setpwent (void){
	openlog("libnss_curl passwd",LOG_PID,LOG_USER);
	if(!init_settings()) return NSS_STATUS_UNAVAIL;
	syslog(LOG_DEBUG, "passwd started");
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_endpwent (void){
	closelog();
	free_settings();
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_getpwent_r (struct passwd *result, char *buffer, size_t buflen, int *errnop){
	char *json_data;
	size_t size;
	static int user_count = 0;
	static int current_index = 0;
	static char *raw_data;
	static user_s *users;

	if(user_count == 0) {
		if(fetch_data(url_for("passwd"), (void **)&json_data, &size) != CURLE_OK) return NSS_STATUS_UNAVAIL;
		if(!parse_passwd(json_data, &users, &raw_data, &user_count)) return NSS_STATUS_UNAVAIL;
		free(json_data);
	}

	if(current_index >= user_count) {
		free(users);
		free(raw_data);
		return NSS_STATUS_NOTFOUND;
	}

	if(buflen < users[current_index].len) return NSS_STATUS_TRYAGAIN;
	memcpy(buffer, &raw_data[users[current_index].offset], users[current_index].len);

	result->pw_name = &buffer[users[current_index].data.pw_name];
	result->pw_passwd = &buffer[users[current_index].data.pw_passwd];
	result->pw_uid = users[current_index].data.pw_uid;
	result->pw_gid = users[current_index].data.pw_gid;
	result->pw_gecos = &buffer[users[current_index].data.pw_gecos];
	result->pw_shell = &buffer[users[current_index].data.pw_shell];
	result->pw_dir = &buffer[users[current_index].data.pw_dir];

	current_index ++;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_curl_getpwuid_r (uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop){
	char *json_data = NULL;
	size_t size = 0;

	static int user_count = 0;
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
			if(buflen < users[i].len) go_out(NSS_STATUS_TRYAGAIN);
			memcpy(buffer, &raw_data[users[i].offset], users[i].len);
			result->pw_name = &buffer[users[i].data.pw_name];
			result->pw_passwd = &buffer[users[i].data.pw_passwd];
			result->pw_uid = users[i].data.pw_uid;
			result->pw_gid = users[i].data.pw_gid;
			result->pw_gecos = &buffer[users[i].data.pw_gecos];
			result->pw_shell = &buffer[users[i].data.pw_shell];
			result->pw_dir = &buffer[users[i].data.pw_dir];

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

	free_settings();

	return NSS_STATUS_NOTFOUND;

	out:
	
	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}
	free_settings();
	return status_rv;
}

enum nss_status _nss_curl_getpwnam_r (const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop){
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
		if(strcmp(name, &raw_data[users[i].offset + users[i].data.pw_name]) == 0){
			if(buflen < users[i].len) go_out(NSS_STATUS_TRYAGAIN);
			memcpy(buffer, &raw_data[users[i].offset], users[i].len);

			result->pw_name = &buffer[users[i].data.pw_name];
			result->pw_passwd = &buffer[users[i].data.pw_passwd];
			result->pw_uid = users[i].data.pw_uid;
			result->pw_gid = users[i].data.pw_gid;
			result->pw_gecos = &buffer[users[i].data.pw_gecos];
			result->pw_shell = &buffer[users[i].data.pw_shell];
			result->pw_dir = &buffer[users[i].data.pw_dir];

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
	free_settings();

	return NSS_STATUS_NOTFOUND;

	out:
	
	if(json_data){ 
		free(json_data);
		json_data = NULL;
	}
	free_settings();
	return status_rv;
}
