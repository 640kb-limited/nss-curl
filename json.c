#include <jansson.h>
#include <syslog.h>
#include <string.h>
#include "json.h"

int parse_passwd(char *data, user_s **users_ref, char **raw_data_ref, int *user_count_rv){
	json_t *root;
	json_error_t error;
	char res = 0;
	int user_count = 0;
	user_s *users = NULL;
	char *raw_data = NULL;

	root = json_loads(data, 0, &error);
	if(!root){
		res = -1;
		syslog(LOG_DEBUG,"Passwd JSON parse failed: %s", error.text);
		return 0;
	} else {
		if(!json_is_array(root)){
			res = -1;
			json_decref(root);
			syslog(LOG_DEBUG,"Passwd JSON top level entity should be an array");
			return 0;
		} else {
			int list_size = json_array_size(root);
			int total_raw_size = 0;
			for(int i = 0; i < list_size; i++){
				json_t *data = json_array_get(root, i);
				if(json_is_object(data)){
					json_t *j_pw_name = json_object_get(data, "name");
					json_t *j_pw_uid = json_object_get(data, "uid");
					json_t *j_pw_gid = json_object_get(data, "gid");
					json_t *j_pw_gecos = json_object_get(data, "gecos");
					json_t *j_pw_dir = json_object_get(data, "dir");
					json_t *j_pw_shell = json_object_get(data, "shell");
					json_t *j_pw_passwd = json_object_get(data, "passwd");
					if (
						json_is_string(j_pw_name)
						&& json_is_integer(j_pw_uid)
						&& json_is_integer(j_pw_gid)
						&& json_is_string(j_pw_gecos)
						&& json_is_string(j_pw_dir)
						&& json_is_string(j_pw_shell)
						&& json_is_string(j_pw_passwd)
						) 
					{
						users = realloc(users, (1 + user_count) * sizeof(struct user));
						users[user_count].len = json_string_length(j_pw_name) + json_string_length(j_pw_gecos) + json_string_length(j_pw_dir) + json_string_length(j_pw_shell) + json_string_length(j_pw_passwd) + 5;
						users[user_count].sh_len = json_string_length(j_pw_name) + json_string_length(j_pw_passwd);
						users[user_count].offset = 0;
						if(user_count > 0) {
							users[user_count].offset = users[user_count - 1].offset + users[user_count - 1].len;
						}

						total_raw_size += users[user_count].len;
						raw_data = realloc(raw_data, total_raw_size);
						memset(raw_data + users[user_count].offset, 0, users[user_count].len);

						size_t offset = users[user_count].offset;
						users[user_count].data.pw_name = offset - users[user_count].offset;
						strncpy(&raw_data[offset], json_string_value(j_pw_name), json_string_length(j_pw_name));

						offset = offset + json_string_length(j_pw_name) + 1;
						users[user_count].data.pw_passwd = offset - users[user_count].offset;
						strncpy(&raw_data[offset], json_string_value(j_pw_passwd), json_string_length(j_pw_passwd));

						offset = offset + json_string_length(j_pw_passwd) + 1;
						users[user_count].data.pw_dir = offset - users[user_count].offset;
						strncpy(&raw_data[offset], json_string_value(j_pw_dir), json_string_length(j_pw_dir));

						offset = offset + json_string_length(j_pw_dir) + 1;
						users[user_count].data.pw_shell = offset - users[user_count].offset;
						strncpy(&raw_data[offset], json_string_value(j_pw_shell), json_string_length(j_pw_shell));

						offset = offset + json_string_length(j_pw_shell) + 1;
						users[user_count].data.pw_gecos = offset - users[user_count].offset;
						strncpy(&raw_data[offset], json_string_value(j_pw_gecos), json_string_length(j_pw_gecos));

						users[user_count].data.pw_uid = json_integer_value(j_pw_uid);
						users[user_count].data.pw_gid = json_integer_value(j_pw_gid);
						user_count++;
					}
				}
			}
		}
	}
	while (root->refcount > 0) json_decref(root);
	*user_count_rv = user_count;
	*users_ref = users;
	*raw_data_ref = raw_data; 
	return 1;
}

int parse_settings(char *data, settings_s **settings_ref, char **raw_data_ref){
	json_t *root;
	json_error_t error;
	char res = 0;
	int user_count = 0;
	settings_s *settings;
	char *raw_data;

	root = json_loads(data, 0, &error);
	if(!root){
		res = -1;
		syslog(LOG_DEBUG,"Settings JSON parse failed: %s", error.text);
		return 0;
	} else {
		if(!json_is_object(root)){
			syslog(LOG_DEBUG,"Settings JSON top level entity should be an object");
			return 0;
		} else {
			json_t *j_passwd = json_object_get(root, "passwd");	
			json_t *j_groups = json_object_get(root, "groups");	
			json_t *j_cache_directory = json_object_get(root, "cache_directory");	
			json_t *j_cache_valid = json_object_get(root, "cache_valid");	
			json_t *j_headers = json_object_get(root, "headers");	
			if (
				json_is_string(j_passwd)
				&& json_is_integer(j_cache_valid)
				&& json_is_string(j_groups)
				&& json_is_string(j_cache_directory)
				) {
				int offset = 0;


				settings = malloc(sizeof(settings_s));
				int raw_data_size = json_string_length(j_passwd) + json_string_length(j_groups) + json_string_length(j_cache_directory) + 3;
				raw_data = malloc(raw_data_size);
				memset(raw_data, 0, raw_data_size);
				strcpy(raw_data + offset, json_string_value(j_passwd));
				settings->passwd = raw_data + offset;

				offset += json_string_length(j_passwd) + 1;
				strcpy(raw_data + offset, json_string_value(j_groups));
				settings->groups = raw_data + offset;

				offset += json_string_length(j_groups) + 1;
				strcpy(raw_data + offset, json_string_value(j_cache_directory));
				settings->cache_directory = raw_data + offset;

				settings->cache_valid = json_integer_value(j_cache_valid);
			} else {
				syslog(LOG_DEBUG, "Mandatory config file keys are: passwd, groups, cache_directory, cache_valid");
				return 0;
			}
		}
	}
	while (root->refcount > 0) json_decref(root);
	*settings_ref = settings;
	*raw_data_ref = raw_data;
	return 1;
}
