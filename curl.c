#include <curl/curl.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include "curl.h"
#include "cache.h"
#include "nss_curl_conf.h"

struct string {
	char *ptr;
	size_t len;
};

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
	size_t new_len = s->len + size*nmemb;
	s->ptr = realloc(s->ptr, new_len+1);
	if (s->ptr == NULL) {
		syslog(LOG_DEBUG, "realloc() failed");
		exit(EXIT_FAILURE);
	}
	memcpy(s->ptr+s->len, ptr, size*nmemb);
	s->ptr[new_len] = '\0';
	s->len = new_len;

	return size*nmemb;
}

CURLcode fetch_data(char *url, void **data_ref, size_t *len){
	CURL *curl;
	CURLcode res;
	char filename[256];
	if(cache_valid(cache_for(url, filename), cache_valid_sec())){
		if(cache_load(cache_for(url, filename), data_ref, len)) return CURLE_OK;
	}
	struct string s;
	s.ptr = NULL;
	s.len = 0;

	curl = curl_easy_init();

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "nss_curl/0.1");

/* example.com is redirected, so we tell libcurl to follow redirection */
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	res = curl_easy_perform(curl);
	if(res == CURLE_OK){
		cache_save(cache_for(url, filename), s.ptr, s.len);
		*data_ref = s.ptr;
		*len = s.len;
	}
	curl_easy_cleanup(curl);
	return res;
}