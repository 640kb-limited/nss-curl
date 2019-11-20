#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
#include "nss_curl_conf.h"
#include <math.h>

int base64_encode(const char* message, char** buffer) { //Encodes a string to base64
  BIO *bio, *b64;
  FILE* stream;
  int encodedSize = 4*ceil((double)strlen(message)/3);
  *buffer = (char *)malloc(encodedSize+1);

  stream = fmemopen(*buffer, encodedSize+1, "w");
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_write(bio, message, strlen(message));
  BIO_flush(bio);
  BIO_free_all(bio);
  fclose(stream);

  return (0); //success
}

void md5sum(char* s, char* output) {
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5,s,strlen(s));
    MD5_Final(output,&md5);
}

char *cache_for(char *url, char *res){
	char s[128];
	char *s_b64;
	s_b64 = malloc(128);
	memset(s, 0, 128);
	memset(s_b64, 0, 128);
	md5sum(url, s);
	base64_encode(s, &s_b64);
	int cache_directory_len = strlen(cache_directory());
	memset(res, 0, cache_directory_len + 1 + strlen(s_b64) + 1 + 1);
	strncpy(res, cache_directory(), cache_directory_len);
	strncpy(res + cache_directory_len,"/",1);
	strncpy(res + cache_directory_len + 1, s_b64, strlen(s_b64));
	free(s_b64);
	return res;
}


int cache_valid(char *filename, int valid_sec){
	struct stat s;	
	time_t rawtime;

	time ( &rawtime );
	if(stat(filename, &s) == -1) return 0;
	return(rawtime - s.st_mtim.tv_sec <= valid_sec);
}

int cache_save(char *filename, void *data, size_t size){
	umask(0x077);
	FILE *file = fopen(filename, "w");
	fwrite(data, 1, size, file);
	fclose(file);
}

int cache_load(char *filename, void **data_ref, size_t *size){
	FILE *file = fopen(filename, "r");
	size_t total_bytes = 0;
	size_t chunk_size = 64*1024;
	void *data;

	while(!feof(file)){
		data = realloc(data, total_bytes + chunk_size);
		size_t count = fread(data + total_bytes, 1, chunk_size, file);
		total_bytes += count;
		if(count < chunk_size) {
			data = realloc(data, total_bytes);
		}
	}
	
	fclose(file);
	if(total_bytes) {
		*size = total_bytes;
		*data_ref = data;
		return 1;
	} else {
		if(data) free(data);
		return 0;
	}
}
