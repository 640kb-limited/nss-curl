char *cache_for(char *url, char *res);
int cache_valid(char *filename, int valid_sec);
int cache_save(char *filename, void *data, size_t size);
int cache_load(char *filename, void **data, size_t *size);
