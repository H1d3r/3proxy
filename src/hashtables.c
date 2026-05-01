#include "proxy.h"
#include "blake2_compat.h"


static void char_index2hash(const struct hashtable *ht, void *index, uint8_t *hash){
    blake2b_state S;

    blake2b_init(&S, ht->hash_size);
    blake2b_update(&S, index, strlen((const char*)index) + 1);
    blake2b_final(&S, hash, ht->hash_size);
}

static void param2hash_add(const struct hashtable *ht, void *index, uint8_t *hash){
    blake2b_state S;
    struct clientparam *param = (struct clientparam *)index;
    unsigned type = param->srv->authcachetype;

    blake2b_init(&S, ht->hash_size);
    if((type & 2) && param->username)blake2b_update(&S, param->username, strlen((const char *)param->username) + 1);
    if((type & 4) && param->password)blake2b_update(&S, param->password, strlen((const char *)param->password) + 1);
    if((type & 1) && !(type & 8))blake2b_update(&S, SAADDR(&param->sincr), SAADDRLEN(&param->sincr));
    if((type & 16))blake2b_update(&S, &param->srv->acl, sizeof(param->srv->acl));
    if((type & 64))blake2b_update(&S, SAADDR(&param->req), SAADDRLEN(&param->req));
    if((type & 128))blake2b_update(&S, SAPORT(&param->req), 2);
    if((type & 256) && param->hostname)blake2b_update(&S, param->hostname, strlen((const char *)param->hostname) + 1);
    if((type & 512))blake2b_update(&S, &param->operation, sizeof(param->operation));
    if((type & 1024))blake2b_update(&S, SAADDR(&param->srv->intsa), SAADDRLEN(&param->srv->intsa));
    if((type & 2048))blake2b_update(&S, SAPORT(&param->srv->intsa), 2);
    blake2b_final(&S, hash, ht->hash_size);
    memcpy(param->hash, hash, ht->hash_size);
}

void param2hash_search(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param = (struct clientparam *)index;

    memcpy(hash, param->hash, ht->hash_size);
}

static void user2hash_search(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param = (struct clientparam *)index;
    blake2b_state S;

    blake2b_init(&S, ht->hash_size);
    blake2b_update(&S, param->username, strlen((const char *)param->username) + 1);
    blake2b_final(&S, hash, ht->hash_size);
}

static void udpparam2hash(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param = (struct clientparam *)index;
    blake2b_state S;
    blake2b_init(&S, ht->hash_size);
    blake2b_update(&S, SAADDR(&param->srv->intsa), SAADDRLEN(&param->srv->intsa));
    blake2b_update(&S, SAPORT(&param->srv->intsa), 2);
    blake2b_update(&S, SAADDR(&param->sincr), SAADDRLEN(&param->sincr));
    blake2b_update(&S, SAPORT(&param->sincr), 2);
    blake2b_final(&S, hash, ht->hash_size);
}

static void pw2hash_add(const struct hashtable *ht, void *index, uint8_t *hash){
    char ** pw = (char **)index;
    blake2b_state S;
    
    blake2b_init(&S, ht->hash_size);
    if(pw[0])blake2b_update(&S, pw[0], strlen(pw[0]) + 1);
    if(pw[1])blake2b_update(&S, pw[1], strlen(pw[1]) + 1);
    blake2b_final(&S, hash, ht->hash_size);
}


static void pw2hash_search(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param  = (struct clientparam *)index;

    char *pw[2] = {(char *)param->username, (char *)param->password};
    
    pw2hash_add(ht, pw, hash);
}

static void pwnt2hash_add(const struct hashtable *ht, void *index, uint8_t *hash){
    char ** pw = (char **)index;
    blake2b_state S;
    
    blake2b_init(&S, ht->hash_size);
    if(pw[0])blake2b_update(&S, pw[0], strlen(pw[0]) + 1);
    if(pw[1])blake2b_update(&S, pw[1], strlen(pw[1]) + 1);
    blake2b_final(&S, hash, ht->hash_size);
}


#ifdef WITH_SSL
static void pwnt2hash_search(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param  = (struct clientparam *)index;
    unsigned char pass[40];
    char *pw[2] = {(char *)param->username, (char *)pass};

    ntpwdhash(pass, param->password, 1);
    pwnt2hash_add(ht, pw, hash);
}
#endif



struct hashtable dns_table = {char_index2hash, char_index2hash, 4, 12};
struct hashtable dns6_table = {char_index2hash, char_index2hash, 16, 12};
struct hashtable auth_table = {param2hash_add, param2hash_search, sizeof(struct authcache), 12};
struct hashtable pw_table = {pw2hash_add, pw2hash_search, 0, 12};
#ifdef WITH_SSL
struct hashtable pwnt_table = {pwnt2hash_add, pwnt2hash_search, 0, 12};
#endif
struct hashtable pwcr_table = {char_index2hash, user2hash_search, 64, 12};
