/*
   3APA3A simplest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#ifndef UDP
#define UDP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }


static void udpparam2hash(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param = (struct clientparam *)index;
    uint32_t m1, m2;
    m1 = murmurhash3(SAADDR(&param->srv->intsa), SAADDRLEN(&param->srv->intsa), 0x3a3a3a3a);
    m1 = murmurhash3(SAPORT(&param->sincr), 2, m1);
    m2 = murmurhash3(SAADDR(&param->sincr), SAADDRLEN(&param->sincr), m1);
    m2 = murmurhash3(SAPORT(&param->srv->intsa), 2, m2);
    memcpy(hash, &m1, 4);
    memcpy(hash+4, &m2, 4);
}

struct hashtable udp_table =  {udpparam2hash, udpparam2hash, sizeof(struct clientparam *), 8};

void * udppmchild(struct clientparam* param) {

 param->clisock = param->srv->srvsock;
 param->waitserver64 = 0x7fffffffffffffff;
 param->res = mapsocket(param, conf.timeouts[STRING_L]);

CLEANRET:

 dolog(param, NULL);
 param->clisock = INVALID_SOCKET;
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	udppmchild,
	0,
	1,
	S_UDPPM,
	" -s single packet UDP service for request/reply (DNS-like) services\n"
};
#include "proxymain.c"
#endif
