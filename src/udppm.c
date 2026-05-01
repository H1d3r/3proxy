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
	int authres;

	if(parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport))) { RETURN(201) }
#ifndef NOIPV6
	memcpy(&param->sinsl, *SAFAMILY(&param->req) == AF_INET6 ? (struct sockaddr *)&param->srv->extsa6 : (struct sockaddr *)&param->srv->extsa, SASIZE(&param->req));
#else
	memcpy(&param->sinsl, (struct sockaddr *)&param->srv->extsa, SASIZE(&param->req));
#endif
	*SAPORT(&param->sinsl) = 0;
	param->remsock = param->srv->so._socket(param->srv->so.state, SASOCK(&param->sinsl), SOCK_DGRAM, IPPROTO_UDP);
	if(param->remsock == INVALID_SOCKET) { RETURN(202); }
	if(param->srv->so._bind(param->srv->so.state, param->remsock, (struct sockaddr *)&param->sinsl, SASIZE(&param->sinsl))) { RETURN(203); }
#ifdef _WIN32
	{ unsigned long ul2 = 1; ioctlsocket(param->remsock, FIONBIO, &ul2); }
#else
	fcntl(param->remsock, F_SETFL, O_NONBLOCK | fcntl(param->remsock, F_GETFL));
#endif
	memcpy(&param->sinsr, &param->req, sizeof(param->req));
	param->operation = UDPASSOC;
	authres = (*param->srv->authfunc)(param);
	if(authres) { RETURN(authres); }
	if(!param->srv->singlepacket)hashadd(&udp_table, param, &param, MAX_COUNTER_TIME);
	param->srv->so._sendto(param->sostate, param->remsock, (char *)param->srvbuf, param->srvinbuf, 0, (struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr));
	_3proxy_sem_unlock(udpinit);
	param->statscli64 += param->srvinbuf;
	param->srvinbuf = 0;
	param->nwrites++;
	param->clisock = param->srv->srvsock;
	param->udp_nhops = 1;
	param->waitserver64 = 0x7fffffffffffffff;
	param->res = udpsockmap(param, conf.timeouts[STRING_L]);
	_3proxy_sem_lock(udpinit);
	if(!param->srv->singlepacket)hashdelete(&udp_table, param);

CLEANRET:

 _3proxy_sem_unlock(udpinit);
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
