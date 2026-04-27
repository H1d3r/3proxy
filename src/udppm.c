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
