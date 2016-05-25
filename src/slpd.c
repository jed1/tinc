/*
    slpd.c -- Simple Local Peer Discovery
    Copyright (C) 2016 Rafal Lesniak

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "slpd.h"

char *my_slpd_port;
char *my_slpd_group;
int my_slpd_expire;
int slpdinterval = 0;

extern char *myname;

void periodic_slpd_handler(void) {
	// expire SLPD addresses
	for splay_each(node_t, n, node_tree) {
			if (!n->slpd_address)
				continue;

			if ((now.tv_sec - n->slpd_active_since.tv_sec) >= my_slpd_expire) {
				logger(DEBUG_STATUS, LOG_INFO, "Expire SLPD for %s", n->name);
				free_config(n->slpd_address);
				n->slpd_address = NULL;
			}
		}
}

void setup_slpd(void) {
	if(!get_config_string(lookup_config(config_tree, "SLPDPort"), &my_slpd_port))
		my_slpd_port = xstrdup(DEFAULT_SLPD_PORT);

	if(!get_config_string(lookup_config(config_tree, "SLPDGroup"), &my_slpd_group))
		my_slpd_group = xstrdup(DEFAULT_SLPD_GROUP);

	char *tmp_expire;
	if(!get_config_string(lookup_config(config_tree, "SLPDExpire"), &tmp_expire))
		my_slpd_expire = DEFAULT_SLPD_EXPIRE;
	else
		my_slpd_expire = atoi(tmp_expire);
}

int setup_slpd_in_socket(void) {
	int nfd;
	char *my_slpd_port;
	char *my_slpd_group;

	struct addrinfo *res;
	struct addrinfo hints;
	struct ipv6_mreq group;

	logger(DEBUG_ALWAYS, LOG_ERR, "Prepare SLPD mutlicast socket");

	if(!get_config_string(lookup_config(config_tree, "SLPDPort"), &my_slpd_port))
		my_slpd_port = xstrdup(DEFAULT_SLPD_PORT);

	if(!get_config_string(lookup_config(config_tree, "SLPDGroup"), &my_slpd_group))
		my_slpd_group = xstrdup(DEFAULT_SLPD_GROUP);

	bzero(&hints, sizeof(hints));
	hints.ai_family   = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

	int status;
	if ((status = getaddrinfo(NULL,  my_slpd_port, &hints, &res)) != 0 ) {
		logger(DEBUG_ALWAYS, LOG_INFO, "getaddrinfo() error: [%s:%d]", strerror(errno), errno);
		return -1;
	}

	nfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if(nfd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can not create socket for SLPD %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "fcntl",
				   strerror(errno));
			return -1;
		}
	}
#endif

	int reuse = 1;
	if(setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can not set SO_REUSEADDR for SLPD %s", sockstrerror(sockerrno));
		closesocket(nfd);
		return -1;
	}

	if (bind(nfd, res->ai_addr, res->ai_addrlen) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can not bind() socket for SLPD %s", sockstrerror(sockerrno));
		closesocket(nfd);
		return -1;
	}

	config_t *c_iface;
	c_iface = lookup_config(config_tree, "SLPDInterface");

	while(c_iface) {

		struct sockaddr_in6 group_addr;
		inet_pton(AF_INET6, my_slpd_group, &group_addr.sin6_addr);
		group.ipv6mr_multiaddr = group_addr.sin6_addr;
		group.ipv6mr_interface = if_nametoindex(c_iface->value);

		if (setsockopt(nfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &group, sizeof(group)) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Can not join group for SLPD %s", sockstrerror(sockerrno));
			closesocket(nfd);
			return -1;
		}
		logger(DEBUG_STATUS, LOG_INFO, "SLPD multicast group joined on %s ready", c_iface->value);
		c_iface = lookup_config_next(config_tree, c_iface);
	}

	logger(DEBUG_STATUS, LOG_INFO, "SLPD socket ready (%d)", nfd);

	return nfd;
} /* int setup_slpd_in_socket */

void handle_incoming_slpd_packet(listen_socket_t *ls, void *pkt, struct sockaddr_in6 *addr, size_t datalen) {

	unsigned int mav, miv, port;
	char nodename[MAXSIZE], fng[MAXSIZE];
	char addrstr[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &addr->sin6_addr, addrstr, sizeof(addrstr));

	int i = sscanf(pkt, "sLPD %d %d %s %d %86s", &mav, &miv, &nodename[0], &port, &fng[0]);
	if (i != 5) {
		logger(DEBUG_ALWAYS, LOG_ERR, "can not parse packet... %d from %s", i, addrstr);
		return;
	}

	fng[86] = '\00';

	if (mav == 0 && miv <= 2) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Got SLPD packet node:%s port:%d %d.%d <%s> from %s", nodename, port, mav, miv, fng, addrstr);

		node_t *n = lookup_node(nodename);
		if (!n) {
			logger(DEBUG_ALWAYS, LOG_ERR, "unknown node: %s", nodename);
			return;
		}

		// Address is still known we do not check if it changed
		if (n->slpd_address != NULL)
				return;

		if (!n->ecdsa)
			node_read_ecdsa_public_key(n);

		char sig[64];
		memset(&sig, 0x0, 64);

		if (miv >= 2) {
			if (b64decode(fng, &sig, 86) != 64) {
				logger(DEBUG_ALWAYS, LOG_ERR, "b64decode() failed!");
				return;
			}

			if (!ecdsa_verify(n->ecdsa, pkt, datalen-86-1, sig)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Signature verification for SLPD from <%s> failed!", addrstr);
				return;
			}
		}

		if (!strncmp(n->name, myself->name, strlen(myself->name))) {
			logger(DEBUG_SCARY_THINGS, LOG_NOTICE, "Ignore SLPD for myself: %s", nodename);
			return;
		}

		config_t *cfg = NULL;

		if (!n->slpd_address) {
			char iface_name[255] = { 0 };
			char fullhost[255] = { 0 };

			if_indextoname(addr->sin6_scope_id, iface_name);

			cfg = new_config();
			cfg->variable = xstrdup("Address");
			snprintf(fullhost, 254, "%s%%%s %d", addrstr, iface_name, port);
			cfg->value = xstrdup(fullhost);
			cfg->file = NULL;
			cfg->line = -1;

			logger(DEBUG_ALWAYS, LOG_ERR, "Discovered %s on %s", nodename , fullhost);
			n->slpd_address = cfg;
			n->slpd_active_since = now;
			n->status.has_address = true;
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got SLPD packet with wrong version %d.%d", mav, miv);
	}
	return;
}

void send_slpd_broadcast(node_t *myself, char *iface) {
	int sd;
	char *myname = myself->name;
	struct addrinfo *mcast_addr;
	struct addrinfo hints;
	sockaddr_t r;

	char slpd_msg[MAXSIZE] = "";

	/* Check if interface is up */
	struct ifreq ifr;
	sd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, iface);
	if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "ioctl() on %s error: [%s:%d]", iface, strerror(errno), errno);
	}
	close(sd);
	// Requested interface is down
	if (!(ifr.ifr_flags & IFF_UP) || !(ifr.ifr_flags & IFF_RUNNING))
		return;

	bzero(&hints, sizeof(hints));
	hints.ai_family   = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;

	int status;
	if ((status = getaddrinfo(my_slpd_group, my_slpd_port, &hints, &mcast_addr)) != 0 ) {
		logger(DEBUG_ALWAYS, LOG_INFO, "getaddrinfo() error: [%s:%d]", strerror(errno), errno);
		return;
	}

	if ((sd = socket(mcast_addr->ai_family, mcast_addr->ai_socktype, 0)) < 0 ) {
		logger(DEBUG_ALWAYS, LOG_INFO, "socket() error: [%s:%d]", strerror(errno), errno);
		freeaddrinfo(mcast_addr);
		return;
	}

	int on = 1;
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "setsockopt() IPV6_V6ONLY failed [%s:%d]", strerror(errno), errno);
		return;
	}

	/* Send SLPD only on this Interface */

	unsigned int ifindex;
	ifindex = if_nametoindex(iface);
	if(setsockopt (sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "setsockopt() IPV6_MULTICAST_IF failed [%s:%d]", strerror(errno), errno);
		freeaddrinfo(mcast_addr);
		return;
	}

	unsigned int reuse = 1;
	if(setsockopt (sd, IPPROTO_IPV6, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "setsockopt() SO_REUSEADDR failed: [%s:%d]", strerror(errno), errno);
		freeaddrinfo(mcast_addr);
		return;
	}

	snprintf(slpd_msg, MAXSIZE, "sLPD 0 2 %s %d", myname, atoi(myport));

	char signature[87];
	char b64sig[255];
	char pkt[MAXSIZE];

	/*
	if (!node_read_ecdsa_public_key(myself)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can not load public key for SLPD");
		return;
	}

	if (!read_ecdsa_private_key()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can not load private key for SLPD");
		return;
	}
	*/
	slpd_msg[MAXSIZE-1] = '\00';

	if (!ecdsa_sign(myself->connection->ecdsa, slpd_msg, strlen(slpd_msg), &signature)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can not sign payload for SLPD");
		return;
	}

	if (b64encode(signature, b64sig, 64) != 86) {
		logger(DEBUG_ALWAYS, LOG_ERR, "b64encode() failed!");
		return;
	}

	int l = snprintf(pkt, strlen(slpd_msg) + strlen(b64sig) + 2, "%s %s", slpd_msg, b64sig);
	pkt[l] = '\00';

	if (sendto(sd, pkt, strlen(pkt), 0, mcast_addr->ai_addr, mcast_addr->ai_addrlen) != strlen(pkt) ) {
		logger(DEBUG_ALWAYS, LOG_ERR, "SLPD send() error: [%s:%d]", strerror(errno), errno);
	}

	close(sd);
	return;
}

void handle_incoming_slpd_data(void *data, int flags) {
	listen_socket_t *ls = data;

	char pkt[MAXSIZE];
	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(addr);

	size_t len = recvfrom(ls->udp.fd, pkt, MAXSIZE, 0, (struct sockaddr *)&addr, &addrlen);

	if(len == 0 || len > MAXSIZE) {
		if(!sockwouldblock(sockerrno))
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving SLPD packet failed: %s", sockstrerror(sockerrno));
		return;
	}

	handle_incoming_slpd_packet(ls, &pkt, &addr, len);
}
