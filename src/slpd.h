/*
    slpd.h -- Simple Local Peer Discovery
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

#include "system.h"

#include "conf.h"
#include "logger.h"
#include "utils.h"
#include "xalloc.h"

#define DEFAULT_SLPD_GROUP    "ff02::42:1"
#define DEFAULT_SLPD_PORT     "1655"
#define DEFAULT_SLPD_EXPIRE   300

extern int slpdinterval;
extern timeout_t slpdupdate_timeout;

void periodic_slpd_handler(void);
void slpdupdate_handler(void *);
void setup_slpd(void);
int setup_slpd_in_socket(void);
void handle_incoming_slpd_packet(listen_socket_t *, void *, struct sockaddr_in6 *, size_t);
void handle_incoming_slpd_data(void *, int);
void send_slpd_broadcast(node_t *, char *);
