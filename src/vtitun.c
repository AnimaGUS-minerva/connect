/*
 * This code adapted from ip6tunnel.c from the iproute2 project.
 * Why tunnels use ioctls, and not netlink... sigh.
 *
 * Getting the structure right in RUST seemed like more work than it was worth.
 *
 * Copyright (C)2006 USAGI/WIDE Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
/*
 * Author:
 *	Masahide NAKAMURA @USAGI
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>

#define DEFAULT_TNL_HOP_LIMIT	(64)
const char *tunname = "v6play";

#define min(x, y) ({			\
	typeof(x) _min1 = (x);		\
	typeof(y) _min2 = (y);		\
	(void) (&_min1 == &_min2);	\
	_min1 < _min2 ? _min1 : _min2; })

static size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t srclen = strlen(src);

	if (size) {
		size_t minlen = min(srclen, size - 1);

		memcpy(dst, src, minlen);
		dst[minlen] = '\0';
	}
	return srclen;
}

/*
 * ip -6 tunnel add myvti6   mode vti6
 *                         local  fe80::5054:ff:fe51:daff
 *                         remote fe80::5054:ff:fe51:12bc
 *                         key 7
 */
static void init_my_tunnel(struct ip6_tnl_parm2 *p, const char *tunname,
                           const char *local, const char *remote,
                           unsigned key, unsigned int phys_index)
{
        struct in6_addr raddr, laddr;

        p->proto = IPPROTO_IPV6;
        p->i_flags |= VTI_ISVTI;

        inet_pton(AF_INET6, remote, &raddr);  // parse
        memcpy(&p->raddr, &raddr, sizeof(p->raddr));
        //p->raddr.s6_addr[15]++;  /* pick a new number */

        inet_pton(AF_INET6, local,  &laddr); // must exist locally
        memcpy(&p->laddr, &laddr, sizeof(p->laddr));
        //p->laddr.s6_addr[15]++;  /* pick a new number */

        p->i_flags |= GRE_KEY;
        p->o_flags |= GRE_KEY;
        p->link     = phys_index;
        fprintf(stderr, "created tunnel %s, key: %u phys: %u\n", tunname, key, phys_index);
        p->i_key = p->o_key = htonl(key);  /* key ... in network byte order... */

        strlcpy(p->name, tunname, sizeof(p->name-1));
}

static void ip6_tnl_parm_init(struct ip6_tnl_parm2 *p, int apply_default)
{
	memset(p, 0, sizeof(*p));
	p->proto = IPPROTO_IPV6;
	if (apply_default) {
		p->hop_limit = DEFAULT_TNL_HOP_LIMIT;
		p->encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
	}
}

int create_vti6_tunnel(const char *tunname, unsigned int key,
                       unsigned int physdev_ifindex,
                       const char *local, const char *remote)
{
  struct ip6_tnl_parm2 p;
  const char *basedev = "ip6tnl0";
  struct ifreq ifr;
  int fd;
  int err, cmd;

  //printf("Creating new tunnel: %s\n", tunname);

  ip6_tnl_parm_init(&p, 1);
  init_my_tunnel(&p, tunname, local, remote, key, physdev_ifindex);

  if (p.i_flags & VTI_ISVTI)
    basedev = "ip6_vti0";

  cmd = SIOCADDTUNNEL;
  memset(&ifr, 0, sizeof(ifr));

  strlcpy(ifr.ifr_name, basedev, IFNAMSIZ);
  ifr.ifr_ifru.ifru_data = &p;

  fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf(stderr, "create socket failed: %s\n", strerror(errno));
    return -1;
  }

  err = ioctl(fd, cmd, &ifr);
  if (err)
    fprintf(stderr, "add tunnel \"%s\" [%s] failed: %s\n", ifr.ifr_name, p.name,
            strerror(errno));
  close(fd);

  return err;
}
