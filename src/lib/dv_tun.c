
#if 0
bool
is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
  ASSERT (match_type);
  if (!dev)
    return false;
  if (dev_type)
    return !strcmp (dev_type, match_type);
  else
    return !strncmp (dev, match_type, strlen (match_type));
}

int
dev_type_enum (const char *dev, const char *dev_type)
{
  if (is_dev_type (dev, dev_type, "tun"))
    return DEV_TYPE_TUN;
  else if (is_dev_type (dev, dev_type, "tap"))
    return DEV_TYPE_TAP;
  else if (is_dev_type (dev, dev_type, "null"))
    return DEV_TYPE_NULL;
  else
    return DEV_TYPE_UNDEF;
}

const char *
dev_type_string (const char *dev, const char *dev_type)
{
  switch (dev_type_enum (dev, dev_type))
    {
    case DEV_TYPE_TUN:
      return "tun";
    case DEV_TYPE_TAP:
      return "tap";
    case DEV_TYPE_NULL:
      return "null";
    default:
      return "[unknown-dev-type]";
    }
}

#endif

#if 0
/*
 * Init tun/tap object.
 *
 * Set up tuntap structure for ifconfig,
 * but don't execute yet.
 */
struct tuntap *
init_tun (const char *dev,       /* --dev option */
	  const char *dev_type,  /* --dev-type option */
	  int topology,          /* one of the TOP_x values */
	  const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	  const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	  const char *ifconfig_ipv6_local_parm,     /* --ifconfig parm 1 IPv6 */
	  int         ifconfig_ipv6_netbits_parm,
	  const char *ifconfig_ipv6_remote_parm,    /* --ifconfig parm 2 IPv6 */
	  in_addr_t local_public,
	  in_addr_t remote_public,
	  const bool strict_warn,
	  struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  struct tuntap *tt;

  ALLOC_OBJ (tt, struct tuntap);
  clear_tuntap (tt);

  tt->type = dev_type_enum (dev, dev_type);
  tt->topology = topology;

  if (ifconfig_local_parm && ifconfig_remote_netmask_parm)
    {
      bool tun = false;

      /*
       * We only handle TUN/TAP devices here, not --dev null devices.
       */
      tun = is_tun_p2p (tt);

      /*
       * Convert arguments to binary IPv4 addresses.
       */

      tt->local = getaddr (
			   GETADDR_RESOLVE
			   | GETADDR_HOST_ORDER
			   | GETADDR_FATAL_ON_SIGNAL
			   | GETADDR_FATAL,
			   ifconfig_local_parm,
			   0,
			   NULL,
			   NULL);

      tt->remote_netmask = getaddr (
				    (tun ? GETADDR_RESOLVE : 0)
				    | GETADDR_HOST_ORDER
				    | GETADDR_FATAL_ON_SIGNAL
				    | GETADDR_FATAL,
				    ifconfig_remote_netmask_parm,
				    0,
				    NULL,
				    NULL);

      /*
       * Look for common errors in --ifconfig parms
       */
      if (strict_warn)
	{
	  ifconfig_sanity_check (tt->type == DEV_TYPE_TUN, tt->remote_netmask, tt->topology);

	  /*
	   * If local_public or remote_public addresses are defined,
	   * make sure they do not clash with our virtual subnet.
	   */

	  check_addr_clash ("local",
			    tt->type,
			    local_public,
			    tt->local,
			    tt->remote_netmask);

	  check_addr_clash ("remote",
			    tt->type,
			    remote_public,
			    tt->local,
			    tt->remote_netmask);

	  if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
	    check_subnet_conflict (tt->local, tt->remote_netmask, "TUN/TAP adapter");
	  else if (tt->type == DEV_TYPE_TUN)
	    check_subnet_conflict (tt->local, IPV4_NETMASK_HOST, "TUN/TAP adapter");
	}

      /*
       * If TAP-style interface, generate broadcast address.
       */
      if (!tun)
	{
	  tt->broadcast = generate_ifconfig_broadcast_addr (tt->local, tt->remote_netmask);
	}


      tt->did_ifconfig_setup = true;
    }

  if (ifconfig_ipv6_local_parm && ifconfig_ipv6_remote_parm)
    {

      /*
       * Convert arguments to binary IPv6 addresses.
       */

      if ( inet_pton( AF_INET6, ifconfig_ipv6_local_parm, &tt->local_ipv6 ) != 1 ||
           inet_pton( AF_INET6, ifconfig_ipv6_remote_parm, &tt->remote_ipv6 ) != 1 ) 
	{
	  msg( M_FATAL, "init_tun: problem converting IPv6 ifconfig addresses %s and %s to binary", ifconfig_ipv6_local_parm, ifconfig_ipv6_remote_parm );
	}
      tt->netbits_ipv6 = ifconfig_ipv6_netbits_parm;

      tt->did_ifconfig_ipv6_setup = true;
    }

  /*
   * Set environmental variables with ifconfig parameters.
   */
  if (es) do_ifconfig_setenv(tt, es);

  gc_free (&gc);
  return tt;
}

int
write_tun_header (struct tuntap* tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
      {
        u_int32_t type;
        struct iovec iv[2];
        struct ip *iph;

        iph = (struct ip *) buf;

        if (tt->ipv6 && iph->ip_v == 6)
            type = htonl (AF_INET6);
        else
            type = htonl (AF_INET);

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof (type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return header_modify_read_write_return (writev (tt->fd, iv, 2));
      }
    else
        return write (tt->fd, buf, len);
}

int
read_tun_header (struct tuntap* tt, uint8_t *buf, int len)
{
    if (tt->type == DEV_TYPE_TUN)
      {
        u_int32_t type;
        struct iovec iv[2];

        iv[0].iov_base = &type;
        iv[0].iov_len = sizeof (type);
        iv[1].iov_base = buf;
        iv[1].iov_len = len;

        return header_modify_read_write_return (readv (tt->fd, iv, 2));
      }
    else
        return read (tt->fd, buf, len);
}
#endif


#if 0
static void
open_tun_generic (const char *dev, const char *dev_type, const char *dev_node,
		  bool ipv6_explicitly_supported, bool dynamic,
		  struct tuntap *tt)
{
  char tunname[256];
  char dynamic_name[256];
  bool dynamic_opened = false;


  if ( tt->ipv6 && ! ipv6_explicitly_supported )
    msg (M_WARN, "NOTE: explicit support for IPv6 tun devices is not provided for this OS");

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
    }
  else
    {
      /*
       * --dev-node specified, so open an explicit device node
       */
      if (dev_node)
	{
	  openvpn_snprintf (tunname, sizeof (tunname), "%s", dev_node);
	}
      else
	{
	  /*
	   * dynamic open is indicated by --dev specified without
	   * explicit unit number.  Try opening /dev/[dev]n
	   * where n = [0, 255].
	   */
#ifdef TARGET_NETBSD
	  /* on NetBSD, tap (but not tun) devices are opened by
           * opening /dev/tap and then querying the system about the
	   * actual device name (tap0, tap1, ...) assigned
           */
	  if ( dynamic && strcmp( dev, "tap" ) == 0 )
	    {
	      struct ifreq ifr;
	      if ((tt->fd = open ( "/dev/tap", O_RDWR)) < 0)
		{
		  msg (M_FATAL, "Cannot allocate NetBSD TAP dev dynamically");
		}
	      if ( ioctl( tt->fd, TAPGIFNAME, (void*)&ifr ) < 0 )
		{
		  msg (M_FATAL, "Cannot query NetBSD TAP device name");
		}
	      CLEAR(dynamic_name);
	      strncpy( dynamic_name, ifr.ifr_name, sizeof(dynamic_name)-1 );
	      dynamic_opened = true;
	      openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dynamic_name );
	    }
	  else
#endif

	  if (dynamic && !has_digit((unsigned char *)dev))
	    {
	      int i;
	      for (i = 0; i < 256; ++i)
		{
		  openvpn_snprintf (tunname, sizeof (tunname),
				    "/dev/%s%d", dev, i);
		  openvpn_snprintf (dynamic_name, sizeof (dynamic_name),
				    "%s%d", dev, i);
		  if ((tt->fd = open (tunname, O_RDWR)) > 0)
		    {
		      dynamic_opened = true;
		      break;
		    }
		  msg (D_READ_WRITE | M_ERRNO, "Tried opening %s (failed)", tunname);
		}
	      if (!dynamic_opened)
		msg (M_FATAL, "Cannot allocate TUN/TAP dev dynamically");
	    }
	  /*
	   * explicit unit number specified
	   */
	  else
	    {
	      openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dev);
	    }
	}

      if (!dynamic_opened)
	{
	  /* has named device existed before? if so, don't destroy at end */
	  if ( if_nametoindex( dev ) > 0 )
	    {
	      msg (M_INFO, "TUN/TAP device %s exists previously, keep at program end", dev );
	      tt->persistent_if = true;
	    }

	  if ((tt->fd = open (tunname, O_RDWR)) < 0)
	    msg (M_ERR, "Cannot open TUN/TAP dev %s", tunname);
	}

      set_nonblock (tt->fd);
      set_cloexec (tt->fd); /* don't pass fd to scripts */
      msg (M_INFO, "TUN/TAP device %s opened", tunname);

      /* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
      tt->actual_name = string_alloc (dynamic_opened ? dynamic_name : dev, NULL);
    }
}

static void
close_tun_generic (struct tuntap *tt)
{
  if (tt->fd >= 0)
    close (tt->fd);
  if (tt->actual_name)
    free (tt->actual_name);
  clear_tuntap (tt);
}

#endif

#if 0

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  struct ifreq ifr;

  /*
   * We handle --dev null specially, we do not open /dev/null for this.
   */
  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
    }
  else
    {
      /*
       * Process --dev-node
       */
      const char *node = dev_node;
      if (!node)
	node = "/dev/net/tun";

      /*
       * Open the interface
       */
      if ((tt->fd = open (node, O_RDWR)) < 0)
	{
	  msg (M_ERR, "ERROR: Cannot open TUN/TAP dev %s", node);
	}

      /*
       * Process --tun-ipv6
       */
      CLEAR (ifr);
      if (!tt->ipv6)
	ifr.ifr_flags = IFF_NO_PI;

#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
      ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

      /*
       * Figure out if tun or tap device
       */
      if (tt->type == DEV_TYPE_TUN)
	{
	  ifr.ifr_flags |= IFF_TUN;
	}
      else if (tt->type == DEV_TYPE_TAP)
	{
	  ifr.ifr_flags |= IFF_TAP;
	}
      else
	{
	  msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	       dev);
	}

      /*
       * Set an explicit name, if --dev is not tun or tap
       */
      if (strcmp(dev, "tun") && strcmp(dev, "tap"))
	strncpynt (ifr.ifr_name, dev, IFNAMSIZ);

      /*
       * Use special ioctl that configures tun/tap device with the parms
       * we set in ifr
       */
      if (ioctl (tt->fd, TUNSETIFF, (void *) &ifr) < 0)
	{
	  msg (M_ERR, "ERROR: Cannot ioctl TUNSETIFF %s", dev);
	}

      msg (M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);

      /*
       * Try making the TX send queue bigger
       */
#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
      if (tt->options.txqueuelen) {
	struct ifreq netifr;
	int ctl_fd;

	if ((ctl_fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0)
	  {
	    CLEAR (netifr);
	    strncpynt (netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
	    netifr.ifr_qlen = tt->options.txqueuelen;
	    if (ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0)
	      msg (D_OSBUF, "TUN/TAP TX queue length set to %d", tt->options.txqueuelen);
	    else
	      msg (M_WARN | M_ERRNO, "Note: Cannot set tx queue length on %s", ifr.ifr_name);
	    close (ctl_fd);
	  }
	else
	  {
	    msg (M_WARN | M_ERRNO, "Note: Cannot open control socket on %s", ifr.ifr_name);
	  }
      }
#endif

      set_nonblock (tt->fd);
      set_cloexec (tt->fd);
      tt->actual_name = string_alloc (ifr.ifr_name, NULL);
    }
  return;
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, false, true, tt);
}

#endif /* HAVE_LINUX_IF_TUN_H */

#if 0

void
close_tun (struct tuntap *tt)
{
  if (tt)
    {
	if (tt->type != DEV_TYPE_NULL && tt->did_ifconfig)
	  {
	    struct argv argv;
	    struct gc_arena gc = gc_new ();
	    argv_init (&argv);

#ifdef ENABLE_IPROUTE
	    if (is_tun_p2p (tt))
	      {
		argv_printf (&argv,
			"%s addr del dev %s local %s peer %s",
			iproute_path,
			tt->actual_name,
			print_in_addr_t (tt->local, 0, &gc),
			print_in_addr_t (tt->remote_netmask, 0, &gc)
			);
	      }
	    else
	      {
		argv_printf (&argv,
			"%s addr del dev %s %s/%d",
			iproute_path,
			tt->actual_name,
			print_in_addr_t (tt->local, 0, &gc),
			count_netmask_bits(print_in_addr_t (tt->remote_netmask, 0, &gc))
			);
	      }
#else
	    argv_printf (&argv,
			"%s %s 0.0.0.0",
			IFCONFIG_PATH,
			tt->actual_name
			);
#endif

	    argv_msg (M_INFO, &argv);
	    openvpn_execve_check (&argv, NULL, 0, "Linux ip addr del failed");

            if (tt->ipv6 && tt->did_ifconfig_ipv6_setup)
              {
                const char * ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);

#ifdef ENABLE_IPROUTE
                argv_printf (&argv, "%s -6 addr del %s/%d dev %s",
                                    iproute_path,
                                    ifconfig_ipv6_local,
                                    tt->netbits_ipv6,
                                    tt->actual_name
                                    );
                argv_msg (M_INFO, &argv);
                openvpn_execve_check (&argv, NULL, 0, "Linux ip -6 addr del failed");
#else
                argv_printf (&argv,
                            "%s %s del %s/%d",
                            IFCONFIG_PATH,
                            tt->actual_name,
                            ifconfig_ipv6_local,
                            tt->netbits_ipv6
                            );
                argv_msg (M_INFO, &argv);
                openvpn_execve_check (&argv, NULL, 0, "Linux ifconfig inet6 del failed");
#endif
              }

	    argv_reset (&argv);
	    gc_free (&gc);
	  }
      close_tun_generic (tt);
      free (tt);
    }
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->ipv6)
    {
      struct tun_pi pi;
      struct iphdr *iph;
      struct iovec vect[2];
      int ret;

      iph = (struct iphdr *)buf;

      pi.flags = 0;

      if(iph->version == 6)
	pi.proto = htons(OPENVPN_ETH_P_IPV6);
      else
	pi.proto = htons(OPENVPN_ETH_P_IPV4);

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = writev(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->ipv6)
    {
      struct iovec vect[2];
      struct tun_pi pi;
      int ret;

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = readv(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
    return read (tt->fd, buf, len);
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
  int if_fd, ip_muxid, arp_muxid, arp_fd, ppa = -1;
  struct lifreq ifr;
  const char *ptr;
  const char *ip_node, *arp_node;
  const char *dev_tuntap_type;
  int link_type;
  bool is_tun;
  struct strioctl  strioc_if, strioc_ppa;

  /* improved generic TUN/TAP driver from
   * http://www.whiteboard.ne.jp/~admin2/tuntap/
   * has IPv6 support
   */
  CLEAR(ifr);

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
      return;
    }

  if (tt->type == DEV_TYPE_TUN)
    {
      ip_node = "/dev/udp";
      if (!dev_node)
	dev_node = "/dev/tun";
      dev_tuntap_type = "tun";
      link_type = I_PLINK;
      is_tun = true;
    }
  else if (tt->type == DEV_TYPE_TAP)
    {
      ip_node = "/dev/udp";
      if (!dev_node)
	dev_node = "/dev/tap";
      arp_node = dev_node;
      dev_tuntap_type = "tap";
      link_type = I_PLINK; /* was: I_LINK */
      is_tun = false;
    }
  else
    {
      msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	   dev);
    }

  if ((tt->ip_fd = open (ip_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", ip_node);

  if ((tt->fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", dev_node);
  
  /* get unit number */
  if (*dev)
    {
      ptr = dev;
      while (*ptr && !isdigit ((int) *ptr))
	ptr++;
      ppa = atoi (ptr);
    }

  /* Assign a new PPA and get its unit number. */
  strioc_ppa.ic_cmd = TUNNEWPPA;
  strioc_ppa.ic_timout = 0;
  strioc_ppa.ic_len = sizeof(ppa);
  strioc_ppa.ic_dp = (char *)&ppa;

  if ( *ptr == '\0' )		/* no number given, try dynamic */
    {
      bool found_one = false;
      while( ! found_one && ppa < 64 )
	{
	  int new_ppa = ioctl (tt->fd, I_STR, &strioc_ppa);
	  if ( new_ppa >= 0 )
	    {
	      msg( M_INFO, "open_tun: got dynamic interface '%s%d'", dev_tuntap_type, new_ppa );
	      ppa = new_ppa;
	      found_one = true;
	      break;
	    }
	  if ( errno != EEXIST )
	    msg (M_ERR, "open_tun: unexpected error trying to find free %s interface", dev_tuntap_type );
	  ppa++;
	}
      if ( !found_one )
	msg (M_ERR, "open_tun: could not find free %s interface, give up.", dev_tuntap_type );
    }
  else				/* try this particular one */
    {
      if ((ppa = ioctl (tt->fd, I_STR, &strioc_ppa)) < 0)
        msg (M_ERR, "Can't assign PPA for new interface (%s%d)", dev_tuntap_type, ppa );
    }

  if ((if_fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s (2)", dev_node);

  if (ioctl (if_fd, I_PUSH, "ip") < 0)
    msg (M_ERR, "Can't push IP module");

  if (tt->type == DEV_TYPE_TUN)
    {
  /* Assign ppa according to the unit number returned by tun device */
  if (ioctl (if_fd, IF_UNITSEL, (char *) &ppa) < 0)
    msg (M_ERR, "Can't set PPA %d", ppa);
    }

  tt->actual_name = (char *) malloc (32);
  check_malloc_return (tt->actual_name);

  openvpn_snprintf (tt->actual_name, 32, "%s%d", dev_tuntap_type, ppa);

  if (tt->type == DEV_TYPE_TAP)
    {
          if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0)
            msg (M_ERR, "Can't get flags\n");
          strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));
          ifr.lifr_ppa = ppa;
          /* Assign ppa according to the unit number returned by tun device */
          if (ioctl (if_fd, SIOCSLIFNAME, &ifr) < 0)
            msg (M_ERR, "Can't set PPA %d", ppa);
          if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) <0)
            msg (M_ERR, "Can't get flags\n");
          /* Push arp module to if_fd */
          if (ioctl (if_fd, I_PUSH, "arp") < 0)
            msg (M_ERR, "Can't push ARP module");

          /* Pop any modules on the stream */
          while (true)
            {
                 if (ioctl (tt->ip_fd, I_POP, NULL) < 0)
                     break;
            }
          /* Push arp module to ip_fd */
          if (ioctl (tt->ip_fd, I_PUSH, "arp") < 0)
            msg (M_ERR, "Can't push ARP module\n");

          /* Open arp_fd */
          if ((arp_fd = open (arp_node, O_RDWR, 0)) < 0)
            msg (M_ERR, "Can't open %s\n", arp_node);
          /* Push arp module to arp_fd */
          if (ioctl (arp_fd, I_PUSH, "arp") < 0)
            msg (M_ERR, "Can't push ARP module\n");

          /* Set ifname to arp */
          strioc_if.ic_cmd = SIOCSLIFNAME;
          strioc_if.ic_timout = 0;
          strioc_if.ic_len = sizeof(ifr);
          strioc_if.ic_dp = (char *)&ifr;
          if (ioctl(arp_fd, I_STR, &strioc_if) < 0){
              msg (M_ERR, "Can't set ifname to arp\n");
          }
   }

  if ((ip_muxid = ioctl (tt->ip_fd, link_type, if_fd)) < 0)
    msg (M_ERR, "Can't link %s device to IP", dev_tuntap_type);

  if (tt->type == DEV_TYPE_TAP) {
          if ((arp_muxid = ioctl (tt->ip_fd, link_type, arp_fd)) < 0)
            msg (M_ERR, "Can't link %s device to ARP", dev_tuntap_type);
          close (arp_fd);
  }

  CLEAR (ifr);
  strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));
  ifr.lifr_ip_muxid  = ip_muxid;
  if (tt->type == DEV_TYPE_TAP) {
          ifr.lifr_arp_muxid = arp_muxid;
  }

  if (ioctl (tt->ip_fd, SIOCSLIFMUXID, &ifr) < 0)
    {
      if (tt->type == DEV_TYPE_TAP)
        {
              ioctl (tt->ip_fd, I_PUNLINK , arp_muxid);
        }
      ioctl (tt->ip_fd, I_PUNLINK, ip_muxid);
      msg (M_ERR, "Can't set multiplexor id");
    }

  set_nonblock (tt->fd);
  set_cloexec (tt->fd);
  set_cloexec (tt->ip_fd);

  msg (M_INFO, "TUN/TAP device %s opened", tt->actual_name);
}

/*
 * Close TUN device. 
 */
void
close_tun (struct tuntap *tt)
{
  if (tt)
    {
      solaris_close_tun (tt);

      if (tt->actual_name)
	free (tt->actual_name);
      
      clear_tuntap (tt);
      free (tt);
    }
}
#endif
