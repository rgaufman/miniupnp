/* $Id: obsdrdr.c,v 1.102 2023/12/07 18:56:32 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2025 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution
 *
 * Implementation for macOS PF to enable port forwarding
 */
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "obsdrdr.h"
#include "../macros.h"

/* Macros for PF device */
#define PF_DEV "/dev/pf"
#define PF_ANCHOR_NAME "miniupnpd"
#define PF_NAT_ANCHOR_NAME "miniupnpd-nat"
#define PF_RULES_FILE "/tmp/miniupnpd-pf.rules"

/* Global variables */
static int dev = -1;
static const char* anchor_name = PF_ANCHOR_NAME;
static const char* nat_anchor_name = PF_NAT_ANCHOR_NAME;

/* Helper to execute a shell command */
static int exec_cmd(const char* cmd) {
    syslog(LOG_DEBUG, "Executing: %s", cmd);
    return system(cmd);
}

/* Initialize PF for port forwarding */
int init_redirect(void) {
    /* Open PF device */
    dev = open(PF_DEV, O_RDWR);
    if (dev < 0) {
        syslog(LOG_ERR, "Unable to open PF device %s", PF_DEV);
        return -1;
    }
    
    /* Create anchors if they don't exist */
    char cmd[512];
    
    /* Load existing anchors */
    snprintf(cmd, sizeof(cmd), "pfctl -s Anchors | grep %s || pfctl -a %s -F all", 
             anchor_name, anchor_name);
    exec_cmd(cmd);
    
    snprintf(cmd, sizeof(cmd), "pfctl -s Anchors | grep %s || pfctl -a %s -F all", 
             nat_anchor_name, nat_anchor_name);
    exec_cmd(cmd);
    
    syslog(LOG_NOTICE, "PF initialized for port forwarding with anchors %s and %s", 
           anchor_name, nat_anchor_name);
    return 0;
}

void shutdown_redirect(void) {
    /* Close PF device if open */
    if (dev >= 0) {
        close(dev);
        dev = -1;
    }
    
    /* Clear our anchors */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "pfctl -a %s -F all", anchor_name);
    exec_cmd(cmd);
    
    snprintf(cmd, sizeof(cmd), "pfctl -a %s -F all", nat_anchor_name);
    exec_cmd(cmd);
    
    syslog(LOG_NOTICE, "PF port forwarding disabled, anchors cleared");
}

int
add_redirect_rule2(const char * ifname,
                   const char * rhost, unsigned short eport,
                   const char * iaddr, unsigned short iport, int proto,
                   const char * desc, unsigned int timestamp)
{
    char cmd[512];
    char protostr[8];
    FILE *file;
    
    UNUSED(timestamp);
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return -1;
    }
    
    /* Convert protocol to string */
    if (proto == IPPROTO_TCP)
        strcpy(protostr, "tcp");
    else if (proto == IPPROTO_UDP)
        strcpy(protostr, "udp");
    else {
        syslog(LOG_ERR, "Unknown protocol %d", proto);
        return -1;
    }
    
    /* Create a temporary file with our NAT rule */
    file = fopen(PF_RULES_FILE, "w");
    if (!file) {
        syslog(LOG_ERR, "Unable to create temporary PF rules file");
        return -1;
    }
    
    if (rhost && rhost[0] != '\0') {
        fprintf(file, "# Port forward for %s (from %s to %s:%hu)\n", desc, rhost, iaddr, iport);
        fprintf(file, "rdr on %s proto %s from %s to any port %hu -> %s port %hu\n", 
                ifname, protostr, rhost, eport, iaddr, iport);
    } else {
        fprintf(file, "# Port forward for %s (from any to %s:%hu)\n", desc, iaddr, iport);
        fprintf(file, "rdr on %s proto %s from any to any port %hu -> %s port %hu\n", 
                ifname, protostr, eport, iaddr, iport);
    }
    
    fclose(file);
    
    /* Load the rule into the NAT anchor directly */
    snprintf(cmd, sizeof(cmd), "pfctl -a %s -f %s", 
             nat_anchor_name, PF_RULES_FILE);
    if (exec_cmd(cmd) != 0) {
        syslog(LOG_ERR, "Failed to load NAT rule for %s:%hu -> %s:%hu", 
               rhost ? rhost : "any", eport, iaddr, iport);
        unlink(PF_RULES_FILE);
        return -1;
    }
    
    /* Clean up and enable PF if needed */
    unlink(PF_RULES_FILE);
    
    /* Make sure PF is enabled */
    exec_cmd("pfctl -e 2>/dev/null");
    
    syslog(LOG_NOTICE, "Added port forwarding: %s:%hu -> %s:%hu proto %s", 
           rhost ? rhost : "any", eport, iaddr, iport, protostr);
    
    return 0;
}

int
add_filter_rule2(const char * ifname,
                 const char * rhost, const char * iaddr,
                 unsigned short eport, unsigned short iport,
                 int proto, const char * desc)
{
    /* Filter rule is already added in add_redirect_rule2 */
    UNUSED(ifname); UNUSED(rhost); UNUSED(iaddr);
    UNUSED(eport); UNUSED(iport); UNUSED(proto); UNUSED(desc);
    return 0;
}

int
delete_redirect_rule(const char * ifname, unsigned short eport, int proto)
{
    char cmd[512];
    char protostr[8];
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return -1;
    }
    
    /* Convert protocol to string */
    if (proto == IPPROTO_TCP)
        strcpy(protostr, "tcp");
    else if (proto == IPPROTO_UDP)
        strcpy(protostr, "udp");
    else {
        syslog(LOG_ERR, "Unknown protocol %d", proto);
        return -1;
    }
    
    /* Create a temporary file with empty rules */
    FILE *file = fopen(PF_RULES_FILE, "w");
    if (!file) {
        syslog(LOG_ERR, "Unable to create temporary PF rules file");
        return -1;
    }
    
    fprintf(file, "# Empty ruleset for miniupnpd-nat anchor\n");
    fprintf(file, "# Used to delete port forward for %s:%hu proto %s\n", ifname, eport, protostr);
    
    fclose(file);
    
    /* Apply the empty ruleset to replace all rules in the anchor */
    snprintf(cmd, sizeof(cmd), "pfctl -a %s -f %s", nat_anchor_name, PF_RULES_FILE);
    exec_cmd(cmd);
    
    /* Clean up */
    unlink(PF_RULES_FILE);
    
    syslog(LOG_NOTICE, "Removed port forwarding for %s:%hu proto %s", 
           ifname, eport, protostr);
    
    return 0;
}

int
delete_redirect_and_filter_rules(const char * ifname, unsigned short eport,
                                 int proto)
{
    /* Delete both redirect and filter rules */
    if (delete_redirect_rule(ifname, eport, proto) < 0)
        return -1;
    
    /* Also try to clean up any matching filter rules */
    if (delete_filter_rule(ifname, eport, proto) < 0)
        return -1;
    
    return 0;
}

int
delete_filter_rule(const char * ifname, unsigned short port, int proto)
{
    char cmd[512];
    char protostr[8];
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return -1;
    }
    
    /* Convert protocol to string */
    if (proto == IPPROTO_TCP)
        strcpy(protostr, "tcp");
    else if (proto == IPPROTO_UDP)
        strcpy(protostr, "udp");
    else {
        syslog(LOG_ERR, "Unknown protocol %d", proto);
        return -1;
    }
    
    /* Create a temporary file with empty rules */
    FILE *file = fopen(PF_RULES_FILE, "w");
    if (!file) {
        syslog(LOG_ERR, "Unable to create temporary PF rules file");
        return -1;
    }
    
    fprintf(file, "# Empty ruleset for miniupnpd filter anchor\n");
    fprintf(file, "# Used to delete filter rule for %s:%hu proto %s\n", ifname, port, protostr);
    
    fclose(file);
    
    /* Apply the empty ruleset to replace all rules in the anchor */
    snprintf(cmd, sizeof(cmd), "pfctl -a %s -f %s", anchor_name, PF_RULES_FILE);
    exec_cmd(cmd);
    
    /* Clean up */
    unlink(PF_RULES_FILE);
    
    syslog(LOG_NOTICE, "Removed filter rule for %s:%hu proto %s", 
           ifname, port, protostr);
    
    return 0;
}

int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen,
                  char * rhost, int rhostlen,
                  unsigned int * timestamp,
                  u_int64_t * packets, u_int64_t * bytes)
{
    char cmd[512];
    char tmpfile[64] = "/tmp/miniupnpd-getrule-XXXXXX";
    char protostr[8];
    FILE *file;
    int fd, result = -1;
    
    UNUSED(desc); UNUSED(desclen);
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return -1;
    }
    
    /* Convert protocol to string */
    if (proto == IPPROTO_TCP)
        strcpy(protostr, "tcp");
    else if (proto == IPPROTO_UDP)
        strcpy(protostr, "udp");
    else {
        syslog(LOG_ERR, "Unknown protocol %d", proto);
        return -1;
    }
    
    /* Create a temporary file */
    fd = mkstemp(tmpfile);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to create temp file");
        return -1;
    }
    close(fd);
    
    /* Get the NAT rules and store in temp file */
    snprintf(cmd, sizeof(cmd), 
             "pfctl -a %s -sn 2>/dev/null | grep 'proto %s' | grep 'port = %hu' > %s",
             nat_anchor_name, protostr, eport, tmpfile);
    exec_cmd(cmd);
    
    /* Read the rule info from the temp file */
    file = fopen(tmpfile, "r");
    if (file) {
        char line[512];
        if (fgets(line, sizeof(line), file)) {
            /* Extract internal IP and port */
            char *arrow = strstr(line, "->");
            if (arrow) {
                char *ipaddrport = arrow + 3;
                char *portstart = strstr(ipaddrport, "port ");
                
                if (portstart) {
                    /* Get IP address */
                    *portstart = '\0';
                    strncpy(iaddr, ipaddrport, iaddrlen - 1);
                    iaddr[iaddrlen - 1] = '\0';
                    
                    /* Remove trailing spaces */
                    char *end = iaddr + strlen(iaddr) - 1;
                    while (end > iaddr && isspace(*end))
                        *end-- = '\0';
                    
                    /* Get port */
                    if (iport) {
                        *iport = (unsigned short)atoi(portstart + 5);
                    }
                    
                    /* Extract remote host if available */
                    if (rhost && rhostlen > 0) {
                        char *from = strstr(line, "from ");
                        if (from) {
                            from += 5;
                            char *to = strstr(from, " to ");
                            if (to) {
                                *to = '\0';
                                strncpy(rhost, from, rhostlen - 1);
                                rhost[rhostlen - 1] = '\0';
                            } else {
                                rhost[0] = '\0';
                            }
                        } else {
                            rhost[0] = '\0';
                        }
                    }
                    
                    /* Set timestamp */
                    if (timestamp)
                        *timestamp = (unsigned int)time(NULL);
                    
                    /* Try to get traffic stats (packets/bytes) */
                    if (packets)
                        *packets = 0;
                    if (bytes)
                        *bytes = 0;
                    
                    result = 0;
                }
            }
        }
        fclose(file);
    }
    
    /* Clean up */
    unlink(tmpfile);
    
    return result;
}

int
get_redirect_rule_by_index(int index,
                           char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen,
                           unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes)
{
    char cmd[512];
    char tmpfile[64] = "/tmp/miniupnpd-getallrules-XXXXXX";
    FILE *file;
    int fd, i = 0, result = -1;
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return -1;
    }
    
    /* Initialize output variables */
    if (ifname)
        ifname[0] = '\0';
    if (eport)
        *eport = 0;
    if (iaddr && iaddrlen > 0)
        iaddr[0] = '\0';
    if (iport)
        *iport = 0;
    if (proto)
        *proto = 0;
    if (desc && desclen > 0)
        desc[0] = '\0';
    if (rhost && rhostlen > 0)
        rhost[0] = '\0';
    if (timestamp)
        *timestamp = 0;
    if (packets)
        *packets = 0;
    if (bytes)
        *bytes = 0;
    
    /* Create a temporary file */
    fd = mkstemp(tmpfile);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to create temp file");
        return -1;
    }
    close(fd);
    
    /* Get all NAT rules and store in temp file */
    snprintf(cmd, sizeof(cmd), 
             "pfctl -a %s -sn 2>/dev/null > %s",
             nat_anchor_name, tmpfile);
    exec_cmd(cmd);
    
    /* Read the rules from the temp file */
    file = fopen(tmpfile, "r");
    if (file) {
        char line[512];
        while (fgets(line, sizeof(line), file)) {
            if (i == index) {
                /* Extract info from the rule */
                char *on = strstr(line, "on ");
                char *proto_str = strstr(line, "proto ");
                char *from = strstr(line, "from ");
                char *to = strstr(line, "to ");
                char *arrow = strstr(line, "->");
                
                /* Get interface name */
                if (ifname && on) {
                    char *space = strchr(on + 3, ' ');
                    if (space) {
                        int len = space - (on + 3);
                        strncpy(ifname, on + 3, len);
                        ifname[len] = '\0';
                    }
                }
                
                /* Get protocol */
                if (proto && proto_str) {
                    char protoname[8];
                    char *space = strchr(proto_str + 6, ' ');
                    if (space) {
                        int len = space - (proto_str + 6);
                        strncpy(protoname, proto_str + 6, len);
                        protoname[len] = '\0';
                        
                        if (strcmp(protoname, "tcp") == 0)
                            *proto = IPPROTO_TCP;
                        else if (strcmp(protoname, "udp") == 0)
                            *proto = IPPROTO_UDP;
                    }
                }
                
                /* Get remote host */
                if (rhost && rhostlen > 0 && from && to) {
                    from += 5;
                    int len = to - from - 1;
                    if (len > 0 && len < rhostlen) {
                        strncpy(rhost, from, len);
                        rhost[len] = '\0';
                    }
                }
                
                /* Get external port */
                if (eport && to) {
                    char *port = strstr(to, "port ");
                    if (port) {
                        *eport = (unsigned short)atoi(port + 5);
                    }
                }
                
                /* Get internal address and port */
                if (arrow) {
                    char *ipaddrport = arrow + 3;
                    char *portstart = strstr(ipaddrport, "port ");
                    
                    if (iaddr && iaddrlen > 0 && portstart) {
                        /* Get IP address */
                        *portstart = '\0';
                        strncpy(iaddr, ipaddrport, iaddrlen - 1);
                        iaddr[iaddrlen - 1] = '\0';
                        
                        /* Remove trailing spaces */
                        char *end = iaddr + strlen(iaddr) - 1;
                        while (end > iaddr && isspace(*end))
                            *end-- = '\0';
                    }
                    
                    /* Get port */
                    if (iport && portstart) {
                        *iport = (unsigned short)atoi(portstart + 5);
                    }
                }
                
                /* Set timestamp */
                if (timestamp)
                    *timestamp = (unsigned int)time(NULL);
                
                result = 0;
                break;
            }
            i++;
        }
        fclose(file);
    }
    
    /* Clean up */
    unlink(tmpfile);
    
    return result;
}

#ifdef TEST
int
clear_redirect_rules(void)
{
    char cmd[512];
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return -1;
    }
    
    /* Clear all NAT rules */
    snprintf(cmd, sizeof(cmd), "pfctl -a %s -F rules", nat_anchor_name);
    if (exec_cmd(cmd) != 0) {
        syslog(LOG_ERR, "Failed to clear NAT rules");
        return -1;
    }
    
    return 0;
}

int
clear_filter_rules(void)
{
    char cmd[512];
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return -1;
    }
    
    /* Clear all filter rules */
    snprintf(cmd, sizeof(cmd), "pfctl -a %s -F rules", anchor_name);
    if (exec_cmd(cmd) != 0) {
        syslog(LOG_ERR, "Failed to clear filter rules");
        return -1;
    }
    
    return 0;
}

int
clear_nat_rules(void)
{
    return clear_redirect_rules();
}
#endif

int
get_redirect_rule_count(const char * ifname)
{
    char cmd[512];
    char tmpfile[64] = "/tmp/miniupnpd-countnat-XXXXXX";
    FILE *file;
    int fd, count = 0;
    
    UNUSED(ifname);
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return 0;
    }
    
    /* Create a temporary file */
    fd = mkstemp(tmpfile);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to create temp file");
        return 0;
    }
    close(fd);
    
    /* Count NAT rules */
    snprintf(cmd, sizeof(cmd), 
             "pfctl -a %s -sn 2>/dev/null | wc -l > %s",
             nat_anchor_name, tmpfile);
    exec_cmd(cmd);
    
    /* Read the count from the file */
    file = fopen(tmpfile, "r");
    if (file) {
        fscanf(file, "%d", &count);
        fclose(file);
    }
    
    /* Clean up */
    unlink(tmpfile);
    
    return count;
}

unsigned short *
get_portmappings_in_range(unsigned short startport, unsigned short endport,
                          int proto, unsigned int * number)
{
    char cmd[512];
    char tmpfile[64] = "/tmp/miniupnpd-getports-XXXXXX";
    char protostr[8];
    FILE *file;
    int fd, count = 0, i = 0;
    unsigned short *ports = NULL;
    
    if (number)
        *number = 0;
    
    if (dev < 0) {
        syslog(LOG_ERR, "PF not initialized");
        return NULL;
    }
    
    /* Convert protocol to string */
    if (proto == IPPROTO_TCP)
        strcpy(protostr, "tcp");
    else if (proto == IPPROTO_UDP)
        strcpy(protostr, "udp");
    else {
        syslog(LOG_ERR, "Unknown protocol %d", proto);
        return NULL;
    }
    
    /* Create a temporary file */
    fd = mkstemp(tmpfile);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to create temp file");
        return NULL;
    }
    close(fd);
    
    /* Get ports in range */
    snprintf(cmd, sizeof(cmd), 
             "pfctl -a %s -sn 2>/dev/null | grep 'proto %s' | grep -o 'port = [0-9]*' | cut -d' ' -f3 > %s",
             nat_anchor_name, protostr, tmpfile);
    exec_cmd(cmd);
    
    /* First pass - count ports in range */
    file = fopen(tmpfile, "r");
    if (file) {
        int port;
        while (fscanf(file, "%d", &port) == 1) {
            if (port >= startport && port <= endport) {
                count++;
            }
        }
        fclose(file);
    }
    
    if (count == 0) {
        unlink(tmpfile);
        return NULL;
    }
    
    /* Allocate memory for the ports */
    ports = malloc(count * sizeof(unsigned short));
    if (!ports) {
        syslog(LOG_ERR, "Failed to allocate memory for ports");
        unlink(tmpfile);
        return NULL;
    }
    
    /* Second pass - collect the ports */
    file = fopen(tmpfile, "r");
    if (file) {
        int port;
        while (fscanf(file, "%d", &port) == 1 && i < count) {
            if (port >= startport && port <= endport) {
                ports[i++] = (unsigned short)port;
            }
        }
        fclose(file);
    }
    
    /* Clean up */
    unlink(tmpfile);
    
    if (number)
        *number = count;
    
    return ports;
}

int
update_portmapping(const char * ifname, unsigned short eport, int proto,
                   unsigned short iport, const char * desc,
                   unsigned int timestamp)
{
    char iaddr[64];
    unsigned short old_iport;
    char old_desc[64];
    char rhost[64];
    unsigned int old_timestamp;
    u_int64_t packets, bytes;
    
    /* Get the existing port mapping */
    if (get_redirect_rule(ifname, eport, proto,
                         iaddr, sizeof(iaddr), &old_iport,
                         old_desc, sizeof(old_desc),
                         rhost, sizeof(rhost),
                         &old_timestamp, &packets, &bytes) < 0) {
        return -1;
    }
    
    /* Delete the existing rule */
    if (delete_redirect_and_filter_rules(ifname, eport, proto) < 0) {
        return -1;
    }
    
    /* Add the updated rule */
    if (add_redirect_rule2(ifname, rhost, eport, iaddr, iport, proto, desc, timestamp) < 0) {
        return -1;
    }
    
    return 0;
}

int
update_portmapping_desc_timestamp(const char * ifname,
                   unsigned short eport, int proto,
                   const char * desc, unsigned int timestamp)
{
    char iaddr[64];
    unsigned short iport;
    char rhost[64];
    u_int64_t packets, bytes;
    
    /* Get the existing port mapping */
    if (get_redirect_rule(ifname, eport, proto,
                         iaddr, sizeof(iaddr), &iport,
                         NULL, 0,
                         rhost, sizeof(rhost),
                         NULL, &packets, &bytes) < 0) {
        return -1;
    }
    
    /* Delete the existing rule */
    if (delete_redirect_and_filter_rules(ifname, eport, proto) < 0) {
        return -1;
    }
    
    /* Add the updated rule */
    if (add_redirect_rule2(ifname, rhost, eport, iaddr, iport, proto, desc, timestamp) < 0) {
        return -1;
    }
    
    return 0;
}