#ifndef __PORT_RANGE_H
#define __PORT_RANGE_H

__maybe_unused static __always_inline void flip_tuple(conn_tuple_t *t) {
    // TODO: we can probably replace this by swap operations
    __u16 tmp_port = t->sport;
    t->sport = t->dport;
    t->dport = tmp_port;

    __u64 tmp_ip_part = t->saddr_l;
    t->saddr_l = t->daddr_l;
    t->daddr_l = tmp_ip_part;

    tmp_ip_part = t->saddr_h;
    t->saddr_h = t->daddr_h;
    t->daddr_h = tmp_ip_part;
}

static __always_inline __u16 ephemeral_range_begin() {
    __u64 val = 0;
    LOAD_CONSTANT("ephemeral_range_begin", val);
    return (__u16) val;
}

static __always_inline __u16 ephemeral_range_end() {
    __u64 val = 0;
    LOAD_CONSTANT("ephemeral_range_end", val);
    return (__u16) val;
}

static __always_inline int is_ephemeral_port(u16 port) {
    return port >= ephemeral_range_begin() && port <= ephemeral_range_end();
}

static __always_inline bool normalize_tuple(conn_tuple_t *t) {
    if (is_ephemeral_port(t->sport) && !is_ephemeral_port(t->dport)) {
        return false;
    }

    if ((!is_ephemeral_port(t->sport) && is_ephemeral_port(t->dport)) || t->dport > t->sport) {
        flip_tuple(t);
        return true;
    }

    return false;
}

#endif
