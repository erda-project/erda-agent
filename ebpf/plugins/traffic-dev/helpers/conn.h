typedef struct {
    __u32 saddr;
    __u32 daddr;
    unsigned short sport;
    unsigned short dport;
    __u8 proto;
} conn_info_t;