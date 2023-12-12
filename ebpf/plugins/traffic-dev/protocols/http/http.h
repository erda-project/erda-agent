#include "./../../helpers/ip.h"

typedef enum {
    HTTP_PHASE_UNKNOWN,
    HTTP_REQUEST,
	HTTP_RESPONSE,
} http_phase_t;

typedef enum {
    HTTP_METHOD_UNKNOWN,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH
} http_method_t;

typedef struct {
    __u8 method;
    __u8 phase;
    __u16 status_code;
} http_info_t;

typedef struct {
    conn_info_t conn_info;
    http_info_t http_info;
} http_event_t;

static __always_inline bool is_http_process_package(conn_info_t *conn_info) {
    if (conn_info->proto != IPPROTO_TCP) {
        return false;
    }

    return true;
}

static __always_inline void read_http_info(struct __sk_buff *skb, http_info_t *http_info, __u32 offset) {
    char p[12];
	bpf_skb_load_bytes(skb, offset, p, 12);

    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
        http_info->phase = HTTP_RESPONSE;
        return;
    }

    http_method_t method = HTTP_METHOD_UNKNOWN;
    http_phase_t phase = HTTP_REQUEST;
    
    if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3]  == ' ') && (p[4] == '/')) {
        method = HTTP_GET;
    } else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4]  == ' ') && (p[5] == '/')) {
        method = HTTP_POST;
    } else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3]  == ' ') && (p[4] == '/')) {
        method = HTTP_PUT;
    } else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E') && (p[6]  == ' ') && (p[7] == '/')) {
        method = HTTP_DELETE;
    } else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4]  == ' ') && (p[5] == '/')) {
        method = HTTP_HEAD;
    } else if ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S') && (p[7]  == ' ') && ((p[8] == '/') || (p[8] == '*'))) {
        method = HTTP_OPTIONS;
    } else if ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H') && (p[5]  == ' ') && (p[6] == '/')) {
        method = HTTP_PATCH;
    } else {
        phase = HTTP_PHASE_UNKNOWN;
    }

    http_info -> phase = phase;
    http_info -> method = method;
}