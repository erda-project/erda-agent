static __always_inline bool check_integer_and_crlf(const char* buf, __u32 buf_size, int index_to_start_from, struct rpc_package_t *pkg) {
    bool is_resp = false;
    char current_char;
    int i = index_to_start_from;
//    char tmp[REDIS_MAX_COMMAND_LENGTH];
//    int j = 0;
//    bool find_cr = false;
//    bool find_lf = false;
#pragma unroll(CLASSIFICATION_MAX_BUFFER)
    for (; i < CLASSIFICATION_MAX_BUFFER;i++) {
        current_char = buf[i];
        if (current_char == '\r' && !is_resp) {
            is_resp = buf[i+1] == '\n';
            if (!is_resp) {
                return false;
            }
            pkg->phase = P_REQUEST;
            break;
        }
        // Parsing redis commands in the kernel
//        else if (is_resp) {
//            if (current_char == '\r' || current_char == '$') {
////                if (current_char == '$' && j < REDIS_MAX_COMMAND_LENGTH) {
//////                    tmp[j] = ' ';
////                    pkg->redis_cmd[j] = ' ';
////                    j++;
////                }
//                find_cr = true;
//                find_lf = false;
//                continue;
//            } else if (find_cr && current_char == '\n') {
//                find_cr = false;
//                find_lf = true;
//                continue;
//            }
//            if (j < REDIS_MAX_COMMAND_LENGTH && find_lf) {
////                tmp[j] = current_char;
////                pkg->redis_cmd[j] = buf[i];
//                j++;
//            }
//        }
    }
    if (is_resp) {
    #pragma unroll(CLASSIFICATION_MAX_BUFFER)
        for (int k = 0; k < CLASSIFICATION_MAX_BUFFER; k++) {
            pkg->path[k] = buf[k];
        }
    }
    return is_resp;
}

static __always_inline bool check_supported_ascii_and_crlf(const char* buf, __u32 buf_size, int index_to_start_from, struct rpc_package_t *pkg) {
    bool is_resp = false;
    char current_char;
    int i = index_to_start_from;
#pragma unroll(CLASSIFICATION_MAX_BUFFER)
    for (; i < CLASSIFICATION_MAX_BUFFER; i++) {
        current_char = buf[i];
        if (current_char == '\r') {
            is_resp = buf[i+1] == '\n';
            break;
        } else if ('A' <= current_char && current_char <= 'Z') {
            continue;
        } else if ('a' <= current_char && current_char <= 'z') {
            continue;
        } else if (current_char == '.' || current_char == ' ' || current_char == '-' || current_char == '_') {
            continue;
        } else if ('0' <= current_char && current_char <= '9') {
            continue;
        }
        return false;
    }
    if (is_resp) {
        pkg->phase = P_RESPONSE;
        pkg->status[0] = 'O';
    }
    return is_resp;
}

static __always_inline bool check_err_prefix(const char* buf, __u32 buf_size, struct rpc_package_t *pkg) {
#define ERR "-ERR "
#define WRONGTYPE "-WRONGTYPE "

    // memcmp returns
    // 0 when s1 == s2,
    // !0 when s1 != s2.
    bool match = !(bpf_memcmp(buf, ERR, sizeof(ERR)-1)
        && bpf_memcmp(buf, WRONGTYPE, sizeof(WRONGTYPE)-1));

    if (match) {
        pkg->status[0] = 'E';
        pkg->phase = P_RESPONSE;
    }
    return match;
}

static __always_inline bool is_redis(const char*buf, __u32 buf_size, const skb_info_t *skb_info, struct rpc_package_t *pkg) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, REDIS_MIN_FRAME_LENGTH);

    char first_char = buf[0];
    switch (first_char) {
    case '*':
        // redis request command, like echo -e "*2\r\n\$3\r\nGET\r\n\$3\r\nfoo\r\n" | nc 127.0.0.1 6379, like `GET foo` in redis cli
        return check_integer_and_crlf(buf, buf_size, 1, pkg);
    case '+':
        // redis ok response, like `+OK\r\n`
        return check_supported_ascii_and_crlf(buf, buf_size, 1, pkg);
    case '$':
        // redis ok response, like `$3\r\nbar\r\n`
        return check_supported_ascii_and_crlf(buf, buf_size, 1, pkg);
    case '-':
        // redis error response, like `-ERR Protocol error: invalid multibulk length\r\n`
        return check_err_prefix(buf, buf_size, pkg);
    default:
        return false;
    }
}