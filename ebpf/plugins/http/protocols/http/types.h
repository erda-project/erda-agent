#define HTTP_PAYLOAD_SIZE 224
#define HTTP_PAYLOAD_BLOCK_SIZE 16
#define HTTP_STATUS_OFFSET 9
#define HTTP_PAYLOAD_PREFIX_SIZE 9

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

// TODO: Memory alignment
typedef struct {
    __u64 request_ts;
    __u64 duration;
    __u16 status_code;
    __u8 method;
    char request_fragment[HTTP_PAYLOAD_SIZE];
} __attribute__((packed)) http_info_t;
