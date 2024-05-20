#ifndef __AMQP_DEFS_H
#define __AMQP_DEFS_H

typedef enum {
    PROG_UNKNOWN = 0,
    PROG_AMQP_FILTER,
} protocol_prog_t;

typedef enum {
    AMQP_UNKNOWN = 0,
    AMQP_PUBLISH,
    AMQP_CONSUME,
} amqp_type;

#define AMQP_PREFACE "AMQP"

// RabbitMQ supported classes.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
#define AMQP_CONNECTION_CLASS 10
#define AMQP_BASIC_CLASS 60
#define AMQP_CHANNEL_CLASS 20
#define AMPQ_QUEUE_CLASS 50

//#define AMQP_METHOD_CLOSE_OK 40
#define AMQP_METHOD_CLOSE 41

#define AMQP_METHOD_CONNECTION_START 10
#define AMQP_METHOD_CONNECTION_START_OK 11

#define AMQP_METHOD_CONNECTION_CLOSE 50
#define AMQP_METHOD_CONNECTION_CLOSE_OK 51

#define AMQP_METHOD_CONSUME 20
#define AMQP_METHOD_PUBLISH 40
#define AMQP_METHOD_DELIVER 60
#define AMQP_METHOD_BIND 20
#define AMQP_FRAME_METHOD_TYPE 1

#define AMQP_MIN_FRAME_LENGTH 8
#define AMQP_MIN_PAYLOAD_LENGTH 11
#define AMQP_QUEUE_MAX_LENGTH 10

#define AMQP_LENGTH_SIZE 4

typedef struct {
    __u8 type;
    __u16 channel;
    __u32 size;
    __u16 class_id;
    __u16 method_id;
} amqp_header;

typedef struct {
    char queue[AMQP_QUEUE_MAX_LENGTH]; // queue name
    char exchange[AMQP_QUEUE_MAX_LENGTH]; // exchange name
    amqp_type type;
    __u32 count;
    __u32 duration;
} amqp_event;

typedef struct {
    amqp_header hdr;
    amqp_event event;
} amqp_data;

struct amqp_trace {
    __u32 dstIP;
    __u32 dstPort;
    __u32 srcIP;
    __u32 srcPort;
    amqp_event event;
};

#endif
