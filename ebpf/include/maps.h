#ifndef __KAFKA_MAPS_H
#define __KAFKA_MAPS_H

#include "map-defs.h"

#ifdef COMPILE_RUNTIME
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
        BPF_PERCPU_ARRAY_MAP(kafka_client_id, char [CLIENT_ID_SIZE_TO_VALIDATE], 1)
        BPF_PERCPU_ARRAY_MAP(kafka_topic_name, char [TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE], 1)
    #else
        BPF_ARRAY_MAP(kafka_client_id, __u32, 1)
        BPF_ARRAY_MAP(kafka_topic_name, __u32, 1)
    #endif

#else
    BPF_PERCPU_ARRAY_MAP(kafka_client_id, char [CLIENT_ID_SIZE_TO_VALIDATE], 1)
    BPF_PERCPU_ARRAY_MAP(kafka_topic_name, char [TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE], 1)
#endif

#endif
