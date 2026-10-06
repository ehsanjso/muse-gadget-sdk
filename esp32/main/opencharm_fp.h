// OpenCharm fingerprint: Hi-Link ZW0608 on UART1 (EF-01 protocol, 57600 8N1). charm.ask answers allow only when an
// enrolled finger matches; everything else (no finger, no match, module silent, timeout) is deny.
#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool allow;        // an enrolled finger matched
    int slot;          // template id on a match, else -1
    int score;
    const char *reason;   // "match", "no_match", "timeout", "module_offline"
} opencharm_fp_result_t;

// Opens the UART and probes the module. Returns false (and later asks all deny) when it does not answer.
bool opencharm_fp_init(void);
bool opencharm_fp_online(void);
// Blocks up to timeout_ms on the calling task for one AutoIdentify (1:N, score level 3). Serialized by a mutex.
opencharm_fp_result_t opencharm_fp_identify(int timeout_ms);
