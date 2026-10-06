// EF-01 over UART, the minimum for charm.ask: build a command, read acks, run AutoIdentify. Ported from OpenCharm's
// firmware (firmware/main/charm/ef01.cc, fingerprint.cc), which also enrols and manages templates; here enrolment is
// done with the OpenCharm firmware or the module vendor's tool, and this build only matches.
#include "opencharm_fp.h"

#include <string.h>
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

static const char *TAG = "charm.fp";
#define FP_UART          UART_NUM_1
#define FP_TX            17
#define FP_RX            18
#define FP_BAUD          57600
#define INS_READ_SYS     0x0F
#define INS_AUTO_IDENT   0x32
#define INS_CANCEL       0x30
#define PID_COMMAND      0x01
#define CC_OK            0x00

static SemaphoreHandle_t s_lock;
static bool s_online;

// EF 01 | FF FF FF FF | PID | LEN(2) | INS | params | SUM(2); LEN and SUM cover from PID.
static int build(uint8_t *out, uint8_t ins, const uint8_t *params, int n) {
    int i = 0;
    out[i++] = 0xEF; out[i++] = 0x01; out[i++] = 0xFF; out[i++] = 0xFF; out[i++] = 0xFF; out[i++] = 0xFF;
    out[i++] = PID_COMMAND;
    uint16_t len = (uint16_t)(n + 1 + 2);
    out[i++] = (uint8_t)(len >> 8); out[i++] = (uint8_t)len; out[i++] = ins;
    memcpy(out + i, params, n); i += n;
    uint16_t sum = 0;
    for (int k = 6; k < i; k++) sum = (uint16_t)(sum + out[k]);
    out[i++] = (uint8_t)(sum >> 8); out[i++] = (uint8_t)sum;
    return i;
}

static void send(uint8_t ins, const uint8_t *params, int n) {
    uint8_t buf[32];
    int len = build(buf, ins, params, n);
    uart_flush_input(FP_UART);
    uart_write_bytes(FP_UART, buf, len);
}

// Reads one ack packet body (cc + params) before the deadline; resyncs on garbage. Returns the body length or -1.
static int read_ack(uint8_t *body, int cap, TickType_t deadline) {
    uint8_t buf[64]; int n = 0;
    for (;;) {
        TickType_t now = xTaskGetTickCount();
        if ((int32_t)(deadline - now) <= 0) return -1;
        uint8_t b;
        if (uart_read_bytes(FP_UART, &b, 1, deadline - now) != 1) return -1;
        if (n < (int)sizeof(buf)) buf[n++] = b;
        // drop leading bytes until the header magic lines up
        while (n > 0 && (buf[0] != 0xEF || (n > 1 && buf[1] != 0x01))) { memmove(buf, buf + 1, --n); }
        if (n < 9) continue;
        int len = (buf[7] << 8) | buf[8];
        if (len < 2 || 9 + len > (int)sizeof(buf)) { memmove(buf, buf + 1, --n); continue; }
        if (n < 9 + len) continue;
        uint16_t sum = 0;
        for (int k = 6; k < 9 + len - 2; k++) sum = (uint16_t)(sum + buf[k]);
        if (sum != (uint16_t)((buf[9 + len - 2] << 8) | buf[9 + len - 1])) { memmove(buf, buf + 1, --n); continue; }
        int blen = len - 2;
        if (blen > cap) blen = cap;
        memcpy(body, buf + 9, blen);
        return blen;
    }
}

bool opencharm_fp_init(void) {
    s_lock = xSemaphoreCreateMutex();
    uart_config_t cfg = {
        .baud_rate = FP_BAUD, .data_bits = UART_DATA_8_BITS, .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1, .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };
    esp_err_t err = uart_driver_install(FP_UART, 512, 0, 0, NULL, 0);
    if (err == ESP_OK) err = uart_param_config(FP_UART, &cfg);
    if (err == ESP_OK) err = uart_set_pin(FP_UART, FP_TX, FP_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) { ESP_LOGE(TAG, "uart init failed: %s", esp_err_to_name(err)); return false; }
    uint8_t body[32];
    for (int attempt = 0; attempt < 2 && !s_online; attempt++) {
        send(INS_READ_SYS, NULL, 0);
        int n = read_ack(body, sizeof(body), xTaskGetTickCount() + pdMS_TO_TICKS(300));
        s_online = n >= 1 && body[0] == CC_OK;
    }
    ESP_LOGI(TAG, "fingerprint module %s", s_online ? "online" : "not answering (charm.ask will deny)");
    return s_online;
}

bool opencharm_fp_online(void) { return s_online; }

opencharm_fp_result_t opencharm_fp_identify(int timeout_ms) {
    opencharm_fp_result_t r = {false, -1, 0, "module_offline"};
    if (!s_online) return r;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    static const uint8_t params[] = {0x03, 0xFF, 0xFF, 0x00, 0x00};   // score level 3, 1:N, step replies
    send(INS_AUTO_IDENT, params, sizeof(params));
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    uint8_t body[32];
    r.reason = "timeout";
    for (;;) {
        int n = read_ack(body, sizeof(body), deadline);
        if (n < 0) break;
        if (body[0] != CC_OK) { r.reason = "no_match"; break; }       // any error code ends the flow (0x09 not found)
        if (n < 2 || body[1] != 0x05) continue;                        // step reply: image taken, features extracted...
        if (n < 6) { r.reason = "bad_reply"; break; }
        r.allow = true; r.slot = (body[2] << 8) | body[3]; r.score = (body[4] << 8) | body[5]; r.reason = "match";
        break;
    }
    if (!r.allow) send(INS_CANCEL, NULL, 0);   // stop a still-running AutoIdentify
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "identify: %s slot=%d score=%d", r.reason, r.slot, r.score);
    return r;
}
