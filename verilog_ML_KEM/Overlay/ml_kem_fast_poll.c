// ML-KEM-768 native driver helpers.
//
// Two layers exposed to Python via ctypes:
//  - Method C (poll-only):  mlkem_wait_done / mlkem_wait_done_iters
//  - Method C-full:         mlkem_{keygen,encaps,decaps}_run — entire
//                           per-op flow (seeds + start + poll + cycles
//                           read) is one C call. Cache flush/invalidate
//                           remain on the Python side (PYNQ allocate()).
//
// Build (on KR260):  make
// Build (manual):    gcc -O2 -Wall -shared -fPIC ml_kem_fast_poll.c -o libmlkemfast.so

#include <stdint.h>
#include <string.h>
#include <time.h>

#define REG_CTRL_WORD       0   // byte offset 0x00 / 4
#define REG_STATUS_WORD     1   // byte offset 0x04 / 4
#define REG_CYCLES_WORD     2   // byte offset 0x08 / 4
#define REG_SEED_D_WORD     4   // byte offset 0x10 / 4
#define REG_SEED_Z_WORD    12   // byte offset 0x30 / 4

#define STATUS_DONE  0x1u
#define STATUS_IDLE  0x2u
#define STATUS_ERROR 0x4u

#define CTRL_START_KEYGEN 0x1u  // op_sel=00, start=1
#define CTRL_START_ENCAPS 0x3u  // op_sel=01, start=1
#define CTRL_START_DECAPS 0x5u  // op_sel=10, start=1

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Returns:
//   >= 0  cycles count (REG_CYCLES) on DONE
//   -1    STATUS_ERROR set
//   -2    timeout
int64_t mlkem_wait_done(volatile uint32_t *regs, uint32_t timeout_us) {
    uint64_t deadline = now_ns() + (uint64_t)timeout_us * 1000ULL;
    while (1) {
        uint32_t status = regs[REG_STATUS_WORD];
        if (status & STATUS_ERROR) return -1;
        if (status & STATUS_DONE)  return (int64_t)regs[REG_CYCLES_WORD];
        if (now_ns() > deadline)   return -2;
    }
}

// Same as above but with a poll-count cap instead of wall-time. Useful for
// micro-benchmarks where you want to bound CPU spinning purely by iters.
int64_t mlkem_wait_done_iters(volatile uint32_t *regs, uint32_t max_iters) {
    for (uint32_t i = 0; i < max_iters; i++) {
        uint32_t status = regs[REG_STATUS_WORD];
        if (status & STATUS_ERROR) return -1;
        if (status & STATUS_DONE)  return (int64_t)regs[REG_CYCLES_WORD];
    }
    return -2;
}

// ---- Method C-full: per-op native driver ----------------------------------
// These functions run an entire ML-KEM operation in native C: write the
// seeds (KeyGen), pulse CTRL.start with op_sel, busy-poll STATUS, read
// REG_CYCLES. Caller (Python) is still responsible for flushing input
// buffers and invalidating output buffers via pynq.allocate().flush() /
// .invalidate() before / after the call.
//
// Returns same convention as mlkem_wait_done:
//   >= 0 : cycle count (REG_CYCLES)
//   -1   : STATUS_ERROR set
//   -2   : timeout

// KeyGen: writes seed_d (32 B), seed_z (32 B), pulses start, waits.
// seed_d and seed_z must be 32-byte buffers; system is little-endian
// (aarch64 default), so we copy 8 × uint32 directly.
int64_t mlkem_keygen_run(volatile uint32_t *regs,
                         const uint8_t *seed_d,
                         const uint8_t *seed_z,
                         uint32_t timeout_us) {
    // Unaligned-safe little-endian load. memcpy + assignment compiles to
    // a single LDR/STR pair on aarch64 with -O2.
    for (int i = 0; i < 8; i++) {
        uint32_t w_d, w_z;
        memcpy(&w_d, seed_d + i * 4, 4);
        memcpy(&w_z, seed_z + i * 4, 4);
        regs[REG_SEED_D_WORD + i] = w_d;
        regs[REG_SEED_Z_WORD + i] = w_z;
    }
    regs[REG_CTRL_WORD] = CTRL_START_KEYGEN;
    return mlkem_wait_done(regs, timeout_us);
}

// Encaps: caller has placed pk + m in DDR + flushed cache. We just trigger.
int64_t mlkem_encaps_run(volatile uint32_t *regs, uint32_t timeout_us) {
    regs[REG_CTRL_WORD] = CTRL_START_ENCAPS;
    return mlkem_wait_done(regs, timeout_us);
}

// Decaps: caller has placed sk + ct in DDR + flushed cache. We trigger.
int64_t mlkem_decaps_run(volatile uint32_t *regs, uint32_t timeout_us) {
    regs[REG_CTRL_WORD] = CTRL_START_DECAPS;
    return mlkem_wait_done(regs, timeout_us);
}
