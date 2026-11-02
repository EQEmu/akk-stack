/* Trusted finite host fixture, unrelated to EQEmu source or candidate inputs. */
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile unsigned long accumulator;
static void pause_ms(long ms) {
    struct timespec delay = {ms / 1000, ms % 1000 * 1000000};
    nanosleep(&delay, NULL);
}
__attribute__((noinline)) void churn_allocations(void) {
    for (int i = 0; i < 20000; ++i) {
        char *temporary = malloc(4096);
        if (!temporary) _exit(3);
        memset(temporary, i, 4096);
        accumulator += temporary[i % 4096];
        free(temporary);
    }
}
__attribute__((noinline)) void busy_stack(void) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        for (int i = 0; i < 100000; ++i) accumulator += (unsigned)i;
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9 < .7);
}
__attribute__((noinline)) void live_allocation(void) {
    char *live = malloc(16 * 1024 * 1024);
    if (!live) _exit(3);
    memset(live, 37, 16 * 1024 * 1024);
    pause_ms(500);
    churn_allocations();
    busy_stack();
    accumulator += live[100];
    free(live);
    pause_ms(300);
}
int main(void) {
    pause_ms(300);
    live_allocation();
    return 0;
}
