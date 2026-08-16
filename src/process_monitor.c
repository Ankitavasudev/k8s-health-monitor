/*
 * Process Monitor - C helper for k8s-health-monitor
 * Monitors container processes and collects resource usage
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct {
    pid_t pid;
    char name[256];
    float cpu_usage;
    float memory_usage;
    int status;
} ProcessInfo;

ProcessInfo* create_process_info(pid_t pid, const char* name) {
    ProcessInfo* info = (ProcessInfo*)malloc(sizeof(ProcessInfo));
    if (info == NULL) return NULL;
    
    info->pid = pid;
    strncpy(info->name, name, sizeof(info->name) - 1);
    info->cpu_usage = 0.0f;
    info->memory_usage = 0.0f;
    info->status = 0;
    return info;
}

void destroy_process_info(ProcessInfo* info) {
    if (info != NULL) {
        free(info);
    }
}

int read_process_status(ProcessInfo* info) {
    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", info->pid);
    
    FILE* file = fopen(path, "r");
    if (file == NULL) return -1;
    
    char state;
    if (fscanf(file, "%*d %*s %c", &state) == 1) {
        info->status = (int)state;
    }
    
    fclose(file);
    return 0;
}

float calculate_cpu_usage(pid_t pid) {
    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    
    FILE* file = fopen(path, "r");
    if (file == NULL) return 0.0f;
    
    unsigned long utime, stime;
    if (fscanf(file, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %lu %lu", &utime, &stime) == 2) {
        fclose(file);
        return (float)(utime + stime) / sysconf(_SC_CLK_TCK);
    }
    
    fclose(file);
    return 0.0f;
}

int is_process_running(pid_t pid) {
    char path[512];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    
    struct stat st;
    return (stat(path, &st) == 0);
}

int main() {
    printf("Process Monitor v1.0\n");
    printf("Monitoring container processes...\n");
    return 0;
}
