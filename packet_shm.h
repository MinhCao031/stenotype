/* Copyright (C) Cerberus - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Dao Van Huy <huy.dao@cerberus.com.vn>
 */
/*
 * File:   packet_shm.h
 * Author: Dao Van Huy <huy.dao@cerberus.com.vn>
 *
 * Created on Mon Oct 16 2023
 */

#pragma once

#include <stdio.h>
#include <pcap.h>

#ifdef __cplusplus
extern "C"
{
#endif

// Need "-lpacket_shm" to link library
// File location: /usr/local/lib/libpacket_shm.a

typedef void (*packet_process_fn)(struct pcap_pkthdr *hdr, uint8_t *data, int recv_idx);
int packet_shm_init(const char *shm_path, int n_recv_threads, packet_process_fn cb);

void packet_shm_exit(void);
void dump_recv_packet_stats(FILE *fp, int n_recv_cores);

#ifdef __cplusplus
}
#endif