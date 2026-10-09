#include <stdio.h>
#include "embedded_ids.h"

int main(void) {
    printf("[EIDS Initializing...]\n");
    EIDS_Init();
    printf("[EIDS Online. Monitoring Hardware Bus Layout...]\n\n");

    // Scenario A: Safe Valid Packet Passing Through
    CAN_Message_t normal_msg = {
        .id = 0x100,
        .dlc = 8,
        .data = {1, 2, 3, 4, 5, 6, 7, 8},
        .timestamp_us = 100000 // Initial time tick
    };
    
    printf("Sending Valid Packet (ID: 0x100)...\n");
    if (EIDS_AnalyzePacket(&normal_msg) == EIDS_OK) {
        printf(">> Result: PASSED safely.\n\n");
    }

    // Scenario B: Malicious Signature Attack (Known Exploit Frame)
    CAN_Message_t malicious_signature_msg = {
        .id = 0x00000666, 
        .dlc = 8,
        .data = {0},
        .timestamp_us = 105000
    };

    printf("Sending Exploit Packet (ID: 0x666)...\n");
    if (EIDS_AnalyzePacket(&malicious_signature_msg) == EIDS_ERR_THREAT) {
        printf(">> Result: THREAT LOCKED & BLOCKED via Signature!\n\n");
    }

    // Scenario C: Anomaly Attack via Injection/Flooding (Timing Violation)
    CAN_Message_t flood_msg_1 = {
        .id = 0x200, // ABS Module Baseline = min 5,000us delta
        .dlc = 4,
        .timestamp_us = 200000
    };
    
    // Process first frame to establish timing baseline
    EIDS_AnalyzePacket(&flood_msg_1);

    // Attack frame arrives only 1,000 microseconds later (Violates 5,000us baseline limit)
    CAN_Message_t flood_msg_2 = {
        .id = 0x200,
        .dlc = 4,
        .timestamp_us = 201000 
    };

    printf("Sending High-Frequency Injection Flood Packet (ID: 0x200 at +1000us)...\n");
    if (EIDS_AnalyzePacket(&flood_msg_2) == EIDS_ERR_THREAT) {
        printf(">> Result: THREAT LOCKED & BLOCKED via Behavioral Timing Anomaly!\n\n");
    }

    return 0;
}

