// Apollo server commands: LiSendExecServerCmd() must put {index,0,0,0} on the
// wire as control packet 0x3000, reliably, on ENet channel 0x08, and refuse to
// send when the control stream is not running or the host protocol lacks the
// packet type. Host reference: Vibepollo src/stream.cpp (IDX_EXEC_SERVER_CMD).
// Rename before any ENet header is seen so prototypes and calls both point at the hooks.
#define enet_peer_send hook_enet_peer_send
#define enet_host_service hook_enet_host_service
#include "../src/ControlStream.c"

#include <stdio.h>

static int sends;
static enet_uint8 lastChannel;
static enet_uint32 lastFlags;
static unsigned char lastBytes[64];
static size_t lastLength;

int hook_enet_peer_send(ENetPeer* p, enet_uint8 channel, ENetPacket* packet) {
    (void)p;
    ++sends;
    lastChannel = channel;
    lastFlags = packet->flags;
    lastLength = packet->dataLength < sizeof(lastBytes) ? packet->dataLength : sizeof(lastBytes);
    memcpy(lastBytes, packet->data, lastLength);
    // Destroying the packet runs its free callback, which ends the sender's ack wait.
    enet_packet_destroy(packet);
    return 0;
}

int hook_enet_host_service(ENetHost* host, ENetEvent* event, enet_uint32 timeout) {
    (void)host; (void)event; (void)timeout;
    return 0;
}

static int failures;
#define CHECK(cond, what) do { if (cond) printf("PASS %s\n", what); else { printf("FAIL %s\n", what); ++failures; } } while (0)

int main(void) {
    ENetPeer fakePeer;
    memset(&fakePeer, 0, sizeof(fakePeer));
    fakePeer.channelCount = CTRL_CHANNEL_COUNT;
    fakePeer.state = ENET_PEER_STATE_CONNECTED;

    // A Sunshine-family host (negative fourth version field) on the unencrypted
    // V1 header path, so the payload is visible on the wire.
    AppVersionQuad[0] = 7; AppVersionQuad[1] = 1; AppVersionQuad[2] = 431; AppVersionQuad[3] = -1;
    encryptedControlStream = false;
    if (PltCreateMutex(&enetMutex) != 0) return 2;

    CHECK(CTRL_CHANNEL_SERVERCTL == 0x08, "server control channel is 0x08");
    CHECK(packetTypesGen7Enc[IDX_EXEC_SERVER_CMD] == 0x3000, "Gen7Enc maps exec server cmd to 0x3000");
    CHECK(packetTypesGen3[IDX_EXEC_SERVER_CMD] == -1 && packetTypesGen4[IDX_EXEC_SERVER_CMD] == -1 &&
          packetTypesGen5[IDX_EXEC_SERVER_CMD] == -1 && packetTypesGen7[IDX_EXEC_SERVER_CMD] == -1,
          "older protocol tables have no exec server cmd");
    CHECK(sizeof(packetTypesGen3) == sizeof(packetTypesGen7Enc) && sizeof(packetTypesGen4) == sizeof(packetTypesGen7Enc) &&
          sizeof(packetTypesGen5) == sizeof(packetTypesGen7Enc) && sizeof(packetTypesGen7) == sizeof(packetTypesGen7Enc),
          "all packet tables have the same length");

    // Not connected: nothing may be sent.
    packetTypes = (short*)packetTypesGen7Enc;
    peer = NULL;
    sends = 0;
    CHECK(LiSendExecServerCmd(3) != 0 && sends == 0, "refuses without a control stream");

    // Connected, stopping: nothing may be sent.
    peer = &fakePeer;
    stopping = true;
    CHECK(LiSendExecServerCmd(3) != 0 && sends == 0, "refuses while the stream is stopping");
    stopping = false;

    // Host protocol without the packet type.
    packetTypes = (short*)packetTypesGen7;
    CHECK(LiSendExecServerCmd(3) != 0 && sends == 0, "refuses when the host protocol has no exec server cmd");

    // Normal send.
    packetTypes = (short*)packetTypesGen7Enc;
    int rc = LiSendExecServerCmd(5);
    CHECK(rc == 0 && sends == 1, "sends exactly one packet");
    CHECK(lastChannel == CTRL_CHANNEL_SERVERCTL, "uses the server control channel");
    CHECK((lastFlags & ENET_PACKET_FLAG_RELIABLE) != 0, "packet is reliable");
    CHECK(lastLength == 2 + 4, "V1 header plus a 4-byte payload");
    CHECK(lastBytes[0] == 0x00 && lastBytes[1] == 0x30, "type 0x3000 little-endian");
    CHECK(lastBytes[2] == 5 && lastBytes[3] == 0 && lastBytes[4] == 0 && lastBytes[5] == 0, "payload is {index,0,0,0}");

    // Index 255 is the largest the host can address.
    sends = 0;
    CHECK(LiSendExecServerCmd(255) == 0 && sends == 1 && lastBytes[2] == 255, "index 255 is sent unchanged");

    PltDeleteMutex(&enetMutex);
    printf("%s: %d failure(s)\n", failures ? "FAILED" : "OK", failures);
    return failures ? 1 : 0;
}
