//
// Created by mohammadrezasabramooz on 8/16/25.
//

/*
 * TESLA Protocol Implementation for NS-3
 */

#ifndef TESLA_PROTOCOL_H
#define TESLA_PROTOCOL_H

#include "ns3/application.h"
#include "ns3/packet.h"
#include "ns3/address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/traced-callback.h"
#include "ns3/data-rate.h"
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/header.h"
#include <queue>
#include <map>
#include <vector>
#include <string>

namespace ns3 {

// TESLA Parameters structure
struct TeslaParams {
    uint32_t chainLength;
    Time intervalDuration;
    Time startTime;
    uint32_t disclosureDelay;
    uint32_t currentInterval;
};

// TeslaHeader class
class TeslaHeader : public Header {
public:
  static TypeId GetTypeId(void);
  TypeId GetInstanceTypeId(void) const override;

  TeslaHeader();
  ~TeslaHeader() override;

  // ns-3 Header overrides
  uint32_t GetSerializedSize(void) const override;
  void Serialize(Buffer::Iterator start) const override;
  uint32_t Deserialize(Buffer::Iterator start) override;
  void Print(std::ostream& os) const override;

  // Setters
  void SetPacketId(uint32_t id)                 { m_packetId = id; }
  void SetIntervalIndex(uint32_t index)         { m_intervalIndex = index; }

  void SetKeyInterval(uint32_t index)           { m_intervalIndex = index; }
  void SetPayloadLen(uint32_t len)              { m_payloadLen = len; }
  void SetMAC(const uint8_t* mac, uint32_t n);
  void SetDisclosedKey(const uint8_t* key, uint32_t n);

  // Getters
  uint32_t GetPacketId() const                  { return m_packetId; }
  uint32_t GetIntervalIndex(void) const         { return m_intervalIndex; }
  // Back-compat alias
  uint32_t GetKeyInterval(void) const           { return m_intervalIndex; }
  uint32_t GetPayloadLen() const                { return m_payloadLen; }

  const uint8_t* GetMAC() const                 { return m_mac; }
  const uint8_t* GetDisclosedKey() const        { return m_disclosedKey; }

  void GetMAC(uint8_t* out) const;
  void GetDisclosedKey(uint8_t* out) const;

private:
  uint32_t m_packetId{0};
  uint32_t m_intervalIndex{0};
  uint32_t m_payloadLen{0};
  uint8_t  m_mac[32]{};
  uint8_t  m_disclosedKey[32]{};

};

// TeslaKeyChain
class TeslaKeyChain : public Object {
public:
    static TypeId GetTypeId(void);

    TeslaKeyChain(uint32_t length);
    TeslaKeyChain() : m_length(0) {}
    virtual ~TeslaKeyChain();

    void Generate(const std::string& seed);
    std::vector<uint8_t> GetKey(uint32_t index);
    std::vector<uint8_t> GetMacKey(uint32_t index);
    bool VerifyKey(const std::vector<uint8_t>& key, uint32_t index);
    std::vector<uint8_t> GetCommitment();
    std::vector<uint8_t> HashFunction(const std::vector<uint8_t>& input);

private:

    std::vector<uint8_t> PseudoRandomFunction(const std::vector<uint8_t>& key, uint8_t label);

    uint32_t m_length;
    std::vector<std::vector<uint8_t>> m_keyChain;
    std::vector<std::vector<uint8_t>> m_macKeyChain;
};

// TeslaSender class
class TeslaSender : public Application {
public:
    static TypeId GetTypeId (void);
    TeslaSender();
    ~TeslaSender() override;

    void Setup(Address peer, uint16_t port, uint32_t packetSize,
               DataRate dataRate, const TeslaParams& params);
    void SetKeyChain(Ptr<TeslaKeyChain> kc) { m_keyChain = kc; }

private:
    void StartApplication() override;
    void StopApplication() override;
    void SendPacket();
    void ScheduleTransmit(Time dt);
    uint32_t GetCurrentInterval();
    std::vector<uint8_t> ComputeMAC(Ptr<Packet> pkt, uint32_t interval);

    // Keep order and single declarations only
    Address              m_peerAddress;
    uint16_t             m_peerPort{0};
    bool                 m_isBroadcast{false};

    Ptr<Socket>          m_socket{nullptr};
    EventId              m_sendEvent;
    DataRate             m_dataRate{DataRate("500kb/s")};
    uint32_t             m_packetSize{0};
    Address              m_broadcastAddress;

    TeslaParams          m_params;
    Ptr<TeslaKeyChain>   m_keyChain{nullptr};
    uint32_t             m_packetsSent{0};
};

// TeslaReceiver class
class TeslaReceiver : public Application {
public:
    static TypeId GetTypeId (void);
    TeslaReceiver();
    ~TeslaReceiver() override;

    void Setup(Address address, uint16_t port, const TeslaParams& params);

    void SetKeyCommitment(const std::vector<uint8_t>& commitment);

private:
    void StartApplication() override;
    void StopApplication() override;
    uint32_t GetCurrentInterval(void);
    void HandleRead(Ptr<Socket> socket);
    bool IsPacketSafe(uint32_t packetInterval);
    void BufferPacket(Ptr<Packet> packet, const TeslaHeader& header);
    bool VerifyDisclosedKey(const std::vector<uint8_t>& key, uint32_t interval);
    void ProcessAuthenticatedPacket(Ptr<Packet> packet);
    void AuthenticateBufferedPackets(const std::vector<uint8_t>& disclosedKey, uint32_t keyInterval);
    bool VerifyMAC(Ptr<Packet> packet, const std::vector<uint8_t>& key, const uint8_t* mac);

    static std::vector<uint8_t> ComputeHash(const std::vector<uint8_t>& input);

    // receiver state
    Address   m_localAddress;
    uint16_t  m_localPort{0};
    TeslaParams m_params;

    Ptr<Socket> m_socket{nullptr};
    uint32_t    m_packetsReceived{0};
    uint32_t    m_packetsAuthenticated{0};

    // attribute used in GetTypeId()
    Time m_maxTimeSyncError{MilliSeconds(100)};

    struct BufferedPacket {
        Ptr<Packet> packet;
        uint32_t    interval;
        uint8_t     mac[32];
        Time        receiveTime;
    };

    std::queue<BufferedPacket>                 m_packetBuffer;
    std::map<uint32_t, std::vector<uint8_t>>   m_verifiedKeys;
    std::vector<uint8_t>                       m_keyCommitment;
};

// TeslaTimeSync helper class
class TeslaTimeSync {
public:
    static Time PerformTimeSync(Ptr<Node> sender, Ptr<Node> receiver);
    static void SetMaxSyncError(Time maxError);
    static Time GetMaxSyncError(void);

private:
    static Time s_maxSyncError;
};

} // namespace ns3

#endif /* TESLA_PROTOCOL_H */