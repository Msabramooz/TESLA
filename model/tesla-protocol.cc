//
// Created by mohammadrezasabramooz on 8/16/25.
//

/*
 * TESLA Protocol Implementation for NS-3
 */

#include "../model/tesla-protocol.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/net-device.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/data-rate.h"
#include "ns3/random-variable-stream.h"
#include "ns3/socket-factory.h"
#include "ns3/type-id.h"
#include "ns3/node.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cstring>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("TeslaProtocol");

// -----------------------------------------------------------------------------
// TeslaHeader Implementation
// -----------------------------------------------------------------------------

NS_OBJECT_ENSURE_REGISTERED(TeslaHeader);
    NS_OBJECT_ENSURE_REGISTERED(TeslaKeyChain);

TeslaHeader::TeslaHeader() : m_intervalIndex(0) {
    memset(m_mac, 0, sizeof(m_mac));
    memset(m_disclosedKey, 0, sizeof(m_disclosedKey));
}

TeslaHeader::~TeslaHeader() {}


struct IfBinding {
  int32_t     ifIndex = -1;
  Ipv4Address local   = Ipv4Address::GetZero();
};

IfBinding FindBroadcastBinding(Ptr<Node> node, Ipv4Address bcast) {
  IfBinding out;
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  if (!ipv4) return out;

  for (uint32_t i = 0; i < ipv4->GetNInterfaces(); ++i) {
    for (uint32_t j = 0; j < ipv4->GetNAddresses(i); ++j) {
      Ipv4InterfaceAddress ifa = ipv4->GetAddress(i, j);
      auto local = ifa.GetLocal();
      if (local == Ipv4Address::GetZero()) continue;      // skip down/invalid
      if (bcast == ifa.GetBroadcast()) {                  // subnet broadcast match
        out.ifIndex = static_cast<int32_t>(i);
        out.local   = local;
        return out;
      }
    }
  }
  return out;
}


bool IsSubnetBroadcastForThisNode(Ptr<Node> node, Ipv4Address dst) {
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  if (!ipv4) return false;
  for (uint32_t i = 0; i < ipv4->GetNInterfaces(); ++i) {
    for (uint32_t j = 0; j < ipv4->GetNAddresses(i); ++j) {
      Ipv4InterfaceAddress ifa = ipv4->GetAddress(i, j);
      if (ifa.GetLocal() == Ipv4Address::GetZero()) continue; // skip down/invalid
      if (dst == ifa.GetBroadcast()) return true;             // subnet bcast match
    }
  }
  return false;
}

int32_t GetIfIndexForSubnetBroadcast(Ptr<Node> node, Ipv4Address dst) {
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  if (!ipv4) return -1;
  for (uint32_t i = 0; i < ipv4->GetNInterfaces(); ++i) {
    for (uint32_t j = 0; j < ipv4->GetNAddresses(i); ++j) {
      Ipv4InterfaceAddress ifa = ipv4->GetAddress(i, j);
      if (ifa.GetLocal() == Ipv4Address::GetZero()) continue; // skip down/invalid
      if (dst == ifa.GetBroadcast()) return static_cast<int32_t>(i);
    }
  }
  return -1;
}


TypeId TeslaHeader::GetTypeId(void) {
      static TypeId tid = TypeId("ns3::TeslaHeader")
    .SetParent<Header>()
    .AddConstructor<TeslaHeader>();
  return tid;
}

    TypeId TeslaKeyChain::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::TeslaKeyChain")
        .SetParent<Object>()
        .SetGroupName("Applications")
        .AddConstructor<TeslaKeyChain>();
    return tid;
}

TypeId TeslaHeader::GetInstanceTypeId(void) const {
    return GetTypeId();
}

void TeslaHeader::Print(std::ostream& os) const
{
  os << " id=" << m_packetId
   << " interval=" << m_intervalIndex
   << " payloadLen=" << m_payloadLen;
}


uint32_t TeslaHeader::GetSerializedSize(void) const {
    // id(4) + interval(4) + mac(32) + key(32) + payloadLen(4)
    return 4 + 4 + 32 + 32 + 4;
}

void TeslaHeader::Serialize(Buffer::Iterator i) const {
	i.WriteU32(m_packetId);
	i.WriteU32(m_intervalIndex);
	i.Write(m_mac, 32);
	i.Write(m_disclosedKey, 32);
	i.WriteU32(m_payloadLen);
}

uint32_t TeslaHeader::Deserialize(Buffer::Iterator i) {
    m_packetId      = i.ReadU32();
	m_intervalIndex = i.ReadU32();
	i.Read(m_mac, 32);
	i.Read(m_disclosedKey, 32);
	m_payloadLen    = i.ReadU32();
  	return GetSerializedSize();
}


void TeslaHeader::SetMAC(const uint8_t* mac, uint32_t n)
{
  NS_ASSERT(n == 32);
  std::copy(mac, mac + 32, m_mac);
}


void TeslaHeader::GetMAC(uint8_t* mac) const {
    memcpy(mac, m_mac, 32);
}

void TeslaHeader::SetDisclosedKey(const uint8_t* key, uint32_t n)
{
  NS_ASSERT(n == 32);
  std::copy(key, key + 32, m_disclosedKey);
}

void TeslaHeader::GetDisclosedKey(uint8_t* key) const {
    memcpy(key, m_disclosedKey, 32);
}

std::vector<uint8_t> TeslaReceiver::ComputeHash(const std::vector<uint8_t>& input) {
  std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
  SHA256(input.data(), input.size(), output.data());
  return output;
}

// -----------------------------------------------------------------------------
// TeslaKeyChain Implementation
// -----------------------------------------------------------------------------

TeslaKeyChain::TeslaKeyChain(uint32_t length) : m_length(length) {
    m_keyChain.resize(length);
    m_macKeyChain.resize(length);
}

TeslaKeyChain::~TeslaKeyChain() {}

void TeslaKeyChain::Generate(const std::string& seed) {
    NS_LOG_FUNCTION(this << seed);

    // Generate K_N from seed
    std::vector<uint8_t> seedBytes(seed.begin(), seed.end());
    m_keyChain[m_length - 1] = HashFunction(seedBytes);

    // Generate chain backwards: K_i = F(K_{i+1})
    for (int i = m_length - 2; i >= 0; i--) {
        m_keyChain[i] = HashFunction(m_keyChain[i + 1]);
    }

    // Generate MAC keys: K'_i = F'(K_i)
    for (uint32_t i = 0; i < m_length; i++) {
        m_macKeyChain[i] = PseudoRandomFunction(m_keyChain[i], 1);
    }

    NS_LOG_INFO("Generated key chain of length " << m_length);
}

std::vector<uint8_t> TeslaKeyChain::GetKey(uint32_t index) {
    NS_ASSERT(index < m_length);
    return m_keyChain[index];
}

std::vector<uint8_t> TeslaKeyChain::GetMacKey(uint32_t index) {
    NS_ASSERT(index < m_length);
    return m_macKeyChain[index];
}

bool TeslaKeyChain::VerifyKey(const std::vector<uint8_t>& key, uint32_t index) {
    if (index >= m_length) return false;

    // Verify by checking if F^{n-i}(key) = K_0
    std::vector<uint8_t> temp = key;
    for (uint32_t j = index; j > 0; j--) {
        temp = HashFunction(temp);
    }

    return (temp == m_keyChain[0]);
}

std::vector<uint8_t> TeslaKeyChain::GetCommitment() {
    return m_keyChain[0];
}

std::vector<uint8_t> TeslaKeyChain::HashFunction(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    SHA256(input.data(), input.size(), output.data());
    return output;
}

std::vector<uint8_t> TeslaKeyChain::PseudoRandomFunction(const std::vector<uint8_t>& key, uint8_t label) {
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    std::vector<uint8_t> input = {label};

    unsigned int len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), key.data(), key.size(),
         input.data(), input.size(), output.data(), &len);

    return output;
}

// -----------------------------------------------------------------------------
// TeslaSender Implementation
// -----------------------------------------------------------------------------

NS_OBJECT_ENSURE_REGISTERED(TeslaSender);

TypeId TeslaSender::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::TeslaSender")
        .SetParent<Application>()
        .SetGroupName("Applications")
        .AddConstructor<TeslaSender>()
        .AddAttribute("DataRate",
                     "The data rate for sending packets",
                     DataRateValue(DataRate("500kb/s")),
                     MakeDataRateAccessor(&TeslaSender::m_dataRate),
                     MakeDataRateChecker())
        .AddAttribute("PacketSize",
                     "Size of packets to send",
                     UintegerValue(1024),
                     MakeUintegerAccessor(&TeslaSender::m_packetSize),
                     MakeUintegerChecker<uint32_t>());
    return tid;
}

TeslaSender::TeslaSender() = default;

TeslaSender::~TeslaSender() { m_socket = 0; }

void TeslaSender::Setup(Address peer, uint16_t port, uint32_t packetSize,
                        DataRate rate, const TeslaParams& p) {

 m_peerAddress = peer;
  m_peerPort    = port;
  m_packetSize  = packetSize;
  m_dataRate    = rate;
  m_params      = p;

  NS_ASSERT_MSG(m_packetSize > 0, "PacketSize must be > 0");
  NS_ASSERT_MSG(m_keyChain, "SetKeyChain() must be called before Start");

}

void TeslaSender::StartApplication()
{
  if (!m_socket) {
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    m_socket = Socket::CreateSocket(GetNode(), tid);

    if (InetSocketAddress::IsMatchingType(m_peerAddress)) {
      InetSocketAddress peer = InetSocketAddress::ConvertFrom(m_peerAddress);
      Ipv4Address dst = peer.GetIpv4();
      uint16_t dstPort = (m_peerPort != 0) ? m_peerPort : peer.GetPort();


      Ptr<Ipv4> ip = GetNode()->GetObject<Ipv4>();
      int32_t ifIndex = ip->GetInterfaceForPrefix(dst, Ipv4Mask("255.255.255.0"));
      if (ifIndex < 0) { ifIndex = ip->GetInterfaceForAddress(Ipv4Address("10.1.1.1")); }
      Ptr<NetDevice> dev = ip->GetNetDevice(static_cast<uint32_t>(ifIndex));
      if (dev) {
        m_socket->BindToNetDevice(dev);
      }
      m_socket->Bind();
      m_socket->SetAllowBroadcast(true);

      if (dst.IsBroadcast() || dst == Ipv4Address("255.255.255.255")) {
        m_isBroadcast = true;
        m_broadcastAddress = InetSocketAddress(dst, dstPort);
      } else {
        m_isBroadcast = false;
        NS_ABORT_IF(m_socket->Connect(InetSocketAddress(dst, dstPort)) != 0);
      }
    } else {
      NS_ABORT_MSG("Unsupported address type");
    }
  }

  NS_ASSERT(m_keyChain);
  SendPacket();
}




void TeslaSender::StopApplication(void) {
    NS_LOG_FUNCTION(this);

    if (m_socket) {
        m_socket->Close();
        m_socket = 0;
    }

    Simulator::Cancel(m_sendEvent);
}

void TeslaSender::SendPacket(void) {
    NS_LOG_FUNCTION(this);

    Ptr<Packet> packet = Create<Packet>(m_packetSize);

    uint32_t currentInterval = GetCurrentInterval();

	if (currentInterval >= m_params.chainLength) {
 		NS_LOG_WARN("Out of keys (interval " << currentInterval << "). Stopping sender.");
  		return;
	}

    // Create TESLA header
    TeslaHeader teslaHeader;
    teslaHeader.SetIntervalIndex(currentInterval);

    // Compute MAC using current interval key
    std::vector<uint8_t> mac = ComputeMAC(packet, currentInterval);
    teslaHeader.SetMAC(mac.data(), mac.size());

    // Disclose key from d intervals ago
    if (currentInterval >= m_params.disclosureDelay) {
        uint32_t disclosureInterval = currentInterval - m_params.disclosureDelay;
		if (disclosureInterval < m_params.chainLength){
        std::vector<uint8_t> disclosedKey = m_keyChain->GetKey(disclosureInterval);
        teslaHeader.SetDisclosedKey(disclosedKey.data(), disclosedKey.size());
		}
    }

    // Add header to packet
    packet->AddHeader(teslaHeader);

    // Send packet
    if (m_isBroadcast) {
     // Send for broadcaset
        m_socket->SendTo(packet, 0, m_broadcastAddress);
        NS_LOG_INFO("Broadcast packet " << m_packetsSent << " in interval " << currentInterval);
    } else {
        // Send for unicast
        m_socket->Send(packet);
        NS_LOG_INFO("Sent packet " << m_packetsSent << " in interval " << currentInterval);
    }

    m_packetsSent++;

    // next transmission
    ScheduleTransmit(m_dataRate.CalculateBytesTxTime(m_packetSize));
}

void TeslaSender::ScheduleTransmit(Time dt) {
    NS_LOG_FUNCTION(this << dt);
    m_sendEvent = Simulator::Schedule(dt, &TeslaSender::SendPacket, this);
}

uint32_t TeslaSender::GetCurrentInterval(void) {
      int64_t num = (Simulator::Now() - m_params.startTime).GetNanoSeconds();
      int64_t den = m_params.intervalDuration.GetNanoSeconds();
      return (num > 0 && den > 0) ? static_cast<uint32_t>(num / den) : 0;
}

std::vector<uint8_t> TeslaSender::ComputeMAC(Ptr<Packet> packet, uint32_t interval) {
  // Get MAC key for this interval
  std::vector<uint8_t> macKey = m_keyChain->GetMacKey(interval);

  // Payload --> buffer
  std::vector<uint8_t> buf(packet->GetSize());
  packet->CopyData(buf.data(), buf.size());

  // HMAC-SHA256
  std::vector<uint8_t> mac(SHA256_DIGEST_LENGTH);
  unsigned int macLen = mac.size();
  HMAC(EVP_sha256(), macKey.data(), macKey.size(),
       buf.data(), buf.size(), mac.data(), &macLen);

  return mac;
}

// -----------------------------------------------------------------------------
// TeslaReceiver Implementation
// -----------------------------------------------------------------------------

NS_OBJECT_ENSURE_REGISTERED(TeslaReceiver);

TypeId TeslaReceiver::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::TeslaReceiver")
        .SetParent<Application>()
        .SetGroupName("Applications")
        .AddConstructor<TeslaReceiver>()
        .AddAttribute("MaxTimeSyncError",
                     "Maximum time synchronization error",
                     TimeValue(MilliSeconds(100)),
                     MakeTimeAccessor(&TeslaReceiver::m_maxTimeSyncError),
                     MakeTimeChecker());
    return tid;
}

TeslaReceiver::TeslaReceiver() :
  m_socket(0),
  m_packetsReceived(0),
  m_packetsAuthenticated(0)
{}

TeslaReceiver::~TeslaReceiver() { m_socket = 0;}

void TeslaReceiver::Setup(Address address, uint16_t port, const TeslaParams& params) {
    NS_LOG_FUNCTION(this);
    m_localAddress = address;
    m_localPort = port;
    m_params = params;
}

void TeslaReceiver::SetKeyCommitment(const std::vector<uint8_t>& commitment) {
    m_keyCommitment = commitment;
}

void TeslaReceiver::StartApplication(void) {
    NS_LOG_FUNCTION(this);

    if (!m_socket) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket(GetNode(), tid);

        if (InetSocketAddress::IsMatchingType(m_localAddress)) {
            InetSocketAddress local = InetSocketAddress::ConvertFrom(m_localAddress);
            m_socket->Bind(InetSocketAddress(local.GetIpv4(), m_localPort));
            NS_LOG_INFO("Receiver bound to " << local.GetIpv4() << ":" << m_localPort);
        } else if (Inet6SocketAddress::IsMatchingType(m_localAddress)) {
            Inet6SocketAddress local = Inet6SocketAddress::ConvertFrom(m_localAddress);
            m_socket->Bind(Inet6SocketAddress(local.GetIpv6(), m_localPort));
            NS_LOG_INFO("Receiver bound to " << local.GetIpv6() << ":" << m_localPort);
        }
    }

    m_socket->SetRecvCallback(MakeCallback(&TeslaReceiver::HandleRead, this));
}

void TeslaReceiver::StopApplication(void) {
    NS_LOG_FUNCTION(this);

    if (m_socket) {
        m_socket->Close();
        m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        m_socket = 0;
    }

    NS_LOG_INFO("Receiver stats: Received=" << m_packetsReceived
                << " Authenticated=" << m_packetsAuthenticated);
}

void TeslaReceiver::HandleRead(Ptr<Socket> socket) {
    NS_LOG_FUNCTION(this << socket);

    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        m_packetsReceived++;

        TeslaHeader teslaHeader;
        packet->RemoveHeader(teslaHeader);

        uint32_t packetInterval = teslaHeader.GetIntervalIndex();

        // Check if packet is safe
        if (IsPacketSafe(packetInterval)) {
            // Buffer the packet for later authentication
            BufferPacket(packet, teslaHeader);
            NS_LOG_INFO("Buffered safe packet from interval " << packetInterval);
        } else {
            NS_LOG_WARN("Dropped unsafe packet from interval " << packetInterval);
        }

        // Process disclosed key
        uint8_t disclosedKey[32];
        teslaHeader.GetDisclosedKey(disclosedKey);

        bool hasKey = false;
        for (int i = 0; i < 32; i++) {
            if (disclosedKey[i] != 0) {
                hasKey = true;
                break;
            }
        }

        if (hasKey && packetInterval >= m_params.disclosureDelay) {
            std::vector<uint8_t> keyVec(disclosedKey, disclosedKey + 32);
            uint32_t keyInterval = packetInterval - m_params.disclosureDelay;
            AuthenticateBufferedPackets(keyVec, keyInterval);
        }
    }
}

bool TeslaReceiver::IsPacketSafe(uint32_t packetInterval) {
     const int64_t tint = m_params.intervalDuration.GetNanoSeconds();
  	 const int64_t t0   = m_params.startTime.GetNanoSeconds();
     const int64_t trecv= Simulator::Now().GetNanoSeconds();
     const int64_t delta= m_maxTimeSyncError.GetNanoSeconds();

     // x = floor((t_recv + Δ − T0) / Tint)
     int64_t num = (trecv + delta) - t0;
     uint32_t x = (num > 0 && tint > 0) ? static_cast<uint32_t>(num / tint) : 0;

     // safe iff x < i + d
     return x < packetInterval + m_params.disclosureDelay;
}

void TeslaReceiver::BufferPacket(Ptr<Packet> packet, const TeslaHeader& header) {
    BufferedPacket bp;
    bp.packet = packet;
    bp.interval = header.GetIntervalIndex();
    header.GetMAC(bp.mac);
    bp.receiveTime = Simulator::Now();

    m_packetBuffer.push(bp);
}

bool TeslaReceiver::VerifyDisclosedKey(const std::vector<uint8_t>& key, uint32_t interval) {
    NS_LOG_FUNCTION(this << interval);

    if (m_verifiedKeys.find(interval) != m_verifiedKeys.end()) {
        return (m_verifiedKeys[interval] == key);
    }


    if (!m_keyCommitment.empty()) {
        std::vector<uint8_t> computed = key;

        for (uint32_t i = 0; i < interval; i++) {
            computed = ComputeHash(computed);
        }

        if (computed == m_keyCommitment) {
            NS_LOG_INFO("Key for interval " << interval << " verified against commitment");
            return true;
        }
    }


    for (const auto& [verifiedInterval, verifiedKey] : m_verifiedKeys) {
        if (verifiedInterval < interval) {

            std::vector<uint8_t> computed = key;

            for (uint32_t i = 0; i < (interval - verifiedInterval); i++) {
                computed = ComputeHash(computed);
            }

            if (computed == verifiedKey) {
                NS_LOG_INFO("Key for interval " << interval
                           << " verified against key from interval " << verifiedInterval);
                return true;
            }
        }
        else if (verifiedInterval > interval) {

            std::vector<uint8_t> computed = verifiedKey;

            for (uint32_t i = 0; i < (verifiedInterval - interval); i++) {
                computed = ComputeHash(computed);
            }

            if (computed == key) {
                NS_LOG_INFO("Key for interval " << interval
                           << " verified against future key from interval " << verifiedInterval);
                return true;
            }
        }
    }

    NS_LOG_WARN("Failed to verify key for interval " << interval);
    return false;
}

void TeslaReceiver::ProcessAuthenticatedPacket(Ptr<Packet> packet) {
    NS_LOG_INFO("========== AUTHENTICATED PACKET ==========");
    NS_LOG_INFO("Receiver Node " << GetNode()->GetId()
                << " authenticated packet at " << Simulator::Now().GetSeconds() << "s");

    // Extract packet data
    uint32_t packetSize = packet->GetSize();
    uint8_t* buffer = new uint8_t[packetSize];
    packet->CopyData(buffer, packetSize);

    std::string message(reinterpret_cast<char*>(buffer), packetSize);

    size_t msgEnd = message.find('\0');
    if (msgEnd != std::string::npos) {
        message = message.substr(0, msgEnd);
    }

    // message content
    NS_LOG_INFO("Message content: \"" << message << "\"");

    NS_LOG_INFO("Stats -> Received: " << m_packetsReceived
                << ", Authenticated: " << m_packetsAuthenticated
                << ", Buffered: " << m_packetBuffer.size());
    NS_LOG_INFO("=========================================\n");

    delete[] buffer;
}


void TeslaReceiver::AuthenticateBufferedPackets(const std::vector<uint8_t>& disclosedKey,uint32_t keyInterval) {
    NS_LOG_FUNCTION(this << keyInterval);

    // Verify the disclosed key
    if (!VerifyDisclosedKey(disclosedKey, keyInterval)) {
        NS_LOG_WARN("Failed to verify disclosed key for interval " << keyInterval);
        return;
    }

    m_verifiedKeys[keyInterval] = disclosedKey;
    NS_LOG_INFO("Verified key for interval " << keyInterval);

    // Authenticate buffered packets from this interval
    std::queue<BufferedPacket> tempBuffer;

    while (!m_packetBuffer.empty()) {
        BufferedPacket bp = m_packetBuffer.front();
        m_packetBuffer.pop();

        if (bp.interval == keyInterval) {
            // Verify MAC using the verified key
            if (VerifyMAC(bp.packet, disclosedKey, bp.mac)) {
                m_packetsAuthenticated++;
                NS_LOG_INFO("Authenticated packet from interval " << keyInterval);

                // Process authenticated packet here
                ProcessAuthenticatedPacket(bp.packet);
            } else {
                NS_LOG_WARN("MAC verification failed for packet from interval " << keyInterval);
            }
        } else if (bp.interval > keyInterval) {
            // Keep for  authentcation
            tempBuffer.push(bp);
        }
        // Packets from intervals < keyInterval are dropped
    }

    m_packetBuffer = tempBuffer;
}


uint32_t TeslaReceiver::GetCurrentInterval(void) {
      int64_t num = (Simulator::Now() - m_params.startTime).GetNanoSeconds();
      int64_t den = m_params.intervalDuration.GetNanoSeconds();
      return (num > 0 && den > 0) ? static_cast<uint32_t>(num / den) : 0;
}

bool TeslaReceiver::VerifyMAC(Ptr<Packet> packet, const std::vector<uint8_t>& key,
                              const uint8_t* mac) {
	  // Derive MAC key from disclosed key (label = 1)
  	  std::vector<uint8_t> macKey(SHA256_DIGEST_LENGTH);
  	  const std::vector<uint8_t> label = {1};
  	  unsigned int macKeyLen = macKey.size();
      HMAC(EVP_sha256(), key.data(), key.size(),label.data(), label.size(), macKey.data(), &macKeyLen);

 	  // Payload --> buffer
      std::vector<uint8_t> buf(packet->GetSize());
      packet->CopyData(buf.data(), buf.size());

      // Compute MAC
      std::vector<uint8_t> computedMac(SHA256_DIGEST_LENGTH);
      unsigned int computedMacLen = computedMac.size();
      HMAC(EVP_sha256(), macKey.data(), macKey.size(),buf.data(), buf.size(), computedMac.data(), &computedMacLen);

      // Compare
      return memcmp(mac, computedMac.data(), SHA256_DIGEST_LENGTH) == 0;
}

// -----------------------------------------------------------------------------
// TeslaTimeSync Implementation
// -----------------------------------------------------------------------------

Time TeslaTimeSync::s_maxSyncError = MilliSeconds(100);

Time TeslaTimeSync::PerformTimeSync(Ptr<Node> sender, Ptr<Node> receiver) {
    // Simple time sync simulation
    // include network round-trip
    Time currentTime = Simulator::Now();

    Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable>();
    double errorMs = rand->GetValue(0, s_maxSyncError.GetMilliSeconds());

    return MilliSeconds(errorMs);
}

void TeslaTimeSync::SetMaxSyncError(Time maxError) {
    s_maxSyncError = maxError;
}

Time TeslaTimeSync::GetMaxSyncError(void) {
    return s_maxSyncError;
}



} // namespace ns3
