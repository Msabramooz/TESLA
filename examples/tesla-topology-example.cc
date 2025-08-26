//
// Created by mohammadrezasabramooz on 8/18/25.
//

/*
 * TESLA Protocol Example for NS-3
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "../model/tesla-protocol.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4.h"
#include <memory>
#include <sstream>
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TeslaTopologyExample");

class TeslaTopologyExample {
public:
    TeslaTopologyExample() :
        m_nNodes(7),
        m_senderNode(0),
        m_port(9999) {}

    void RunBroadcastTopology();
    void RunStarTopology();
    void RunMeshTopology();
    void RunRingTopology();

private:
    void SetupTeslaApplications();
    void ConfigureAnimation(std::string filename);

    uint32_t m_nNodes;
    uint32_t m_senderNode;
    uint16_t m_port;
    NodeContainer m_nodes;
    NetDeviceContainer m_devices;
    Ipv4InterfaceContainer m_interfaces;
    TeslaParams m_teslaParams;
    Ptr<TeslaKeyChain> m_keyChain;
};


static std::string BuildAnimFilename(const std::string& topology)
{
    std::ostringstream oss;
    oss << "tesla-" << topology << ".xml";
    return oss.str();
}

// Create AnimationInterface
static std::unique_ptr<AnimationInterface>
CreateAnimationForTopology(const std::string& topology)
{
    const Time poll = MilliSeconds(100);

    std::string file = BuildAnimFilename(topology);   // keep std::string alive
    auto anim = std::make_unique<AnimationInterface>(file);
    anim->SetMobilityPollInterval(poll);

    return anim;
}

// Broadcast topology using CSMA
void TeslaTopologyExample::RunBroadcastTopology() {
    using namespace ns3;
    NS_LOG_INFO("=== Running BROADCAST Topology Example ===");

    // Create nodes
    m_nodes.Create(m_nNodes);

    // Setup CSMA
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));

    // Connect all nodes to the same CSMA network
    m_devices = csma.Install(m_nodes);

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(m_nodes);

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    m_interfaces = ipv4.Assign(m_devices);

    // Position nodes
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue(0.0),
                                 "MinY", DoubleValue(0.0),
                                 "DeltaX", DoubleValue(20.0),
                                 "DeltaY", DoubleValue(20.0),
                                 "GridWidth", UintegerValue(3),
                                 "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(m_nodes);

    // Setup TESLA
    SetupTeslaApplications();

    // Configure animation

    auto anim = CreateAnimationForTopology("broadcast");  // Store animation on tesla-broadcast.xml

    // Run simulation
    NS_LOG_INFO("Starting BROADCAST topology simulation");
    Simulator::Stop(Seconds(20.0));
    Simulator::Run();
    Simulator::Destroy();
}

// Star topology
void TeslaTopologyExample::RunStarTopology() {
    NS_LOG_INFO("=== Running STAR Topology Example ===");

    // Create nodes
    m_nodes.Create(m_nNodes);
    uint32_t hubNode = m_nNodes / 2;

    // Setup point-to-point links in star pattern
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    // Connect all nodes to hub
    for (uint32_t i = 0; i < m_nNodes; i++) {
        if (i != hubNode) {
            NetDeviceContainer link = p2p.Install(
                NodeContainer(m_nodes.Get(hubNode), m_nodes.Get(i)));
            m_devices.Add(link);
        }
    }

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(m_nodes);

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.252");
    for (uint32_t i = 0; i < m_devices.GetN(); i += 2) {
        ipv4.Assign(NetDeviceContainer(m_devices.Get(i), m_devices.Get(i+1)));
        ipv4.NewNetwork();
    }

    // Enable routing
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Position nodes for visualization
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();

    // Hub at center
    posAlloc->Add(Vector(50, 50, 0));

    // Other nodes in circle
    double radius = 30.0;
    for (uint32_t i = 0; i < m_nNodes; i++) {
        if (i != hubNode) {
            double angle = 2 * M_PI * i / (m_nNodes - 1);
            posAlloc->Add(Vector(50 + radius * cos(angle),
                                50 + radius * sin(angle), 0));
        }
    }

    mobility.SetPositionAllocator(posAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(m_nodes);

    // Setup TESLA
    SetupTeslaApplications();

    // Configure animation
    auto anim = CreateAnimationForTopology("star");

    // Run simulation
    NS_LOG_INFO("Starting STAR topology simulation");
    Simulator::Stop(Seconds(20.0));
    Simulator::Run();
    Simulator::Destroy();
}

// Mesh topology
void TeslaTopologyExample::RunMeshTopology() {
    NS_LOG_INFO("=== Running MESH Topology Example ===");

    // Create nodes
    m_nodes.Create(m_nNodes);

    // Setup point-to-point links in mesh pattern
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("2Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("5ms"));

    // Connect every node to every other node
    for (uint32_t i = 0; i < m_nNodes - 1; i++) {
        for (uint32_t j = i + 1; j < m_nNodes; j++) {
            NetDeviceContainer link = p2p.Install(
                NodeContainer(m_nodes.Get(i), m_nodes.Get(j)));
            m_devices.Add(link);
        }
    }

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(m_nodes);

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.2.1.0", "255.255.255.252");
    for (uint32_t i = 0; i < m_devices.GetN(); i += 2) {
        ipv4.Assign(NetDeviceContainer(m_devices.Get(i), m_devices.Get(i+1)));
        ipv4.NewNetwork();
    }

    // Enable routing
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Position nodes in grid
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue(0.0),
                                 "MinY", DoubleValue(0.0),
                                 "DeltaX", DoubleValue(20.0),
                                 "DeltaY", DoubleValue(20.0),
                                 "GridWidth", UintegerValue(3),
                                 "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(m_nodes);

    // Setup TESLA
    SetupTeslaApplications();

    // Configure animation
    auto anim = CreateAnimationForTopology("mesh");

    // Run simulation
    NS_LOG_INFO("Starting MESH topology simulation");
    Simulator::Stop(Seconds(20.0));
    Simulator::Run();
    Simulator::Destroy();
}

// Ring topology
void TeslaTopologyExample::RunRingTopology() {
    NS_LOG_INFO("=== Running RING Topology Example ===");

    // Create nodes
    m_nodes.Create(m_nNodes);

    // Setup point-to-point links in ring pattern
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("1ms"));

    // Connect nodes in a ring
    for (uint32_t i = 0; i < m_nNodes; i++) {
        uint32_t next = (i + 1) % m_nNodes;
        NetDeviceContainer link = p2p.Install(
            NodeContainer(m_nodes.Get(i), m_nodes.Get(next)));
        m_devices.Add(link);
    }

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(m_nodes);

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.3.1.0", "255.255.255.252");
    for (uint32_t i = 0; i < m_devices.GetN(); i += 2) {
        ipv4.Assign(NetDeviceContainer(m_devices.Get(i), m_devices.Get(i+1)));
        ipv4.NewNetwork();
    }

    // Enable routing
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Position nodes in circle
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();

    double radius = 40.0;
    for (uint32_t i = 0; i < m_nNodes; i++) {
        double angle = 2 * M_PI * i / m_nNodes;
        posAlloc->Add(Vector(50 + radius * cos(angle),
                            50 + radius * sin(angle), 0));
    }

    mobility.SetPositionAllocator(posAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(m_nodes);

    // Setup TESLA
    SetupTeslaApplications();

    // Configure animation
    auto anim = CreateAnimationForTopology("ring");

    // Run simulation
    NS_LOG_INFO("Starting RING topology simulation");
    Simulator::Stop(Seconds(20.0));
    Simulator::Run();
    Simulator::Destroy();
}

// Setup TESLA
void TeslaTopologyExample::SetupTeslaApplications() {
  // --- TESLA parameters ---
  m_teslaParams.chainLength      = 200;
  m_teslaParams.intervalDuration = MilliSeconds(100);
  m_teslaParams.startTime        = Seconds(1.0);
  m_teslaParams.disclosureDelay  = 2;
  m_teslaParams.currentInterval  = 0;

  // --- Shared key-chain + commitment
  m_keyChain = Create<TeslaKeyChain>(m_teslaParams.chainLength);
  m_keyChain->Generate("TOPOLOGY_EXAMPLE_SEED");
  std::vector<uint8_t> commitment = m_keyChain->GetCommitment();


  auto pickNodeAddress = [&](uint32_t i) -> Ipv4Address {

    if (m_interfaces.GetN() >= m_nNodes) {
      return m_interfaces.GetAddress(i);
    }

    Ptr<Ipv4> ip = m_nodes.Get(i)->GetObject<Ipv4>();
    for (uint32_t ifx = 0; ifx < ip->GetNInterfaces(); ++ifx) {
      for (uint32_t a = 0; a < ip->GetNAddresses(ifx); ++a) {
        Ipv4InterfaceAddress ifa = ip->GetAddress(ifx, a);
        Ipv4Address local = ifa.GetLocal();
        if (local != Ipv4Address::GetZero() && local != Ipv4Address("127.0.0.1")) {
          return local;
        }
      }
    }
    return Ipv4Address("0.0.0.0");
  };

  // --- Receivers
  for (uint32_t i = 0; i < m_nNodes; ++i) {
    if (i == m_senderNode) continue;

    NS_LOG_INFO("Setting up TESLA receiver on node " << i);
    Ptr<TeslaReceiver> rx = CreateObject<TeslaReceiver>();
    m_nodes.Get(i)->AddApplication(rx);

    rx->Setup(InetSocketAddress(Ipv4Address::GetAny(), m_port),
              m_port, m_teslaParams);
    rx->SetKeyCommitment(commitment);
    rx->SetAttribute("MaxTimeSyncError", TimeValue(MilliSeconds(15))); // comfortable safety margin
    rx->SetStartTime(Seconds(0.5));
    rx->SetStopTime(Seconds(20.0));
  }

  // --- Senders 
  for (uint32_t i = 0; i < m_nNodes; ++i) {
    if (i == m_senderNode) continue;

    Ipv4Address dst = pickNodeAddress(i);
    NS_LOG_INFO("Setting up TESLA unicast sender to node " << i << " at " << dst);

    Ptr<TeslaSender> s = CreateObject<TeslaSender>();
    m_nodes.Get(m_senderNode)->AddApplication(s);

    // Share the exact same key-chain with the sender
    s->SetKeyChain(m_keyChain);

    // Unicast destination to that receiver
    s->Setup(InetSocketAddress(dst, m_port),
             m_port,
             256, DataRate("10kb/s"), m_teslaParams);

    s->SetStartTime(m_teslaParams.startTime);
    s->SetStopTime(Seconds(19.0));
  }
}



void TeslaTopologyExample::ConfigureAnimation(std::string filename) {

    AnimationInterface anim(filename);

    // Set node descriptions
    anim.UpdateNodeDescription(m_senderNode, "SENDER");
    for (uint32_t i = 0; i < m_nNodes; i++) {
        if (i != m_senderNode) {
            anim.UpdateNodeDescription(i, "R" + std::to_string(i));
        }
    }

    // Set node colors
    anim.UpdateNodeColor(m_senderNode, 255, 0, 0);
    for (uint32_t i = 0; i < m_nNodes; i++) {
        if (i != m_senderNode) {
            anim.UpdateNodeColor(i, 0, 255, 0);
        }
    }
}

int main(int argc, char *argv[]) {
    // Command line parameters
    std::string topology = "broadcast";
    bool verbose = false;

    CommandLine cmd;
    cmd.AddValue("topology", "Topology type (broadcast|star|mesh|ring)", topology);
    cmd.AddValue("verbose", "Enable verbose logging", verbose);
    cmd.Parse(argc, argv);



    if (verbose) {
        LogComponentEnable("TeslaProtocol", LOG_LEVEL_ALL);
        LogComponentEnable("TeslaTopologyExample", LOG_LEVEL_ALL);
        /** Stack-level tracing
        LogComponentEnable("Ipv4L3Protocol", LOG_LEVEL_ALL);
        LogComponentEnable("UdpSocketImpl", LOG_LEVEL_ALL);
        LogComponentEnable("ArpCache", LOG_LEVEL_ALL); */
    }


    // Create and run example
    TeslaTopologyExample example;

    if (topology == "broadcast") {
        example.RunBroadcastTopology();
    } else if (topology == "star") {
        example.RunStarTopology();
    } else if (topology == "mesh") {
        example.RunMeshTopology();
    } else if (topology == "ring") {
        example.RunRingTopology();
    } else {
        NS_LOG_ERROR("Unknown topology: " << topology);
        NS_LOG_ERROR("Valid options: broadcast, star, mesh, ring");
        return 1;
    }

    NS_LOG_INFO("Example completed successfully");
    return 0;
}