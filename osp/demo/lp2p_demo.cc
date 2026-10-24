// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An example of the Local Peer-to-Peer data channel extension on top of the
// Open Screen Protocol: one side advertises itself (`--listen`, an
// `Lp2pReceiver`) and echoes the text it receives, the other discovers it,
// connects (`--connect`, an `Lp2pRequest`), opens a data channel and sends the
// lines it reads from stdin. Received messages are printed to stdout.

#include <charconv>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "osp/msgs/osp_messages.h"
#include "osp/public/authentication_config.h"
#include "osp/public/lp2p/lp2p_connection.h"
#include "osp/public/lp2p/lp2p_data_channel.h"
#include "osp/public/lp2p/lp2p_receiver.h"
#include "osp/public/lp2p/lp2p_request.h"
#include "osp/public/message_demuxer.h"
#include "osp/public/network_service_manager.h"
#include "osp/public/protocol_connection_client.h"
#include "osp/public/protocol_connection_client_factory.h"
#include "osp/public/protocol_connection_server.h"
#include "osp/public/protocol_connection_server_factory.h"
#include "osp/public/protocol_connection_service_observer.h"
#include "osp/public/service_config.h"
#include "osp/public/service_listener.h"
#include "osp/public/service_listener_factory.h"
#include "osp/public/service_publisher.h"
#include "osp/public/service_publisher_factory.h"
#include "platform/api/network_interface.h"
#include "platform/impl/logging.h"
#include "platform/impl/platform_client_posix.h"
#include "third_party/getopt/getopt.h"
#include "util/osp_logging.h"

namespace openscreen::osp {
namespace {

struct DemoOptions {
  std::string listen_name;
  std::string connect_name;
  std::string label = "chat";
  std::string protocol;
  uint16_t port = 6668;
  AuthenticationConfig auth_config;
  Lp2pConfig lp2p_config;
};

// Prints a line for humans and test harnesses to stdout.
void Print(std::string_view line) {
  std::cout << "lp2p_demo: " << line << std::endl;
}

std::string EncodingName(Lp2pDataEncoding encoding) {
  switch (encoding) {
    case Lp2pDataEncoding::kBlob:
      return "blob";
    case Lp2pDataEncoding::kString:
      return "string";
    case Lp2pDataEncoding::kArrayBuffer:
      return "arraybuffer";
  }
  return "unknown";
}

// Runs one side of the demo. All methods except the constructor run on the
// platform task runner.
class Lp2pDemo final : public ProtocolConnectionServiceObserver,
                       public ServiceListener::Observer,
                       public ServicePublisher::Observer,
                       public Lp2pReceiver::Delegate,
                       public Lp2pRequest::Delegate,
                       public Lp2pConnection::Delegate,
                       public Lp2pDataChannel::Delegate {
 public:
  explicit Lp2pDemo(DemoOptions options) : options_(std::move(options)) {}
  Lp2pDemo(const Lp2pDemo&) = delete;
  Lp2pDemo& operator=(const Lp2pDemo&) = delete;
  Lp2pDemo(Lp2pDemo&&) noexcept = delete;
  Lp2pDemo& operator=(Lp2pDemo&&) noexcept = delete;
  ~Lp2pDemo() override = default;

  bool is_listener() const { return !options_.listen_name.empty(); }

  void Start() {
    if (is_listener()) {
      StartListener();
    } else {
      StartConnector();
    }
  }

  void Stop() {
    channels_.clear();
    connections_.clear();
    receiver_.reset();
    request_.reset();
    // The getters of the services this side does not run CHECK.
    NetworkServiceManager* manager = NetworkServiceManager::Get();
    if (is_listener()) {
      manager->GetServicePublisher()->Stop();
      manager->GetProtocolConnectionServer()->Stop();
    } else {
      manager->GetServiceListener()->Stop();
      manager->GetProtocolConnectionClient()->Stop();
    }
    // NetworkServiceManager::Dispose() is not called: once a QUIC
    // connection was made it crashes in QUIC service teardown (the services
    // close their connections again after `Stop`, and the connection factory
    // closes connections that were already destroyed). The process exits
    // next, so the services are left alive.
  }

  // Sends `line` on every open data channel. Lines read before the first
  // channel opens are sent once it does.
  void SendLine(const std::string& line) {
    if (!has_opened_) {
      pending_lines_.push_back(line);
      return;
    }
    bool sent = false;
    for (const auto& channel : channels_) {
      if (channel->state() == Lp2pDataChannel::State::kOpen) {
        sent = channel->Send(line).ok() || sent;
      }
    }
    if (!sent) {
      Print("no open data channel, dropped: " + line);
    }
  }

  // ProtocolConnectionServiceObserver overrides.
  void OnRunning() override {}
  void OnStopped() override {}
  void OnSuspended() override {}
  void OnMetrics(const NetworkMetrics& metrics) override {}
  void OnError(const Error& error) override {
    OSP_LOG_ERROR << "error: " << error;
    if (request_ && !connected_) {
      Print("connect failed: " + error.ToString());
    }
  }
  void OnIncomingConnection(
      std::unique_ptr<ProtocolConnection> stream) override {
    if (receiver_) {
      receiver_->OnIncomingStream(std::move(stream));
    } else if (request_) {
      request_->OnIncomingStream(std::move(stream));
    }
  }

  // ServiceListener::Observer overrides.
  void OnStarted() override {}
  void OnSearching() override {}
  void OnReceiverAdded(const ServiceInfo& info) override {
    OSP_LOG_INFO << "discovered " << info.instance_name;
    if (info.instance_name != options_.connect_name || connecting_) {
      return;
    }
    connecting_ = true;
    Print("discovered " + info.instance_name + ", connecting");
    // Let the client, which observes the listener too, learn of it first.
    PlatformClientPosix::GetInstance()->GetTaskRunner().PostTask([this] {
      if (request_) {
        request_->Start(options_.connect_name, *this);
      }
    });
  }
  void OnReceiverChanged(const ServiceInfo& info) override {}
  void OnReceiverRemoved(const ServiceInfo& info) override {}
  void OnAllReceiversRemoved() override {}

  // Lp2pReceiver::Delegate and Lp2pRequest::Delegate overrides.
  void OnConnection(std::unique_ptr<Lp2pConnection> connection) override {
    connected_ = true;
    Print("connected to instance " + std::to_string(connection->instance_id()) +
          " " + connection->instance_name());
    connection->SetDelegate(this);
    if (!is_listener()) {
      ErrorOr<std::unique_ptr<Lp2pDataChannel>> channel =
          connection->CreateDataChannel(
              {.label = options_.label, .protocol = options_.protocol}, this);
      if (channel.is_error()) {
        Print("failed to open a data channel: " + channel.error().ToString());
      } else {
        channels_.push_back(std::move(channel.value()));
      }
    }
    connections_.push_back(std::move(connection));
  }

  // Lp2pConnection::Delegate overrides.
  void OnDataChannel(std::unique_ptr<Lp2pDataChannel> channel) override {
    channel->SetDelegate(this);
    OnOpen(*channel);
    channels_.push_back(std::move(channel));
  }

  // Lp2pDataChannel::Delegate overrides.
  void OnOpen(Lp2pDataChannel& channel) override {
    Print("data channel " + std::to_string(channel.id()) + " \"" +
          channel.label() + "\" open");
    if (!has_opened_) {
      has_opened_ = true;
      for (const std::string& line : pending_lines_) {
        channel.Send(line);
      }
      pending_lines_.clear();
    }
  }
  void OnMessage(Lp2pDataChannel& channel,
                 Lp2pDataEncoding encoding,
                 ByteView payload) override {
    const std::string text(payload.begin(), payload.end());
    Print("received on " + std::to_string(channel.id()) + " (" +
          EncodingName(encoding) + "): " + text);
    if (is_listener()) {
      if (encoding == Lp2pDataEncoding::kString) {
        channel.Send("echo: " + text);
      } else {
        channel.Send(payload, encoding);
      }
    }
  }
  void OnClose(Lp2pDataChannel& channel) override {
    Print("data channel " + std::to_string(channel.id()) + " closed");
  }

 private:
  std::vector<InterfaceInfo> UsableInterfaces() {
    std::vector<InterfaceInfo> interfaces;
    for (const InterfaceInfo& interface : GetNetworkInterfaces()) {
      if (!interface.addresses.empty() &&
          interface.type != InterfaceInfo::Type::kLoopback) {
        interfaces.push_back(interface);
      }
    }
    OSP_LOG_IF(WARN, interfaces.empty())
        << "No network interfaces had usable addresses for mDNS.";
    return interfaces;
  }

  AgentInfoConfig MakeAgentInfo(std::string display_name) {
    return {.display_name = std::move(display_name),
            .model_name = "Open Screen lp2p_demo",
            .capabilities = {msgs::AgentCapability::kDataChannels},
            .locales = {"en"}};
  }

  void StartListener() {
    TaskRunner& task_runner =
        PlatformClientPosix::GetInstance()->GetTaskRunner();
    ServicePublisher::Config publisher_config = {
        .instance_name = options_.listen_name,
        .connection_server_port = options_.port};
    ServiceConfig server_config = {.instance_name = options_.listen_name};
    server_config.authentication = options_.auth_config;
    server_config.agent_info = MakeAgentInfo(options_.listen_name);
    for (const InterfaceInfo& interface : UsableInterfaces()) {
      server_config.connection_endpoints.push_back(
          IPEndpoint{interface.addresses[0].address, options_.port});
      publisher_config.network_interfaces.push_back(interface);
    }

    auto server = ProtocolConnectionServerFactory::Create(
        server_config, *this, task_runner, MessageDemuxer::kDefaultBufferLimit);
    publisher_config.fingerprint = server->GetAgentFingerprint();
    publisher_config.auth_token = server->GetAuthToken();
    receiver_ = std::make_unique<Lp2pReceiver>(*server, task_runner, *this,
                                               options_.lp2p_config);

    auto publisher =
        ServicePublisherFactory::Create(publisher_config, task_runner);
    publisher->AddObserver(*this);
    auto* manager = NetworkServiceManager::Create(nullptr, std::move(publisher),
                                                  nullptr, std::move(server));
    manager->GetServicePublisher()->Start();
    manager->GetProtocolConnectionServer()->Start();
    Print("listening as " + options_.listen_name);
  }

  void StartConnector() {
    TaskRunner& task_runner =
        PlatformClientPosix::GetInstance()->GetTaskRunner();
    ServiceListener::Config listener_config;
    ServiceConfig client_config;
    client_config.authentication = options_.auth_config;
    client_config.agent_info = MakeAgentInfo("lp2p_demo requester");
    for (const InterfaceInfo& interface : UsableInterfaces()) {
      listener_config.network_interfaces.push_back(interface);
      client_config.connection_endpoints.push_back(
          {interface.addresses[0].address, 0});
    }

    auto client = ProtocolConnectionClientFactory::Create(
        client_config, *this, task_runner, MessageDemuxer::kDefaultBufferLimit);
    request_ = std::make_unique<Lp2pRequest>(*client, task_runner,
                                             options_.lp2p_config);
    auto listener =
        ServiceListenerFactory::Create(listener_config, task_runner);
    // The client must learn of receivers before `OnReceiverAdded` connects.
    listener->AddObserver(*client);
    listener->AddObserver(*this);
    auto* manager = NetworkServiceManager::Create(std::move(listener), nullptr,
                                                  std::move(client), nullptr);
    manager->GetServiceListener()->Start();
    manager->GetProtocolConnectionClient()->Start();
    Print("looking for " + options_.connect_name);
  }

  const DemoOptions options_;
  std::unique_ptr<Lp2pReceiver> receiver_;
  std::unique_ptr<Lp2pRequest> request_;
  bool connecting_ = false;
  bool connected_ = false;
  bool has_opened_ = false;
  std::vector<std::string> pending_lines_;
  std::vector<std::unique_ptr<Lp2pConnection>> connections_;
  std::vector<std::unique_ptr<Lp2pDataChannel>> channels_;
};

void LogUsage(const char* argv0) {
  std::cerr << "usage: " << argv0
            << R"( <options> (--listen=<name> | --connect=<name>)

    --listen=<name>: Advertise as <name> and accept data channels. Text
        messages are echoed back prefixed with "echo: ".

    --connect=<name>: Discover <name>, connect, open a data channel and send
        each line read from stdin as a text message.

    --label=<label>, --protocol=<protocol>: The data channel to open
        (default label "chat").

    --port=<port>: The QUIC port to listen on (default 6668).

    --psk=<digits>: The PSK. The PSK presenter shows it (a random one is
        generated and logged when omitted); the PSK consumer requires it.

    --psk_ease_of_input=<0-100>: Sent in auth-capabilities (default 50).

    Options that deviate from the specs (off by default; for interop
    experiments only):

    --spake2_suite=p256: Use SPAKE2 over P-256 instead of edwards25519.

    --skip_data_channel_open_response: Neither send nor wait for
        data-channel-open-response, as go-lp2p does.

    -v, --verbose: Enable verbose logging.

    -h, --help: Show this help message.
)";
}

bool ParseOptions(int argc, char** argv, DemoOptions& options) {
  enum LongOnlyOption {
    kListen = 1000,
    kConnect,
    kLabel,
    kProtocol,
    kPort,
    kPsk,
    kPskEaseOfInput,
    kSpake2Suite,
    kSkipDataChannelOpenResponse,
  };
  const get_opt::option kOptions[] = {
      {"listen", required_argument, nullptr, kListen},
      {"connect", required_argument, nullptr, kConnect},
      {"label", required_argument, nullptr, kLabel},
      {"protocol", required_argument, nullptr, kProtocol},
      {"port", required_argument, nullptr, kPort},
      {"psk", required_argument, nullptr, kPsk},
      {"psk_ease_of_input", required_argument, nullptr, kPskEaseOfInput},
      {"spake2_suite", required_argument, nullptr, kSpake2Suite},
      {"skip_data_channel_open_response", no_argument, nullptr,
       kSkipDataChannelOpenResponse},
      {"verbose", no_argument, nullptr, 'v'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0}};

  bool verbose = false;
  int ch = -1;
  while ((ch = getopt_long(argc, argv, "vh", kOptions, nullptr)) != -1) {
    const std::string_view value =
        get_opt::optarg ? std::string_view(get_opt::optarg) : "";
    switch (ch) {
      case kListen:
        options.listen_name = std::string(value);
        break;
      case kConnect:
        options.connect_name = std::string(value);
        break;
      case kLabel:
        options.label = std::string(value);
        break;
      case kProtocol:
        options.protocol = std::string(value);
        break;
      case kPort: {
        const auto result = std::from_chars(
            value.data(), value.data() + value.size(), options.port);
        if (result.ec != std::errc() || options.port == 0) {
          return false;
        }
        break;
      }
      case kPsk:
        options.auth_config.psk = std::string(value);
        break;
      case kPskEaseOfInput: {
        uint64_t ease = 0;
        const auto result =
            std::from_chars(value.data(), value.data() + value.size(), ease);
        if (result.ec != std::errc() || ease > 100) {
          return false;
        }
        options.auth_config.psk_ease_of_input = ease;
        break;
      }
      case kSpake2Suite:
        if (value == "p256") {
          options.auth_config.spake2_suite =
              AuthenticationConfig::Spake2Suite::kP256;
        } else if (value != "edwards25519") {
          return false;
        }
        break;
      case kSkipDataChannelOpenResponse:
        options.lp2p_config.skip_data_channel_open_response = true;
        break;
      case 'v':
        verbose = true;
        break;
      default:
        return false;
    }
  }
  SetLogLevel(verbose ? LogLevel::kVerbose : LogLevel::kInfo);
  return options.listen_name.empty() != options.connect_name.empty();
}

}  // namespace
}  // namespace openscreen::osp

int main(int argc, char** argv) {
  using openscreen::PlatformClientPosix;
  using openscreen::osp::DemoOptions;
  using openscreen::osp::Lp2pDemo;

  DemoOptions options;
  if (!openscreen::osp::ParseOptions(argc, argv, options)) {
    openscreen::osp::LogUsage(argv[0]);
    return 1;
  }

  PlatformClientPosix::Create(std::chrono::milliseconds(50));
  auto& task_runner = PlatformClientPosix::GetInstance()->GetTaskRunner();
  auto demo = std::make_unique<Lp2pDemo>(std::move(options));
  task_runner.PostTask([&demo] { demo->Start(); });

  // Send each stdin line; stop at the end of stdin.
  std::string line;
  while (std::getline(std::cin, line)) {
    task_runner.PostTask([&demo, line] { demo->SendLine(line); });
  }

  std::promise<void> done;
  task_runner.PostTask([&demo, &done] {
    demo->Stop();
    demo.reset();
    done.set_value();
  });
  done.get_future().wait();
  PlatformClientPosix::ShutDown();
  return 0;
}
