#include "CustomClient.hpp"
#include <chrono>

int main(int argc, char *argv[])
{
  int ret = 0;

  try
  {
    std::string privateKeyPassword = "abc123bys";
    std::string peer_info;
//    std::string epki_cert_fn;
//    std::string epki_ca_fn;
//    std::string epki_key_fn;
//    std::string write_url_fn;

    bool retry;
    do {
      std::cout << "starting configuration..." << std::endl;
      retry = false;
      ClientAPI::Config config;
      config.content = CustomClient::read_profile("/home/mgr/openvpn-related/my-tests/UAK01.ovpn", nullptr);
      config.connTimeout = 0;
      config.privateKeyPassword = privateKeyPassword;
      config.info = true;

//      if (!epki_cert_fn.empty())
//        config.externalPkiAlias = "epki"; // dummy string

      PeerInfo::Set::parse_flexible(peer_info, config.peerInfo);

      // allow -s server override to reference a friendly name
      // in the config.
      //   setenv SERVER <HOST>/<FRIENDLY_NAME>
      if (!config.serverOverride.empty())
      {
        ClientAPI::OpenVPNClientHelper clihelper;
        const ClientAPI::EvalConfig cfg_eval = clihelper.eval_config(config);
        for (auto &se : cfg_eval.serverList)
        {
          if (config.serverOverride == se.friendlyName)
          {
            config.serverOverride = se.server;
            break;
          }
        }
      }

      CustomClient client;
      const ClientAPI::EvalConfig eval = client.eval_config(config);
      if (eval.error)
        OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);

//      client.set_write_url_fn(write_url_fn);

      std::cout << "CONNECTING..." << std::endl;

      int disconnect_wait_seconds = 11;
      std::thread timer([&client, &disconnect_wait_seconds]() {
        std::cout << std::endl << "running stop thread - waiting to disconnect OpenVPN v3 client after " << std::to_string(disconnect_wait_seconds) << " seconds" << std::endl << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(disconnect_wait_seconds * 1000));
        std::cout << std::endl << "wait interval passed - disconnecting OpenVPN v3 client" << std::endl << std::endl;
        client.stop();
      });
      timer.detach();

      ClientAPI::Status connect_status = client.connect();
      if (connect_status.error)
      {
        std::cout << "connect error: ";
        if (!connect_status.status.empty())
          std::cout << connect_status.status << ": ";
        std::cout << connect_status.message << std::endl;
      }

      // print closing stats
      client.print_stats();
    } while (retry);
  }
  catch (const std::exception &e)
  {
    std::cout << "Main thread exception: " << e.what() << std::endl;
    ret = 1;
  }
  return ret;
}
