//
// Created by mgr on 2/13/23.
//

#include <string>
#include <iostream>
#include <thread>
#include <memory>
#include <mutex>

#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_MAC
#include <CoreFoundation/CFBundle.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

// If enabled, don't direct ovpn3 core logging to
// ClientAPI::OpenVPNClient::log() virtual method.
// Instead, logging will go to LogBaseSimple::log().
// In this case, make sure to define:
//   LogBaseSimple log;
// at the top of your main() function to receive
// log messages from all threads.
// Also, note that the OPENVPN_LOG_GLOBAL setting
// MUST be consistent across all compilation units.
#ifdef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_LOG_GLOBAL // use global rather than thread-local log object pointer
#include <openvpn/log/logbasesimple.hpp>
#endif

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

// use SITNL on Linux by default
#if defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_USE_IPROUTE2) && !defined(OPENVPN_USE_SITNL)
#define OPENVPN_USE_SITNL
#endif

// should be included before other openvpn includes,
// with the exception of openvpn/log includes
#include <client/ovpncli.cpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/getopt.hpp>
#include <openvpn/common/getpw.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/ssl/peerinfo.hpp>
#include <openvpn/ssl/sslchoose.hpp>

#ifdef OPENVPN_REMOTE_OVERRIDE
#include <openvpn/common/process.hpp>
#endif

#if defined(USE_MBEDTLS)
#include <openvpn/mbedtls/util/pkcs1.hpp>
#elif defined(USE_OPENSSL)
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#endif
#endif

#if defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/win/console.hpp>
#include <shellapi.h>
#endif

#ifdef USE_NETCFG
#include "client/core-client-netcfg.hpp"
#endif

#if defined(OPENVPN_PLATFORM_LINUX)

#include <openvpn/tun/linux/client/tuncli.hpp>

// we use a static polymorphism and define a
// platform-specific TunSetup class, responsible
// for setting up tun device
#define TUN_CLASS_SETUP TunLinuxSetup::Setup<TUN_LINUX>
#include <openvpn/tun/linux/client/tuncli.hpp>
#elif defined(OPENVPN_PLATFORM_MAC)
#include <openvpn/tun/mac/client/tuncli.hpp>
#define TUN_CLASS_SETUP TunMac::Setup
#endif

using namespace openvpn;

#ifdef USE_TUN_BUILDER
class ClientBase : public ClientAPI::OpenVPNClient
{
  public:
    bool tun_builder_new() override
    {
        tbc.tun_builder_set_mtu(1500);
        return true;
    }

    int tun_builder_establish() override
    {
        if (!tun)
        {
            tun.reset(new TUN_CLASS_SETUP());
        }

        TUN_CLASS_SETUP::Config config;
        config.layer = Layer(Layer::Type::OSI_LAYER_3);
        // no need to add bypass routes on establish since we do it on socket_protect
        config.add_bypass_routes_on_establish = false;
        return tun->establish(tbc, &config, nullptr, std::cout);
    }

    bool tun_builder_add_address(const std::string &address,
                                 int prefix_length,
                                 const std::string &gateway, // optional
                                 bool ipv6,
                                 bool net30) override
    {
        return tbc.tun_builder_add_address(address, prefix_length, gateway, ipv6, net30);
    }

    bool tun_builder_add_route(const std::string &address,
                               int prefix_length,
                               int metric,
                               bool ipv6) override
    {
        return tbc.tun_builder_add_route(address, prefix_length, metric, ipv6);
    }

    bool tun_builder_reroute_gw(bool ipv4,
                                bool ipv6,
                                unsigned int flags) override
    {
        return tbc.tun_builder_reroute_gw(ipv4, ipv6, flags);
    }

    bool tun_builder_set_remote_address(const std::string &address,
                                        bool ipv6) override
    {
        return tbc.tun_builder_set_remote_address(address, ipv6);
    }

    bool tun_builder_set_session_name(const std::string &name) override
    {
        return tbc.tun_builder_set_session_name(name);
    }

    bool tun_builder_add_dns_server(const std::string &address, bool ipv6) override
    {
        return tbc.tun_builder_add_dns_server(address, ipv6);
    }

    void tun_builder_teardown(bool disconnect) override
    {
        std::ostringstream os;
        auto os_print = Cleanup([&os]()
                                { OPENVPN_LOG_STRING(os.str()); });
        tun->destroy(os);
    }

    bool socket_protect(int socket, std::string remote, bool ipv6) override
    {
        (void)socket;
        std::ostringstream os;
        auto os_print = Cleanup([&os]()
                                { OPENVPN_LOG_STRING(os.str()); });
        return tun->add_bypass_route(remote, ipv6, os);
    }

  private:
    TUN_CLASS_SETUP::Ptr tun = new TUN_CLASS_SETUP();
    TunBuilderCapture tbc;
};
#else // USE_TUN_BUILDER
class ClientBase : public ClientAPI::OpenVPNClient
{
public:
  bool socket_protect(int socket, std::string remote, bool ipv6) override
  {
    std::cout << "NOT IMPLEMENTED: *** socket_protect " << socket << " " << remote << std::endl;
    return true;
  }
};
#endif

class CustomClient : public ClientBase
{
public:
  enum ClockTickAction
  {
    CT_UNDEF,
    CT_STOP,
    CT_RECONNECT,
    CT_PAUSE,
    CT_RESUME,
    CT_STATS,
  };

  bool is_dynamic_challenge() const
  {
    return !dc_cookie.empty();
  }

  std::string dynamic_challenge_cookie()
  {
    return dc_cookie;
  }

  std::string epki_ca;
  std::string epki_cert;
#if defined(USE_MBEDTLS)
  MbedTLSPKI::PKContext epki_ctx; // external PKI context
#elif defined(USE_OPENSSL)
  openvpn::OpenSSLPKI::PKey epki_pkey;
#endif

  void set_clock_tick_action(const ClockTickAction action)
  {
    clock_tick_action = action;
  }

  void print_stats()
  {
    const int n = stats_n();
    std::vector<long long> stats = stats_bundle();

    std::cout << "STATS:" << std::endl;
    for (int i = 0; i < n; ++i)
    {
      const long long value = stats[i];
      if (value)
        std::cout << "  " << stats_name(i) << " : " << value << std::endl;
    }
  }

#ifdef OPENVPN_REMOTE_OVERRIDE
  void set_remote_override_cmd(const std::string &cmd)
    {
        remote_override_cmd = cmd;
    }
#endif

  void set_write_url_fn(const std::string &fn)
  {
    write_url_fn = fn;
  }

  static std::string read_profile(const char *fn, const std::string *profile_content)
  {
    if (!string::strcasecmp(fn, "http") && profile_content && !profile_content->empty())
      return *profile_content;
    else
    {
      ProfileMerge pm(fn,
                      "ovpn",
                      "",
                      ProfileMerge::FOLLOW_FULL,
                      ProfileParseLimits::MAX_LINE_SIZE,
                      ProfileParseLimits::MAX_PROFILE_SIZE);
      if (pm.status() != ProfileMerge::MERGE_SUCCESS)
        OPENVPN_THROW_EXCEPTION("merge config error: " << pm.status_string() << " : " << pm.error());
      return pm.profile_content();
    }
  }


private:
  virtual void event(const ClientAPI::Event &ev) override
  {
    std::cout << date_time() << " EVENT: " << ev.name;
    if (!ev.info.empty())
      std::cout << ' ' << ev.info;
    if (ev.fatal)
      std::cout << " [FATAL-ERR]";
    else if (ev.error)
      std::cout << " [ERR]";
    std::cout << std::endl;
    if (ev.name == "DYNAMIC_CHALLENGE")
    {
      dc_cookie = ev.info;

      ClientAPI::DynamicChallenge dc;
      if (ClientAPI::OpenVPNClientHelper::parse_dynamic_challenge(ev.info, dc))
      {
        std::cout << "DYNAMIC CHALLENGE" << std::endl;
        std::cout << "challenge: " << dc.challenge << std::endl;
        std::cout << "echo: " << dc.echo << std::endl;
        std::cout << "responseRequired: " << dc.responseRequired << std::endl;
        std::cout << "stateID: " << dc.stateID << std::endl;
      }
    }
    else if (ev.name == "PROXY_NEED_CREDS")
    {
      std::cout << "PROXY_NEED_CREDS " << ev.info << std::endl;
    }
    else if (ev.name == "INFO")
    {
      if (string::starts_with(ev.info, "OPEN_URL:"))
      {
        open_url(ev.info.substr(9), "");
      }
      else if (string::starts_with(ev.info, "WEB_AUTH:"))
      {
        auto extra = ev.info.substr(9);
        size_t flagsend = extra.find(':');
        if (flagsend != std::string::npos)
        {

          auto flags = extra.substr(0, flagsend);
          auto url = extra.substr(flagsend + 1);
          open_url(url, flags);
        }
      }
      else if (string::starts_with(ev.info, "CR_TEXT:"))
      {
        std::string cr_response;
        std::cout << "\n\n"
                  << ev.info.substr(8) << ": ";
        std::getline(std::cin, cr_response);
        post_cc_msg("CR_RESPONSE," + base64->encode(cr_response));
      }
    }
  }

  void open_url(std::string url_str, std::string flags)
  {
    if (string::starts_with(url_str, "http://")
        || string::starts_with(url_str, "https://"))
    {
      if (!write_url_fn.empty())
      {
        write_string(write_url_fn, url_str + '\n');
        return;
      }
#ifdef OPENVPN_PLATFORM_MAC
      std::thread thr([url_str]()
                            {
			    CFURLRef url = CFURLCreateWithBytes(
			      NULL,                        // allocator
			      (UInt8*) url_str.c_str(),     // URLBytes
			      url_str.length(),            // length
			      kCFStringEncodingUTF8,       // encoding
			      NULL                         // baseURL
			    );
			    LSOpenCFURLRef(url, 0);
			    CFRelease(url); });
            thr.detach();
#elif defined(OPENVPN_PLATFORM_TYPE_UNIX)
      Argv argv;
            if (::getuid() == 0 && ::getenv("SUDO_USER"))
            {
                argv.emplace_back("/usr/sbin/runuser");
                argv.emplace_back("-u");
                argv.emplace_back(::getenv("SUDO_USER"));
            }
            argv.emplace_back("/usr/bin/xdg-open");
            argv.emplace_back(url_str);
            system_cmd(argv);
#else
      std::cout << "No implementation to launch " << url_str << std::endl;
#endif
    }
  }

  virtual void log(const ClientAPI::LogInfo &log) override
  {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << date_time() << ' ' << log.text << std::flush;
  }

  virtual void clock_tick() override
  {
    const ClockTickAction action = clock_tick_action;
    clock_tick_action = CT_UNDEF;

    switch (action)
    {
      case CT_STOP:
        std::cout << "signal: CT_STOP" << std::endl;
        stop();
        break;
      case CT_RECONNECT:
        std::cout << "signal: CT_RECONNECT" << std::endl;
        reconnect(0);
        break;
      case CT_PAUSE:
        std::cout << "signal: CT_PAUSE" << std::endl;
        pause("clock-tick pause");
        break;
      case CT_RESUME:
        std::cout << "signal: CT_RESUME" << std::endl;
        resume();
        break;
      case CT_STATS:
        std::cout << "signal: CT_STATS" << std::endl;
        print_stats();
        break;
      default:
        break;
    }
  }

  virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest &certreq) override
  {
    if (!epki_cert.empty())
    {
      certreq.cert = epki_cert;
      certreq.supportingChain = epki_ca;
    }
    else
    {
      certreq.error = true;
      certreq.errorText = "external_pki_cert_request not implemented";
    }
  }

#ifdef USE_OPENSSL
  void doOpenSSLSignature(ClientAPI::ExternalPKISignRequest &signreq) const
  {
    using PKEY_CTX_unique_ptr = std::unique_ptr<::EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;

    BufferAllocated signdata(256, BufferAllocated::GROW);
    base64->decode(signdata, signreq.data);

    EVP_PKEY *pkey = epki_pkey.obj();


    PKEY_CTX_unique_ptr pkey_ctx(EVP_PKEY_CTX_new(pkey, nullptr), EVP_PKEY_CTX_free);

    if (!(pkey_ctx))
      throw Exception("epki_sign failed, error creating PKEY ctx");


    if ((EVP_PKEY_sign_init(pkey_ctx.get()) < 0))
    {
      throw Exception("epki_sign failed, error in EVP_PKEY_sign_init: " + openssl_error());
    }

    if (signreq.algorithm == "RSA_PKCS1_PSS_PADDING")
    {
      EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.get(), RSA_PKCS1_PSS_PADDING);
    }
    else if (signreq.algorithm == "RSA_PKCS1_PADDING")
    {
      EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.get(), RSA_PKCS1_PADDING);
    }
    else if (signreq.algorithm == "RSA_NO_PADDING")
    {
      EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.get(), RSA_NO_PADDING);
    }

    /* determine the output length */
    size_t outlen;

    if ((EVP_PKEY_sign(pkey_ctx.get(), nullptr, &outlen, signdata.c_data(), signdata.size())) < 0)
    {
      throw Exception("epki_sign failed, error signing data: " + openssl_error());
    }

    BufferAllocated sig(outlen, BufferAllocated::ARRAY);

    if ((EVP_PKEY_sign(pkey_ctx.get(), sig.data(), &outlen, signdata.c_data(), signdata.size())) < 0)
    {
      throw Exception("epki_sign failed, error signing data: " + openssl_error());
    }

    sig.set_size(outlen);
    signreq.sig = base64->encode(sig);
    OPENVPN_LOG("SIGNATURE[" << outlen << "]: " << signreq.sig);
  }

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
  void doOpenSSLDigestSignature(ClientAPI::ExternalPKISignRequest &signreq)
  {
    /* technically implementing this without OpenSSL 3.0 is possible but
     * only the xkey_provider implementation for OpenSSL 3.0 requires this,
     * so in the cli.cpp, which is only a test cient, we skip this extra
     * effort and just use only the modern APIs in doOpenSSLDigestSignature
     */
    throw Exception("epki_sign failed, digest sign only implemented in OpenSSL 3.0");
  }
#else
  void doOpenSSLDigestSignature(ClientAPI::ExternalPKISignRequest &signreq)
    {
        EVP_PKEY_CTX *pkey_ctx = nullptr;
        BufferAllocated signdata(256, BufferAllocated::GROW);
        base64->decode(signdata, signreq.data);

        using MD_unique_ptr = std::unique_ptr<::EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;

        MD_unique_ptr md(EVP_MD_CTX_new(), EVP_MD_CTX_free);

        if (!md)
            throw Exception("epki_sign failed, error creating MD ctx");

        if (!signreq.saltlen.empty() && signreq.saltlen != "digest")
        {
            throw Exception("epki_sign failed, only padding=digest supported" + openssl_error());
        }

        const char *padding = "none";

        if (signreq.algorithm == "RSA_PKCS1_PSS_PADDING")
        {
            padding = "pss";
        }
        else if (signreq.algorithm == "RSA_PKCS1_PADDING")
        {
            padding = "pkcs1";
        }
        else if (signreq.algorithm == "RSA_NO_PADDING")
        {
            padding = "none";
        }

        EVP_PKEY *pkey = epki_pkey.obj();
        OSSL_PARAM params[6] = {OSSL_PARAM_END};

        char *hashalg = const_cast<char *>(signreq.hashalg.c_str());
        if (signreq.hashalg == "none")
            hashalg = nullptr;

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, hashalg, 0);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, const_cast<char *>(padding), 0);

        if (EVP_PKEY_get_id(pkey) == EVP_PKEY_RSA && !signreq.saltlen.empty())
        {
            /* The strings are used const in OpenSSL but the API definition has char * */
            char *saltlen = const_cast<char *>(signreq.saltlen.c_str());
            params[2] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, saltlen, 0);
            params[3] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, hashalg, 0);
            params[4] = OSSL_PARAM_construct_end();
        }

        EVP_DigestSignInit_ex(md.get(), &pkey_ctx, hashalg, nullptr, nullptr, pkey, params);

        /* determine the output length */
        size_t outlen;

        if (EVP_DigestSign(md.get(), nullptr, &outlen, signdata.data(), signdata.size()) < 0)
        {
            throw Exception("epki_sign failed, error signing data: " + openssl_error());
        }

        BufferAllocated sig(outlen, BufferAllocated::ARRAY);

        if (EVP_DigestSign(md.get(), sig.data(), &outlen, signdata.data(), signdata.size()) < 0)
        {
            throw Exception("epki_sign failed, error signing data: " + openssl_error());
        }

        sig.set_size(outlen);
        signreq.sig = base64->encode(sig);
        OPENVPN_LOG("SIGNATURE[" << outlen << "]: " << signreq.sig);
    }
#endif

  void doOpenSSLSignRequest(ClientAPI::ExternalPKISignRequest &signreq)
  {
    if (signreq.hashalg.empty())
    {
      doOpenSSLSignature(signreq);
    }
    else
    {
      doOpenSSLDigestSignature(signreq);
    }
  }
#endif

  virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest &signreq) override
  {
#if defined(USE_MBEDTLS)
    if (epki_ctx.defined())
        {
            try
            {
                // decode base64 sign request
                BufferAllocated signdata(256, BufferAllocated::GROW);
                base64->decode(signdata, signreq.data);

                // get MD alg
                const mbedtls_md_type_t md_alg = PKCS1::DigestPrefix::MbedTLSParse().alg_from_prefix(signdata);

                // log info
                OPENVPN_LOG("SIGN[" << PKCS1::DigestPrefix::MbedTLSParse::to_string(md_alg) << ',' << signdata.size() << "]: " << render_hex_generic(signdata));

                // allocate buffer for signature
                BufferAllocated sig(mbedtls_pk_get_len(epki_ctx.get()), BufferAllocated::ARRAY);

                // sign it
                size_t sig_size = 0;
                const int status = mbedtls_pk_sign(epki_ctx.get(),
                                                   md_alg,
                                                   signdata.c_data(),
                                                   signdata.size(),
                                                   sig.data(),
                                                   &sig_size,
                                                   rng_callback,
                                                   this);
                if (status != 0)
                    throw Exception("mbedtls_pk_sign failed, err=" + openvpn::to_string(status));
                if (sig.size() != sig_size)
                    throw Exception("unexpected signature size");

                // encode base64 signature
                signreq.sig = base64->encode(sig);
                OPENVPN_LOG("SIGNATURE[" << sig_size << "]: " << signreq.sig);
            }
            catch (const std::exception &e)
            {
                signreq.error = true;
                signreq.errorText = std::string("external_pki_sign_request: ") + e.what();
            }
        }
        else
#elif defined(USE_OPENSSL)
    if (epki_pkey.defined())
    {
      try
      {
        doOpenSSLSignRequest(signreq);
      }
      catch (const std::exception &e)
      {
        signreq.error = true;
        signreq.errorText = std::string("external_pki_sign_request: ") + e.what();
      }
    }
    else
#endif
    {
      signreq.error = true;
      signreq.errorText = "external_pki_sign_request not implemented";
    }
  }

  // RNG callback
  static int rng_callback(void *arg, unsigned char *data, size_t len)
  {
    CustomClient *self = (CustomClient *)arg;
    if (!self->rng)
    {
      self->rng.reset(new SSLLib::RandomAPI(false));
      self->rng->assert_crypto();
    }
    return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose mbed TLS error code
  }

  virtual bool pause_on_connection_timeout() override
  {
    return false;
  }

#ifdef OPENVPN_REMOTE_OVERRIDE
  virtual bool remote_override_enabled() override
    {
        return !remote_override_cmd.empty();
    }

    virtual void remote_override(ClientAPI::RemoteOverride &ro) override
    {
        RedirectPipe::InOut pio;
        Argv argv;
        argv.emplace_back(remote_override_cmd);
        OPENVPN_LOG(argv.to_string());
        const int status = system_cmd(remote_override_cmd,
                                      argv,
                                      nullptr,
                                      pio,
                                      RedirectPipe::IGNORE_ERR,
                                      nullptr);
        if (!status)
        {
            const std::string out = string::first_line(pio.out);
            OPENVPN_LOG("REMOTE OVERRIDE: " << out);
            auto svec = string::split(out, ',');
            if (svec.size() == 4)
            {
                ro.host = svec[0];
                ro.ip = svec[1];
                ro.port = svec[2];
                ro.proto = svec[3];
            }
            else
                ro.error = "cannot parse remote-override, expecting host,ip,port,proto (at least one or both of host and ip must be defined)";
        }
        else
            ro.error = "status=" + std::to_string(status);
    }
#endif

  std::mutex log_mutex;
  std::string dc_cookie;
  RandomAPI::Ptr rng; // random data source for epki
  volatile ClockTickAction clock_tick_action = CT_UNDEF;

#ifdef OPENVPN_REMOTE_OVERRIDE
  std::string remote_override_cmd;
#endif

  std::string write_url_fn;
};
