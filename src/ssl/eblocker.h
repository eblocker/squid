#ifndef SQUID_EBLOCKER_LOG_H
#define SQUID_EBLOCKER_LOG_H

#include "openssl/ssl.h"
#include <string>

namespace eblocker {
    std::string pem(X509* x509);
    std::string x509_to_pem(X509* x509);
    std::string string_replace(std::string value, std::string target, std::string replacement);
};

#endif //SQUID_EBLOCKER_LOG_H
