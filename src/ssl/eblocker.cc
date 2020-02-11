#include "eblocker.h"

namespace eblocker {

    std::string pem(X509 *x509) {
        if (x509 == NULL) {
            return "<null>";
        }

        std::string pem = x509_to_pem(x509);
        std::string escapedPem = string_replace(pem, "\n", "\\n");
        return escapedPem;
    }

    std::string x509_to_pem(X509 *x509) {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, x509);

        char *pem = NULL;
        int len = BIO_get_mem_data(bio, &pem);
        std::string pem_string = "";
        pem_string.append(pem, len);

        BIO_free(bio);

        return pem_string;
    }

    std::string string_replace(std::string value, std::string target, std::string replacement) {
        std::string::size_type n = 0;
        while ((n = value.find(target, n)) != std::string::npos) {
            value.replace(n, target.size(), replacement);
            n += replacement.size();
        }
        return value;
    }

}
