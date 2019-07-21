/**
 * https://tls.mbed.org/kb/how-to/generate-a-self-signed-certificate
 */
#include <iostream>
#include <memory>

#include "mbedtls/config.h"

// enable the cert writing API
#define MBEDTLS_X509_CRT_WRITE_C

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

using namespace std;

using defer = shared_ptr<void>;

int main()
{
    const string privkey_pem = R"(-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIAHKlgiceeOHMp6ewahK4V9KzWW1wEzgz+P3Fd6Kn8PgoAcGBSuBBAAK
oUQDQgAEBCUUmUKyKCxRPCNY4f9WKryzCjMnaKxF+X56dSOJdDCAm5KC9uxTMq1m
rN4VOu6Na6baSZGXP8btHeMtGCpbkA==
-----END EC PRIVATE KEY-----)";

    mbedtls_pk_context issuer_key;
    mbedtls_pk_init(&issuer_key);
    defer _1(nullptr, [&](...) { mbedtls_pk_free(&issuer_key); });

    {
        auto status = mbedtls_pk_parse_key(
            &issuer_key,
            (const uint8_t *)(privkey_pem.c_str()), privkey_pem.length() + 1,
            nullptr, 0);
        if (0 != status)
        {
            cout << "[PARSE] failed to decode privkey: " << status << endl;
            return status;
        }
    }

    mbedtls_x509write_cert cert;
    mbedtls_x509write_crt_init(&cert);
    defer _2(nullptr, [&](...) { mbedtls_x509write_crt_free(&cert); });

    {
        cout << "setting name of subject and issuer ..." << endl;

        const auto issuer_name = "CN=Hello World,O=bd,C=CN";
        const auto subject_name = issuer_name;

        auto status = mbedtls_x509write_crt_set_subject_name(&cert, subject_name);
        if (0 != status)
        {
            cout << "[NAMING] failed to set subject name: " << status << endl;
            return status;
        }

        status = mbedtls_x509write_crt_set_issuer_name(&cert, issuer_name);
        if (0 != status)
        {
            cout << "[NAMING] failed to set issuer name: " << status << endl;
            return status;
        }
    }

    auto subject_key = issuer_key;
    {
        cout << "setting key of subject and issuer ..." << endl;

        mbedtls_x509write_crt_set_subject_key(&cert, &subject_key);
        mbedtls_x509write_crt_set_issuer_key(&cert, &issuer_key);

        // for version 3 only
        auto status = mbedtls_x509write_crt_set_subject_key_identifier(&cert);
        if (0 != status)
        {
            cout << "[SUBJECT KEY ID] failed: " << status << endl;
            return status;
        }

        status = mbedtls_x509write_crt_set_authority_key_identifier(&cert);
        if (0 != status)
        {
            cout << "[AUTHORITY KEY ID] failed: " << status << endl;
            return status;
        }
    }

    const auto not_before = "20190721000000";
    const auto not_after = "20200721000000";
    {
        cout << "setting validity ..." << endl;
        auto status = mbedtls_x509write_crt_set_validity(&cert, not_before, not_after);
        if (0 != status)
        {
            cout << "[VALIDITY] failed: " << status << endl;
            return status;
        }
    }

    const auto VERSION = MBEDTLS_X509_CRT_VERSION_3;
    const int is_ca = 1;
    const int max_pathlen = 3;
    {
        cout << "setting version and constraints ..." << endl;
        mbedtls_x509write_crt_set_version(&cert, VERSION);

        auto status = mbedtls_x509write_crt_set_basic_constraints(&cert, is_ca, max_pathlen);
        if (0 != status)
        {
            cout << "[CONSTRAINTS] failed: " << status << endl;
            return status;
        }
    }

    const auto MD_ALGO = MBEDTLS_MD_SHA256;
    {
        cout << "setting message digest algorithm ..." << endl;
        mbedtls_x509write_crt_set_md_alg(&cert, MD_ALGO);
    }

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    defer _3(nullptr, [&](...) { mbedtls_mpi_free(&serial); });
    {
        cout << "setting serial number to 1234567" << endl;
        auto status = mbedtls_mpi_read_string(&serial, 10, "1234567");
        if (0 != status)
        {
            cout << "[SERIAL] reading failed: " << status << endl;
            return status;
        }

        status = mbedtls_x509write_crt_set_serial(&cert, &serial);
        if (0 != status)
        {
            cout << "[SERIAL] setting failed: " << status << endl;
            return status;
        }
    }

    const auto key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN;
    {
        cout << "setting key usage as " << key_usage << " ..." << endl;
        auto status = mbedtls_x509write_crt_set_key_usage(&cert, key_usage);
        if (0 != status)
        {
            cout << "[KEY USAGE] failed: " << status << endl;
            return status;
        }
    }

    const auto ns_cert_type = MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
                              MBEDTLS_X509_NS_CERT_TYPE_EMAIL;
    {
        cout << "setting NS cert type as " << ns_cert_type << " ..." << endl;
        auto status = mbedtls_x509write_crt_set_ns_cert_type(&cert, ns_cert_type);
        if (0 != status)
        {
            cout << "[NS] failed: " << status << endl;
            return status;
        }
    }

    {
        cout << "displaying cert ..." << endl;

        mbedtls_entropy_context entropy;
        mbedtls_entropy_init(&entropy);
        defer _1(nullptr, [&](...) { mbedtls_entropy_free(&entropy); });

        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ctr_drbg_init(&ctr_drbg);
        defer _2(nullptr, [&](...) { mbedtls_ctr_drbg_free(&ctr_drbg); });

        uint8_t out[4096] = {0};
        auto status = mbedtls_x509write_crt_pem(
            &cert, out, sizeof(out), mbedtls_ctr_drbg_random, &ctr_drbg);
        if (0 != status)
        {
            cout << "[PEM] failed: " << status << endl;
            return status;
        }

        cout << (char *)out << endl;
    }

    return 0;
}