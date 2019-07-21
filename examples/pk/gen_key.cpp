#include <iostream>
#include <memory>

#include "mbedtls/config.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#include "cppcodec/hex_default_lower.hpp"

using namespace std;

using defer = shared_ptr<void>;

using hex = cppcodec::hex_lower;

int main()
{
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    defer _1(nullptr, [&](...) { mbedtls_entropy_free(&entropy); });

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    defer _2(nullptr, [&](...) { mbedtls_ctr_drbg_free(&ctr_drbg); });

    {
        const string passphrase = "hello world ecdsa";
        auto status = mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy,
            (const uint8_t *)(passphrase.data()), passphrase.length());
        if (0 != status)
        {
            cout << "seeding failed: " << status << endl;
            return status;
        }
    }

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    defer _3(nullptr, [&](...) { mbedtls_pk_free(&key); });

    {
        //const auto info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA);
        const auto info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
        auto status = mbedtls_pk_setup(&key, info);
        if (0 != status)
        {
            cout << "[SETUP] failed: " << status << endl;
            return status;
        }

        status = mbedtls_ecp_gen_key(
            MBEDTLS_ECP_DP_SECP256K1, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg);
        if (0 != status)
        {
            cout << "[GENKEY] failed: " << status << endl;
            return status;
        }
    }

    // print key
    {
        auto ecp_key = mbedtls_pk_ec(key);
        cout << "curve: " << mbedtls_ecp_curve_info_from_grp_id(ecp_key->grp.id)->name << endl;
        mbedtls_mpi_write_file("Qx = ", &ecp_key->Q.X, 16, NULL);
        mbedtls_mpi_write_file("Qy = ", &ecp_key->Q.Y, 16, NULL);
        mbedtls_mpi_write_file(" d = ", &ecp_key->d, 16, NULL);
    }

    {
        cout << "\nexporting private key to as PEM ..." << endl;

        uint8_t out[16000];
        auto status = mbedtls_pk_write_key_pem(&key, out, sizeof(out));
        if (0 != status)
        {
            cout << "[PEM] failed: " << status << endl;
            return status;
        }

        cout << ((char *)out) << endl;
    }

    {
        cout << "\nexporting public key to as PEM ..." << endl;

        uint8_t out[16000];
        auto status = mbedtls_pk_write_pubkey_pem(&key, out, sizeof(out));
        if (0 != status)
        {
            cout << "[PEM] failed: " << status << endl;
            return status;
        }

        cout << ((char *)out) << endl;
    }

    cout << "done" << endl;

    return 0;
}