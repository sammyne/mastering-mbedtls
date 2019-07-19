#include <iostream>
#include <memory>

#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"

#include "cppcodec/hex_default_lower.hpp"

using namespace std;

using defer = shared_ptr<void>;

using hex = cppcodec::hex_lower;

string mpi_hexlify(const mbedtls_mpi *x)
{
    uint8_t xx[32];

    auto status = mbedtls_mpi_write_binary_le(x, xx, sizeof(xx));
    if (0 != status)
    {
        cout << "hexlify failed: " << status << endl;
        return "";
    }

    return hex::encode(xx, sizeof(xx));
}

int main()
{
    const auto EC_GROUP_ID = MBEDTLS_ECP_DP_SECP256K1;

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

    //mbedtls_ecdsa_context sign_ctx;
    //mbedtls_ecdsa_init(&sign_ctx);
    //defer _3(nullptr, [&](...) { mbedtls_ecdsa_free(&sign_ctx); });

    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    defer _3(nullptr, [&](...) { mbedtls_ecp_keypair_free(&key); });

    {
        auto status = mbedtls_ecp_gen_key(EC_GROUP_ID, &key, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (0 != status)
        {
            cout << "[KEYGEN] failed: " << status << endl;
            return status;
        }
    }

    uint8_t md[32];
    {
        const string msg = "Hello World";
        auto status = mbedtls_sha256_ret((const uint8_t *)(msg.data()), msg.length(), md, 0);
        if (0 != status)
        {
            cout << "[HASH] failed: " << status << endl;
            return status;
        }

        cout << "[HASH] hash to sign = " << hex::encode(md, 32) << endl;
    }

    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    defer _4(nullptr, [&](...) { mbedtls_mpi_free(&r); });

    mbedtls_mpi_init(&s);
    defer _5(nullptr, [&](...) { mbedtls_mpi_free(&s); });

    {
        mbedtls_ecp_group group;
        mbedtls_ecp_group_init(&group);
        defer _6(nullptr, [&](...) { mbedtls_ecp_group_free(&group); });

        auto status = mbedtls_ecp_group_load(&group, EC_GROUP_ID);
        if (0 != status)
        {
            cout << "[SIGN/LOAD] failed: " << status << endl;
            return status;
        }

        status = mbedtls_ecdsa_sign_det(
            &group, &r, &s, &(key.d), md, sizeof(md), MBEDTLS_MD_SHA256);
        if (0 != status)
        {
            cout << "[SIGN] failed: " << status << endl;
            return status;
        }

        cout << "sig = (" << endl;
        cout << " r = " << mpi_hexlify(&r) << endl;
        cout << " s = " << mpi_hexlify(&s) << endl;
        cout << ")" << endl;
    }

    {
        mbedtls_ecp_group group;
        mbedtls_ecp_group_init(&group);
        defer _6(nullptr, [&](...) { mbedtls_ecp_group_free(&group); });

        auto status = mbedtls_ecp_group_load(&group, EC_GROUP_ID);
        if (0 != status)
        {
            cout << "[VERIFY/LOAD] failed: " << status << endl;
            return status;
        }

        status = mbedtls_ecdsa_verify(&group, md, sizeof(md), &(key.Q), &r, &s);
        if (0 != status)
        {
            cout << "[VERIFY] failed: " << status << endl;
            return status;
        }
    }

    cout << "done" << endl;

    return 0;
}