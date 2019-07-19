#include <iostream>
#include <memory>

#include "mbedtls/config.h"

#include "mbedtls/bignum.h"

using namespace std;

using defer = shared_ptr<void>;

int main()
{
    mbedtls_mpi x, y, z;

    mbedtls_mpi_init(&x);
    defer _1(nullptr, [&](...) { mbedtls_mpi_free(&x); });

    mbedtls_mpi_init(&y);
    defer _2(nullptr, [&](...) { mbedtls_mpi_free(&y); });

    mbedtls_mpi_init(&z);
    defer _3(nullptr, [&](...) { mbedtls_mpi_free(&z); });

    {
        auto status = mbedtls_mpi_read_string(&x, 10, "120");
        if (0 != status)
        {
            cout << "failed to initialize x: " << status << endl;
            return status;
        }
    }

    {
        auto status = mbedtls_mpi_read_string(&y, 10, "3");
        if (0 != status)
        {
            cout << "failed to initialize y: " << status << endl;
            return status;
        }
    }

    {
        auto status = mbedtls_mpi_mul_mpi(&z, &x, &y);
        if (0 != status)
        {
            cout << "failed to mutiply x and y: " << status << endl;
            return status;
        }

        size_t ell;
        mbedtls_mpi_write_string(&z, 10, nullptr, 0, &ell);

        auto zz = new char[ell];
        status = mbedtls_mpi_write_string(&z, 10, zz, ell, &ell);
        if (0 != status)
        {
            cout << "failed to export z: " << status << endl;
            return status;
        }
        cout << "z = " << zz << endl;

        delete[] zz;
    }

    return 0;
}
