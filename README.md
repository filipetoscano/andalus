Andalus
===============================================================================

[![CI](https://github.com/filipetoscano/andalus/workflows/CI/badge.svg)](https://github.com/filipetoscano/andalus/actions)
[![NuGet](https://img.shields.io/nuget/vpre/andalus.svg?label=NuGet)](https://www.nuget.org/packages/Andalus/)
[![codecov](https://codecov.io/github/filipetoscano/andalus/branch/master/graph/badge.svg?token=AUZO88V5IU)](https://codecov.io/github/filipetoscano/andalus)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)


| Name                             | Description
|----------------------------------|-------------------------------------------
| `Andalus.Cryptography`           | Abstractions, implementation of test HSM
| `Andalus.Cryptography.AwsKms`    | Provider for [AWS Key Management Service](https://aws.amazon.com/kms/)
| `Andalus.Cryptography.BouncyHsm` | Provider for [BouncyHSM](https://github.com/harrison314/BouncyHsm), a software simulator of HSM
| `Andalus.Cryptography.GoogleKms` | Provider for [Google Key Management Service](https://docs.cloud.google.com/kms/docs)
| `Andalus.Cryptography.KeyVault`  | Provider for [Azure KeyVault](https://azure.microsoft.com/en-us/products/key-vault)
| `Andalus.Cryptography.Pkcs11`    | Provider for PKCS#11
| `Andalus.Cryptography.Xml`       | XmlDigSig which defers signing to HSM provider


Pre-requisites
-------------------------------------------------------------------------------

* [.NET 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)
