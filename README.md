# Enarx Demos
Programs for demonstrating the Enarx subcomponents and eventually their synergy.

## Wasmtime Basic
Compiling Rust/C/C++ programs to WASI-compliant WASM and running it natively using a Rust-powered JIT.

## AMD SEV
A demonstration of running encrypted code in an SEV VM.

## Intel SGX
A demonstration of remote attestation for an SGX enclave.

Usage: 
1. Make sure your system is SGX2-capable and supports Flexible Launch Control, and have Intel's DCAP driver and other components installed from this [page](https://download.01.org/intel-sgx/dcap-1.1/linux/dcap\_installers/ubuntuServer18.04/).
2. Have Rust Nightly and the Fortanix EDP installed, following the steps on this [page](https://github.com/fortanix/rust-sgx). 
3. Retrieve Intel's PCK certificate chain with [Intel's API](https://api.portal.trustedservices.intel.com/documentation#pcs-certificate). (See below for more detail.)
4. Run the `attestation-enclave` with `cargo run --target x86_64-fortanix-unknown-sgx` and leave it running. Run the `attestation-daemon` with `cargo run` and leave it running.
5. Run the `attestation-tenant` with `cargo run <filepath>`, where filepath is the path to the PCK certificate chain from Step 3.

### Retrieving PCK certificate chain 
To retrieve this certificate chain, you must [register](https://software.intel.com/registration/?lang=en-us) with Intel (this is currently free). Registration will give you an API key, which must be included in the PCK retrieval request.

Retrieve the other necessary parameters (PPID, CPUSVN, PCESVN, PCEID) with Intel's [PCK Cert Retrieval Tool](https://download.01.org/intel-sgx/dcap-1.0.1/dcap_installer/ubuntuServer1604/PCKIDRetrievalTool_v1.0.100.48192.tar.gz). After downloading and extracting the tool, run `PCKIDRetrievalTool -f outfile.csv` to place the information into `outfile.csv`. There is also a README included with this tool. Note: These parameters reflect your system's attributes for the purpose of this demo. In production, the values would reflect the remote system you are attesting and would be provided to you.

Once you have retrieved the PPID, CPUSVN, PCESVN, PCEID, and your API key, run the below [command](https://api.portal.trustedservices.intel.com/documentation#pcs-certificate) with these parameters filled in. These numbers are all shown as `####` below, but they will actually be varying lengths. **Note: DO NOT include brackets around the API key in the request, but DO include brackets around the other parameters.**

```
curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v1/pckcert?encrypted_ppid={####}&cpusvn={####}&pcesvn={####}&pceid={####}" -H "Ocp-Apim-Subscription-Key: ####"
```

The PCK certificate chain will be dumped to stdout, but you can redirect it to a file with `> pck_cert_chain.pem` added to the end of the command above. This file will have 3 certificates: the PCK leaf cert, an intermediate cert, and a root cert. Delete extraneous info between certificates (anything not between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`) and [URL decode](https://www.url-encode-decode.com/) the remaining text. The `.pem` file should now have the leaf cert, followed by the intermediate cert, followed by the root cert, with one new line between each, and no other data. The path of this file will serve as the one input argument for running the `attestation-tenant`.
