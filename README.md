# Enarx Demos
Programs for demonstrating the Enarx subcomponents and eventually their synergy.

## Wasmtime Basic
Compiling Rust/C/C++ programs to WASI-compliant WASM and running it natively using a Rust-powered JIT.

## AMD SEV
A demonstration of running encrypted code in an SEV VM.

## Intel SGX
A demonstration of remote attestation for an SGX enclave.

### Retrieving PCK certificate chain for Intel SGX Remote Attestation
The root and intermediate certificates can be retrieved from [Intel's API](https://api.portal.trustedservices.intel.com/documentation#pcs-certificate) by using the following command, which parses the response from Intel and places is in a file:
```
curl -v "https://api.trustedservices.intel.com/sgx/certification/v1/pckcrl?ca={processor}" 2>&1 | awk -F"SGX-PCK-CRL-Issuer-Chain: " '{print $2}' | sed -e :a -e 's@%@\\x@g;/./,$!d;/^\n*$/{$d;N;};/\n$/ba' | xargs -0 printf "%b" > pck_chain.pem
```
The output file, `pck_chain.pem`, will include the Intermediate and Root PCK certificates from Intel. 
The Quote provided by the platform will include the complete certificate chain with these same Intermediate and Root certificates, as well as the PCK Leaf Certificate that is specific to the SGX-capable platform.
The tenant can thus verify that the Root and Intermediate certificates embedded in the Quote, and thus the PCK certificate embedded in the Quote, are all legitimate.

### Usage 
1. Make sure your system is SGX2-capable and supports Flexible Launch Control, and have Intel's DCAP driver and other components installed from this [page](https://download.01.org/intel-sgx/dcap-1.1/linux/dcap\_installers/ubuntuServer18.04/).
2. Have Rust Nightly and the Fortanix EDP installed, following the steps on this [page](https://github.com/fortanix/rust-sgx). 
3. Retrieve Intel's PCK certificate chain as described in the section above.
4. Run the `attestation-enclave` with `cargo run --target x86_64-fortanix-unknown-sgx` and leave it running. Run the `attestation-daemon` with `cargo run` and leave it running.
5. Run the `attestation-tenant` with `cargo run <filepath>`, where filepath is the path to the PCK certificate chain from Step 3.
