# MVARCS

MVARCS (Mark Verifying Authority Root Certificate Store) is a store for the trusted root certificates involved in Mark Certificates (MC) from Mark Verifying Authorities (MVA).

The [cacert.pem](cacert.pem) file contains the PEM certificates from the MVAs.

Subsequent packages and libraries use this repo as a submodule for packaging up the certificates:
- [mvarcs-python](https://github.com/markcerts/mvarcs-python)

This store is inspired by the similar [Certifi.io](https://certifi.io/) used for TLS certificates.

## Certificate Fetcher
The `bin\mvarcs.py` script fetches and formats the certificates.

``` sh
# install required dependencies
pip install -r requirements.txt
# run doctest against script
python -m doctest -v bin/mvarcs.py
# run the tool
python bin/mvarcs.py
```

## Disclaimer
This tool and the certificates are provided "as is" without any warranties. Use it at your own risk.

## Terms and Conditions
The author(s) are not responsible for any damage or loss caused by the use of this tool or certificates.  
Inclusion of certificates here does not guarantee that an provider will honor your MCs.
