"""
sedo-client: automation of the Ukrainian Armed Forces EDMS (sedo.mod.gov.ua).

The modules of the package:

    sedo.client          the CLI and SEDOClient (`sedo-client`, `python -m sedo`)
    sedo.config          config.toml / config_local.toml, key profiles and roles
    sedo.check           --check: the readiness report
    sedo.iit_client      the IIT "Користувач ЦСК-1" agent (JSON-RPC over localhost)
    sedo.opensc_signer   signing through OpenSC's pkcs11-tool
    sedo.pkcs11_signer   signing through PyKCS11 and the vendor PKCS#11 module
    sedo.virtual_signer  the virtual token (Key-6.dat)
    sedo.mechanism_ids   PKCS#11 mechanism ids, choosing the DSTU 4145 one
    sedo._console        console helpers shared by every entry point

The top-level modules of earlier versions (sedo_client.py, iit_client.py, …)
remain in the repository root: run as a script they start the same program,
imported they warn and hand back the module from this package.
"""
