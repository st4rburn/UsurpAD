# UsurpAD

The patch for BadSuccessor (CVE-2025-53779) involved validating the link between the dMSA account and the account it was set to supersede from both sides rather than blindly trusting the dMSA. While this means dMSAs can no longer essentially grant instant DA, they can still be utilised by a privileged user to dump passwords or take over accounts if the user has appropriate write permissions over those accounts.

UsurpAD in particular is designed to exploit this functionality to dump the passwords of any user you have write permissions over. This is done by looping over every user in the domain, trying to write the relevant attributes, and if it succeeds authenticating to the dMSA. This returns a copy of each user's current Kerberos keys, which also may include the RC4-HMAC key, aka NT hash. These keys can then be used to perform pass-the-key attacks against the user, or if an NT hash is present, pass-the-hash or password cracking.

## Requirements

- A dMSA account you can authenticate from
- Having a user with the ability to write to
  - `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState` attributes of the dMSA
  - `msDS-SupersededManagedAccountLink` and `msDS-SupersededServiceAccountState` attributes of target users

GenericWrite will satisfy this for target users, and the ability to create a dMSA in any OU will allow you to grant yourself GenericWrite over it, hence satisfying the requirement for writing attributes on the dMSA.

Essentially if there is any OU you can create an object in and you have GenericWrite over any users, you are good to go. These requirements do of course mean this works better for more privileged users, and the script does not create the dMSA or grant you GenericWrite over it automatically, you need to do that part first.

## Usage

```
usage: main.py [-h] --url URL --dmsa DMSA [--dmsa-machine-url DMSA_MACHINE_URL] [--no-cleanup]
```

UsurpAD should be run using `uv` as it relies on a currently unreleased version of `msldap` and the default Kali install of `minikerberos` appears to be out of date at this time.

Any argument that requires a URL expects one in the [pypykatz format](https://github.com/skelsec/pypykatz/wiki/Connection-URL).

Several common examples of usage are listed below.

### Examples

Run UsurpAD using `Miela` from `corp0.local` as the high privilege user that sets attributes needed to run the attack. `Miela` is also the principal authorised to sign in as `puppet_dMSA`; the dMSA account we will be using to dump credentials.
```sh
uv run python main.py --url 'password://corp0.local\Miela:admin123!@DC01.corp0.local/?dc=192.168.100.10' --dmsa 'CN=puppet_dMSA,CN=Managed Service Accounts,DC=corp0,DC=local'
```

In this example, we're using a dMSA that already existed and belongs to host `SRV01`. We don't want to / can't modify our dMSA to allow `Miela` to authenticate it, and already have `SRV01`'s credentials, so we run the attack using `Miela` to set attributes like before, but `SRV01` to log in as the dMSA. We're also not interested in cleaning up after ourselves if it could mean getting detected, so we add `--no-cleanup`
```sh
uv run python main.py --url 'password://corp0.local\Miela:admin123!@DC01.corp0.local/?dc=192.168.100.10' --dmsa 'CN=puppet_dMSA,CN=Managed Service Accounts,DC=corp0,DC=local' --dmsa-machine-url 'password://corp0.local\SRV01$:admin123!@DC01.corp0.local/?dc=192.168.100.10' --no-cleanup
```

This example is the same as the first, but we want to authenticate using NTLM for attribute setting / enumeration. The dMSA has to log in via Kerberos, so it will need a different URL to be specified, removing the 'NTLM' part.
```sh
uv run python main.py --url 'ntlm-password://corp0.local\Miela:admin123!@DC01.corp0.local/?dc=192.168.100.10' --dmsa 'CN=puppet_dMSA,CN=Managed Service Accounts,DC=corp0,DC=local' --dmsa-machine-url 'password://corp0.local\Miela:admin123!@DC01.corp0.local/?dc=192.168.100.10'
```

No password? No problem! Check out [skelsec's guide](https://github.com/skelsec/pypykatz/wiki/Connection-URL) to pypykatz URLs, the format we use here. You can use NT hashes for both authentications.

## Detection

Unfortunately as it stands my AD lab is severely under-resourced and I don't have a SIEM running, so this will largely be untested for now.

Due to Kerberos authentication (TGS requests in particular) being required to get the target users' Kerberos keys, if the attack is successful there will likely be an abnormally high number of TGS requests to the same dMSA account. This can be paired with detections for attributes rapidly being set (or attempted to be set) across numerous users - currently the tool blindly attempts the attack on every user in the domain.
