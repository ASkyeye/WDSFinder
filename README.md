# WDSFinder

## Description

WDSFinder is a tool to identify WDS servers in an Active Directory domain and enumerate their exposed SMB shares. WDS servers can be used with SCCM Distribution Points and MDT shares, which are great targets to retrieve sensitive data like credentials.

More details about this in these two blog posts :

- https://trustedsec.com/blog/red-team-gold-extracting-credentials-from-mdt-shares
- https://hideandsec.sh/books/windows-sNL/page/mdt-where-are-you

## Why Rust ?

Yes.

## How to use it

Just compile the tool with Cargo on Windows or Linux, and run it. However, **the SMB enumeration only works on Linux at this time**, because `smbclient` is used under the hood.

```bash
# Optional, only on Linux
sudo apt install smbclient

cargo build --release
```

```plain
Usage: WDSFinder.exe [OPTIONS] --username <username> --password <password> --ip <ip>

Options:
  -u, --username <username>  Username to authenticate against the LDAP server
  -p, --password <password>  Password to authenticate against the LDAP server
  -i, --ip <ip>              IP address of the LDAP server
  -d, --domain <domain>      FQDN of the domain to which the LDAP server belongs
  -h, --help                 Print help
  -V, --version              Print version
```

## Disclaimers

This is an obvious disclaimer because I don't want to be held responsible if someone uses this tool against anyone who hasn't asked for anything.

Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
