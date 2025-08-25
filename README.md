# WDSFinder

## Description

WDSFinder is a tool to identify WDS servers in an Active Directory domain and enumerate their exposed SMB shares. WDS servers can be used with SCCM Distribution Points and MDT shares, which are great targets to retrieve sensitive data like credentials.

More details about this in these two blog posts :

- https://trustedsec.com/blog/red-team-gold-extracting-credentials-from-mdt-shares
- https://hideandsec.sh/books/windows-sNL/page/mdt-where-are-you

## Why Rust?

Yes.

## How to use it

### Windows

On Windows, just compile the tool with Cargo, and run it.

However, **the SMB enumeration only works on Linux at this time**, because `smbclient` is used under the hood. 

Additionally, the `ldap3` Rust library, used by this project, uses Kerberos with the Linux GSSAPI library to perform session signing on LDAP. So, if the Domain Controller enforces session signing on LDAP, **either use WDSFinder on Linux with Kerberos authentication, or use LDAPS if it is available.**

```bash
cargo build --release
```

### Linux

On Linux, some dependancies are required to compile:

```bash
# Only on Linux
sudo apt install pkg-config libssl-dev libkrb5-dev libgssapi-krb5-2 libclang-dev clang
sudo apt install smbclient

cargo build --release
```

If you wish to authenticate with Kerberos, you first have to modify the `/etc/krb5.conf` file on your system to create the target realm. For example, if the target domain is `LAB.LOCAL`:

```plain
cat /etc/krb5.conf
[libdefaults]
        default_realm = LAB.LOCAL

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false


# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        LAB.LOCAL = {
                kdc = lab-dc.lab.local
                default_domain = lab.local
        }

[...SNIP...]

[domain_realm]
        .lab.local = LAB.LOCAL
```

Then, obtain a valid TGT for your user, for example with Impacket:

```bash
getTGT.py -dc-ip lab-dc.lab.local lab.local/Administrator:Password123!
export KRB5CCNAME=./Administrator.ccache
```

You can now authenticate with Kerberos, and perform session signing on LDAP.

### Help

```plain
Usage: WDSFinder.exe [OPTIONS] --username <username> --password <password> --ip <ip> --domain <domain>

Options:
  -u, --username <username>  Username to authenticate against the LDAP server
  -p, --password <password>  Password to authenticate against the LDAP server
  -i, --ip <ip>              IP address or hostname (for Kerberos) of the LDAP server
  -d, --domain <domain>      FQDN of the domain to which the LDAP server belongs
  -k, --kerberos             Use Kerberos (GSSAPI) for authentication. Useful when signing is enforced. Only available on Linux at this time.
  -s, --ldaps                Use LDAPS (LDAP over SSL)
  -h, --help                 Print help
  -V, --version              Print version
```

## Disclaimers

This is an obvious disclaimer because I don't want to be held responsible if someone uses this tool against anyone who hasn't asked for anything.

Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
