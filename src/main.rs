mod ldap_utils;
mod smb_utils;

use ldap3::{SearchEntry};
use ldap_utils::{LdapConfig, LdapClient, print_search_results, domain_to_base_dn};
use smb_utils::{SmbClient, SmbConfig, print_shares/*, print_share_content*/};

use std::error::Error;
use clap::{Arg, Command};
use log::LevelFilter;
use simple_logger::SimpleLogger;


fn extract_cn_value(dn: &str) -> Option<String> {
    dn.strip_prefix("CN=")
        .and_then(|s| s.split(',').next())
        .map(|s| s.to_string())
}


fn main() -> Result<(), Box<dyn Error>> {
    SimpleLogger::new()
        .without_timestamps()
        .with_colors(true)
        .init()
        .unwrap();
    ::log::set_max_level(LevelFilter::Info);

    // Command line argument parsing 
    let args = Command::new("WDS Server Search")
        .author("BlackWasp")
        .version("0.1.0")
        .arg(
            Arg::new("username")
                .short('u')
                .long("username")
                .required(true)
                .help("Username to authenticate against the LDAP server"),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .required(true)
                .help("Password to authenticate against the LDAP server"),
        )
        .arg(
            Arg::new("ip")
                .short('i')
                .long("ip")
                .required(true)
                .help("IP address of the LDAP server"),
        )
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .help("FQDN of the domain to which the LDAP server belongs"),
        )
        .get_matches();

    // Parsing the domain argument to obtain the DN
    let dn = domain_to_base_dn(args.get_one::<String>("domain").unwrap().as_str());

    /*
            ***LDAP SECTION***
    */

    // LDAP configuration
    let config = LdapConfig::new(
        args.get_one::<String>("ip").unwrap().to_string(), // LDAP server IP
        args.get_one::<String>("username").unwrap().to_string(),
        args.get_one::<String>("domain").unwrap().to_string(),
        args.get_one::<String>("password").unwrap().to_string(),
    )
    .with_port(389)                      // LDAP standard port
    .with_base_dn(dn.to_string()); // DN base

    // LDAP client building
    let mut client = LdapClient::new(config);

    // Connection
    client.connect()?;

    // Authentication
    client.bind()?;

    // Search
    println!("\n=== Search for WDS server ===\n");
    let mut results_store: Vec<SearchEntry> = Vec::new();
    match client.search_wds(
        None,
        "(objectclass=intellimirrorSCP)",
        vec!["name", "netbootServer"],
    ) {
        Ok(results) => {
            print_search_results(&results);
            results_store = results.clone();
        },
        Err(e) => {
            log::error!("Search failed: {}", e);
            return Err(e);
        }
    }
    println!("");

    // LDAP disconnect
    client.disconnect()?;
    println!("");

    #[cfg(target_os = "linux")]
    {
        /*
                ***SMB SECTION***
        */

        // SMB configuration
        let mut wds_fqdn = String::new();
        for (_, entry) in results_store.iter().enumerate() {
            for (attr, values) in &entry.attrs {
                if attr == "netbootServer" {
                    println!("{}",extract_cn_value(values[0].as_str()).unwrap());
                    wds_fqdn.push_str(extract_cn_value(values[0].as_str()).unwrap().as_str());
                    wds_fqdn.push_str(&(".".to_string() + args.get_one::<String>("domain").unwrap()));
                }
            }
        }
        let smb_config = SmbConfig::new(
            wds_fqdn.to_string(),
            args.get_one::<String>("username").unwrap().to_string(),
            args.get_one::<String>("domain").unwrap().to_string(),
            args.get_one::<String>("password").unwrap().to_string()
        )
        .with_port(445);

        // SMB client building
        let smb_client = SmbClient::new(smb_config);

        // Test SMB connection
        match smb_client.test_connection() {
            Ok(true) => {
                log::info!("SMB connection successful!");
                
                // List shares
                match smb_client.list_shares() {
                    Ok(shares) => {
                        print_shares(&shares);
                        
                        // Access to the share content
                        /*if let Some(first_share) = shares.first() {
                            if first_share.share_type == "Disk" {
                                println!("\n=== Share content '{}' ===", first_share.name);
                                match smb_client.list_share_content(&first_share.name, None) {
                                    Ok(files) => print_share_content(&first_share.name, &files),
                                    Err(e) => log::error!("Error during share access: {}", e),
                                }
                            }
                        }*/
                    }
                    Err(e) => log::error!("Error when retrieving shares: {}", e),
                }
            }
            Ok(false) => log::error!("Error connecting to SMB server: Connection failed"),
            Err(e) => log::error!("Failed testing SMB connection: {}", e),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        log::warn!("SMB functionality is not supported on this OS at this time.");
        log::warn!("Detected OS: {}", std::env::consts::OS);
    }

    Ok(())
}