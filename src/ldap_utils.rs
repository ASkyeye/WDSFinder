use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

/// Convert a domain name to a base DN (Distinguished Name) format for LDAP.
/// 
/// # Examples
/// ```
/// assert_eq!(domain_to_base_dn("lab.local"), "dc=lab,dc=local");
/// assert_eq!(domain_to_base_dn("example.com"), "dc=example,dc=com");
/// assert_eq!(domain_to_base_dn("sub.domain.corp"), "dc=sub,dc=domain,dc=corp");
/// ```
pub fn domain_to_base_dn(domain: &str) -> String {
    format!("dc={}", domain.replace('.', ",dc="))
}

#[derive(Debug)]
pub struct LdapConfig {
    pub server_ip: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    pub password: String,
    pub base_dn: String,
}

impl LdapConfig {
    pub fn new(server_ip: String, username: String, domain: String, password: String) -> Self {
        Self {
            server_ip,
            port: 389, // Standard LDAP port
            username,
            domain: domain.clone(),
            password,
            base_dn: domain_to_base_dn(&domain),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_base_dn(mut self, base_dn: String) -> Self {
        self.base_dn = base_dn;
        self
    }

    pub fn get_bind_dn(&self) -> String {
        format!("{}@{}", self.username, self.domain)
    }

    pub fn get_ldap_url(&self) -> String {
        format!("ldap://{}:{}", self.server_ip, self.port)
    }
}

pub struct LdapClient {
    config: LdapConfig,
    connection: Option<LdapConn>,
}

impl LdapClient {
    pub fn new(config: LdapConfig) -> Self {
        Self {
            config,
            connection: None,
        }
    }

    pub fn connect(&mut self) -> Result<(), Box<dyn Error>> {
        let ldap_url = self.config.get_ldap_url();
        log::debug!("Connection to : {}", ldap_url);

        let ldap = LdapConn::new(&ldap_url)?;
        self.connection = Some(ldap);
        Ok(())
    }

    pub fn bind(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut ldap) = self.connection {
            let bind_dn = self.config.get_bind_dn();
            log::debug!("Authentication with : {}", bind_dn);

            let result = ldap.simple_bind(&bind_dn, &self.config.password)?;
            match result.success() {
                Ok(_) => {
                    log::info!("Authentication successful !");
                    Ok(())
                },
                Err(err) => {
                    log::error!("Authentication failed !");
                    Err(format!("{:?}", err).into())
                }
            }
        } else {
            Err("No connection performed. Call connect() first.".into())
        }
    }

    pub fn search_wds(&mut self, base_dn: Option<&str>, filter: &str, attributes: Vec<&str>) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
        if let Some(ref mut ldap) = self.connection {
            let search_base = base_dn.unwrap_or(&self.config.base_dn);

            log::debug!("WDS search in {} with the filter : {}", search_base, filter);

            let (rs, _res) = ldap.search(
                search_base,
                Scope::Subtree,
                filter,
                attributes,
            )?.success()?;

            let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
            log::info!("Number of entries: {}", entries.len());

            Ok(entries)
        } else {
            Err("No connection performed. Call connect() and bind() first.".into())
        }
    }

    pub fn disconnect(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(mut ldap) = self.connection.take() {
            ldap.unbind()?;
            log::info!("Disconnected from LDAP server.");
        }
        Ok(())
    }
}

impl Drop for LdapClient {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}


// Print search results in a readable format
pub fn print_search_results(entries: &[SearchEntry]) {
    for (i, entry) in entries.iter().enumerate() {
        println!("\n--- Entry {} ---", i + 1);
        println!("DN: {}", entry.dn);
        
        for (attr, values) in &entry.attrs {
            println!("  {}: {:?}", attr, values);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_base_dn() {
        assert_eq!(domain_to_base_dn("lab.local"), "dc=lab,dc=local");
        assert_eq!(domain_to_base_dn("example.com"), "dc=example,dc=com");
        assert_eq!(domain_to_base_dn("sub.domain.corp"), "dc=sub,dc=domain,dc=corp");
        assert_eq!(domain_to_base_dn("company.internal"), "dc=company,dc=internal");
        assert_eq!(domain_to_base_dn("single"), "dc=single");
    }

    #[test]
    fn test_config_creation() {
        let config = LdapConfig::new(
            "192.168.1.100".to_string(),
            "testuser".to_string(),
            "example.com".to_string(),
            "password123".to_string(),
        );

        assert_eq!(config.server_ip, "192.168.1.100");
        assert_eq!(config.username, "testuser");
        assert_eq!(config.domain, "example.com");
        assert_eq!(config.base_dn, "dc=example,dc=com");
        assert_eq!(config.get_bind_dn(), "testuser@example.com");
        assert_eq!(config.get_ldap_url(), "ldap://192.168.1.100:389");
    }
}
