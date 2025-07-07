use std::error::Error;
use std::process::Command;
use std::str;


// SMB structure
#[derive(Debug, Clone)]
pub struct SmbConfig {
    pub server_ip: String,
    pub username: String,
    pub domain: String,
    pub password: String,
    pub port: u16,
}

impl SmbConfig {
    pub fn new(server_ip: String, username: String, domain: String, password: String) -> Self {
        Self {
            server_ip,
            username,
            domain,
            password,
            port: 445, // Standard SMB port
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

// Structure to represent a SMB share
#[derive(Debug, Clone)]
pub struct SmbShare {
    pub name: String,
    pub share_type: String,
    pub comment: String,
}

// SMB client
pub struct SmbClient {
    config: SmbConfig,
}

impl SmbClient {
    pub fn new(config: SmbConfig) -> Self {
        Self { config }
    }

    // Uses smbclient to list available shares on the SMB server - only works Linux
    pub fn list_shares(&self) -> Result<Vec<SmbShare>, Box<dyn Error>> {
        log::debug!("SMB connextion to {}:{}", self.config.server_ip, self.config.port);

        // Contrusts the smbclient command to list shares
        let mut cmd = Command::new("smbclient");
        cmd.arg("-L")
           .arg(&self.config.server_ip)
           .arg("-U")
           .arg(format!("{}\\{}%{}", self.config.domain, self.config.username, self.config.password))
           .arg("-p")
           .arg(&self.config.port.to_string())
           .arg("--option=client min protocol=NT1"); // Retrocompatibility with older SMB versions

        let output = cmd.output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Smbclient error: {}", error_msg).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_shares_output(&stdout)
    }

    // Smbclient output parser to extract shares
    fn parse_shares_output(&self, output: &str) -> Result<Vec<SmbShare>, Box<dyn Error>> {
        let mut shares = Vec::new();
        let mut in_shares_section = false;

        for line in output.lines() {
            let line = line.trim();
            
            // Detect the start of the shares section
            if line.contains("Sharename") && line.contains("Type") {
                in_shares_section = true;
                continue;
            }

            // And the end of the shares section
            if in_shares_section && (line.is_empty() || line.starts_with("SMB")) {
                break;
            }

            // Parse the share line
            if in_shares_section && !line.starts_with("-") {
                if let Some(share) = self.parse_share_line(line) {
                    shares.push(share);
                }
            }
        }

        Ok(shares)
    }

    // Parse a single line of the smbclient output to extract share information
    fn parse_share_line(&self, line: &str) -> Option<SmbShare> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let name = parts[0].to_string();
        let share_type = parts[1].to_string();
        let comment = if parts.len() > 2 {
            parts[2..].join(" ")
        } else {
            String::new()
        };

        Some(SmbShare {
            name,
            share_type,
            comment,
        })
    }

    // Test the SMB connection
    pub fn test_connection(&self) -> Result<bool, Box<dyn Error>> {
        log::debug!("Test the SMB connection with {}:{}", self.config.server_ip, self.config.port);

        let mut cmd = Command::new("smbclient");
        cmd.arg("-L")
           .arg(&self.config.server_ip)
           .arg("-U")
           .arg(format!("{}\\{}%{}", self.config.domain, self.config.username, self.config.password))
           .arg("-p")
           .arg(&self.config.port.to_string())
           .arg("--option=client min protocol=NT1");

        let output = cmd.output()?;
        Ok(output.status.success())
    }

    // List the content of a specific share
    /*pub fn list_share_content(&self, share_name: &str, path: Option<&str>) -> Result<Vec<String>, Box<dyn Error>> {
        let target_path = path.unwrap_or("");
        let share_path = format!("\\\\{}\\{}", self.config.server_ip, share_name);

        log::info!("Access to the share {} at: {}", share_path, target_path);

        let mut cmd = Command::new("smbclient");
        cmd.arg(&share_path)
           .arg("-U")
           .arg(format!("{}\\{}%{}", self.config.domain, self.config.username, self.config.password))
           .arg("-p")
           .arg(&self.config.port.to_string())
           .arg("-c")
           .arg(format!("cd {}; ls", target_path));

        let output = cmd.output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Erreur during share access: {}", error_msg).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(self.parse_directory_listing(&stdout))
    }

    // Parse the output of the directory listing command
    fn parse_directory_listing(&self, output: &str) -> Vec<String> {
        let mut files = Vec::new();
        
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("smb:") || line.contains("blocks available") {
                continue;
            }
            
            // Format typique: "  nom_fichier    A    taille  date"
            if let Some(filename) = line.split_whitespace().next() {
                if filename != "." && filename != ".." {
                    files.push(filename.to_string());
                }
            }
        }
        
        files
    }*/
}

pub fn print_shares(shares: &[SmbShare]) {
    println!("\n=== Available shares on the WDS server ===");
    for (i, share) in shares.iter().enumerate() {
        println!("--- Share {} ---", i + 1);
        println!("  Name: {}", share.name);
        println!("  Type: {}", share.share_type);
        println!("  Comment: {}\n", share.comment);
    }
}

/*pub fn print_share_content(share_name: &str, files: &[String]) {
    println!("\n=== Share content '{}' ===", share_name);
    for (i, file) in files.iter().enumerate() {
        println!("  {}: {}", i + 1, file);
    }
}*/