use dirs::cache_dir;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use crate::client::DebugInfodClient;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Source;

use anyhow::anyhow;
use anyhow::Result;
use reqwest::Url;

#[derive(Debug)]
pub struct DebugInfodResolver {
    ignore_cache: bool,
    base_path: PathBuf,
    clients: Vec<DebugInfodClient>,
}

impl DebugInfodResolver {
    /// Returns a DebugInfodResolver resolver.
    pub fn new(
        clients: Vec<DebugInfodClient>,
        base_path: PathBuf,
        ignore_cache: bool,
    ) -> DebugInfodResolver {
        DebugInfodResolver {
            ignore_cache,
            base_path,
            clients,
        }
    }

    pub fn cache_dir() -> Result<PathBuf> {
        let mut dir = cache_dir()
            .or(Some(std::env::temp_dir()))
            .expect("Could not create temp dir");
        dir.push("blazesym");
        dir.push("debuginfod");
        Ok(dir)
    }

    /// Returns a default DebugInfodResolver resolver suitable for use. Caches
    /// resolved objects by default.
    pub fn default_resolver(urls: Vec<Url>) -> Result<DebugInfodResolver> {
        let clients = DebugInfodClient::get_default_clients(urls)?;
        let cache_dir = DebugInfodResolver::cache_dir()?;
        std::fs::create_dir_all(&cache_dir)?;
        Ok(DebugInfodResolver::new(clients, cache_dir, true))
    }

    fn cached(&self, path: &Path) -> bool {
        if path.is_file() {
            return true
        }
        false
    }

    fn debuginfo_path(&self, build_id: &[u8], path: Option<&str>) -> Result<PathBuf> {
        match path {
            Some(p) => Ok(PathBuf::from(p.to_string())),
            _ => {
                let mut path = self.base_path.clone();
                path.push(format!(
                    "{}.debuginfo",
                    DebugInfodClient::format_build_id(build_id)?
                ));
                Ok(path)
            }
        }
    }

    fn executable_path(&self, build_id: &[u8], path: Option<&str>) -> Result<PathBuf> {
        match path {
            Some(p) => Ok(PathBuf::from(p.to_string())),
            _ => {
                let mut path = self.base_path.clone();
                path.push(DebugInfodClient::format_build_id(build_id)?);
                Ok(path)
            }
        }
    }

    /// Returns debug info from a remote debuginfod source. The path can be used to set the result.
    pub fn debug_info(&self, build_id: &[u8], path: Option<&str>) -> Result<PathBuf> {
        let path = self.debuginfo_path(build_id, path)?;

        if !self.ignore_cache && self.cached(&path) {
            return Ok(path)
        }

        if self.clients.is_empty() {
            return Err(anyhow!("No debuginfod clients configured"))
        }

        let mut file = File::create(&path)?;

        let success = self
            .clients
            .iter()
            .find(|client| client.get_debug_info(build_id, &mut file).is_ok());

        if success.is_none() {
            fs::remove_file(&path)?;
            return Err(anyhow!(
                "failed to get debug info for build_id: {}",
                DebugInfodClient::format_build_id(build_id)?
            ))
        }
        Ok(path)
    }

    /// Returns an executable from a remote debuginfod source. The path can be used to set the
    /// result.
    pub fn executable(&self, build_id: &[u8], path: Option<&str>) -> Result<PathBuf> {
        let path = self.executable_path(build_id, path)?;

        if !self.ignore_cache && self.cached(&path) {
            return Ok(path)
        }

        if self.clients.is_empty() {
            return Err(anyhow!("No debuginfod clients configured"))
        }

        let mut file = File::create(&path)?;

        let success = self
            .clients
            .iter()
            .find(|client| client.get_executable(build_id, &mut file).is_ok());

        if success.is_none() {
            fs::remove_file(&path)?;
            return Err(anyhow!(
                "failed to get executable for build_id: {}",
                DebugInfodClient::format_build_id(build_id)?
            ))
        }
        Ok(path)
    }

    pub fn debug_info_from(&self, build_id: &[u8], path: Option<&str>) -> Result<Source> {
        let elf_path: PathBuf = self.debug_info(build_id, path)?;
        Ok(Source::Elf(Elf::new(elf_path)))
    }

    pub fn executable_from(&self, build_id: &[u8], path: Option<&str>) -> Result<Source> {
        let elf_path: PathBuf = self.executable(build_id, path)?;
        Ok(Source::Elf(Elf::new(elf_path)))
    }
}
