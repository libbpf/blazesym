use std::io::Write;

use anyhow::anyhow;
use anyhow::Result;
use reqwest::blocking::Client;
use reqwest::blocking::Request;
use reqwest::Method;
use reqwest::Url;

#[derive(Debug)]
pub struct DebugInfodClient {
    // See:
    // https://github.com/seanmonstar/reqwest/issues/988
    base_url: Url,
    client: Client,
}

impl DebugInfodClient {
    pub fn new(client: Client, base_url: Url) -> DebugInfodClient {
        DebugInfodClient { base_url, client }
    }

    /// Helper method to return build_id as a String.
    pub fn format_build_id(build_id: &[u8]) -> Result<String> {
        Ok(String::from_utf8(build_id.to_vec())?)
    }

    pub fn base_path_for(build_id: &[u8]) -> Result<String> {
        Ok(format!("{}/", DebugInfodClient::format_build_id(build_id)?))
    }

    /// Returns the debug info from a debuginfod source. Writes are buffered into the writer.
    pub fn get_debug_info(&self, build_id: &[u8], dest: &mut impl Write) -> Result<()> {
        // /buildid/<BUILDID>/debuginfo
        let url = self
            .base_url
            .clone()
            .join("buildid/")?
            .join(DebugInfodClient::base_path_for(build_id)?.as_str())?
            .join("debuginfo")?;
        let mut res = self.client.execute(Request::new(Method::GET, url))?;
        if res.status().is_success() {
            res.copy_to(dest)?;
            Ok(dest.flush()?)
        } else {
            Err(anyhow!(format!("request error {}", res.status())))
        }
    }

    /// Returns an executable from a debuginfod source. Writes are buffered into
    /// the writer.
    pub fn get_executable(&self, build_id: &[u8], dest: &mut impl Write) -> Result<()> {
        // /buildid/<BUILDID>/executable
        let url = self
            .base_url
            .join("buildid/")?
            .join(DebugInfodClient::base_path_for(build_id)?.as_str())?
            .join("executable")?;
        let mut res = self.client.execute(Request::new(Method::GET, url))?;
        res.copy_to(dest)?;
        Ok(dest.flush()?)
    }

    /// Returns a vector of URLs based on format of the DEBUGINFOD_URLS
    /// environment variable value, which is either a comma separated or
    /// whitespace separated list of URLs.
    pub fn parse_debuginfo_urls(var: String) -> Result<Vec<Url>> {
        let res: Vec<String> = var.split([',', ' ']).map(|v| v.to_string()).collect();
        let urls: Vec<Url> = res.iter().filter_map(|v| Url::parse(v).ok()).collect();
        Ok(urls)
    }

    /// Returns a set of default clients based on the get_default_servers method.
    pub fn get_default_clients(urls: Vec<Url>) -> Result<Vec<DebugInfodClient>> {
        Ok(urls
            .into_iter()
            .map(|base_url| DebugInfodClient::new(Client::new(), base_url))
            .collect::<Vec<DebugInfodClient>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_id() {
        let bytes = b"47917234fbfbd1c7288684d9232fe2a279e96fa4";
        let slice: &[u8] = bytes;
        let expected = "47917234fbfbd1c7288684d9232fe2a279e96fa4";
        let formatted_build_id = DebugInfodClient::format_build_id(slice).unwrap();
        assert_eq!(formatted_build_id, expected);
    }
    #[test]
    fn parse_debuginfo_urls_ws_separated() {
        let vars = "https://debug.infod https://de.bug.info.d";
        let parsed_urls = DebugInfodClient::parse_debuginfo_urls(vars.to_string()).unwrap();
        assert_eq!(
            parsed_urls,
            vec![
                Url::parse("https://debug.infod").ok().unwrap(),
                Url::parse("https://de.bug.info.d").ok().unwrap(),
            ],
        );
    }
    #[test]
    fn parse_debuginfo_urls_comma_separated() {
        let vars = "https://debug.infod,https://de.bug.info.d";
        let parsed_urls = DebugInfodClient::parse_debuginfo_urls(vars.to_string()).unwrap();
        assert_eq!(
            parsed_urls,
            vec![
                Url::parse("https://debug.infod").ok().unwrap(),
                Url::parse("https://de.bug.info.d").ok().unwrap(),
            ],
        );
    }
}
