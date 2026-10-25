use std::collections::BTreeMap;
use std::time::Duration;

use memcached_protocol::text::{self, ProtocolError, Status, StoreCmd};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("connection closed by server")]
    Closed,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// What the server was observed to support; probed, not inferred from version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub version: String,
    pub meta: bool,
}

pub struct Client {
    io: BufReader<TcpStream>,
    op_timeout: Duration,
}

impl Client {
    pub async fn connect(addr: &str, op_timeout: Duration) -> Result<Self, ClientError> {
        let stream = timeout(op_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| ClientError::Timeout)??;
        stream.set_nodelay(true)?;
        Ok(Self {
            io: BufReader::new(stream),
            op_timeout,
        })
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        timeout(self.op_timeout, self.io.get_mut().write_all(bytes))
            .await
            .map_err(|_| ClientError::Timeout)??;
        Ok(())
    }

    async fn line(&mut self) -> Result<String, ClientError> {
        let mut buf = String::new();
        let n = timeout(self.op_timeout, self.io.read_line(&mut buf))
            .await
            .map_err(|_| ClientError::Timeout)??;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        Ok(buf)
    }

    pub async fn version(&mut self) -> Result<String, ClientError> {
        self.send(&text::encode_version()).await?;
        let l = self.line().await?;
        l.trim_end()
            .strip_prefix("VERSION ")
            .map(str::to_owned)
            .ok_or_else(|| ProtocolError::Malformed(l.trim_end().to_owned()).into())
    }

    pub async fn stats(
        &mut self,
        arg: Option<&str>,
    ) -> Result<BTreeMap<String, String>, ClientError> {
        self.send(&text::encode_stats(arg)).await?;
        let mut out = BTreeMap::new();
        loop {
            let l = self.line().await?;
            match text::parse_stat_line(&l)? {
                Some((k, v)) => {
                    out.insert(k.to_owned(), v.to_owned());
                }
                None => return Ok(out),
            }
        }
    }

    /// Returns `(flags, cas, data)` for a hit.
    pub async fn get(&mut self, key: &[u8]) -> Result<Option<(u32, Vec<u8>)>, ClientError> {
        self.send(&text::encode_get(&[key])?).await?;
        let mut found = None;
        while let Some(h) = text::parse_value_header(&self.line().await?)? {
            let mut data = vec![0u8; h.len + 2];
            timeout(self.op_timeout, self.io.read_exact(&mut data))
                .await
                .map_err(|_| ClientError::Timeout)??;
            data.truncate(h.len);
            found = Some((h.flags, data));
        }
        Ok(found)
    }

    pub async fn store(
        &mut self,
        cmd: StoreCmd,
        key: &[u8],
        flags: u32,
        exptime: i64,
        data: &[u8],
    ) -> Result<Status, ClientError> {
        self.send(&text::encode_store(cmd, key, flags, exptime, data)?)
            .await?;
        Ok(text::parse_status_line(&self.line().await?)?)
    }

    pub async fn delete(&mut self, key: &[u8]) -> Result<Status, ClientError> {
        self.send(&text::encode_delete(key)?).await?;
        Ok(text::parse_status_line(&self.line().await?)?)
    }

    pub async fn touch(&mut self, key: &[u8], exptime: i64) -> Result<Status, ClientError> {
        self.send(&text::encode_touch(key, exptime)?).await?;
        Ok(text::parse_status_line(&self.line().await?)?)
    }

    /// Probes the server: `version`, then `mn` to detect meta command support.
    pub async fn probe(&mut self) -> Result<Capabilities, ClientError> {
        let version = self.version().await?;
        self.send(&text::encode_meta_noop()).await?;
        let meta = self.line().await?.trim_end() == "MN";
        Ok(Capabilities { version, meta })
    }
}
