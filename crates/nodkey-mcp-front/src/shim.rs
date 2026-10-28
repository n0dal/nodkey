//! `nodkey-mcp-stdio` (agent-interface-v1 §2.2): copies stdin → `mcp.sock` → stdout byte for
//! byte. It holds no secret and parses nothing; it only counts bytes since the last `\n` to
//! enforce the 64 KiB line cap, and stops (non-zero exit) when a line exceeds it.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::mcp::MAX_LINE;

#[derive(Debug, PartialEq, Eq)]
pub enum CopyEnd {
    /// The source reached end of stream.
    Eof,
    /// A line exceeded the cap; nothing past the cap was written.
    LineTooLong,
    /// A read or write failed.
    Io,
}

/// Copies `r` to `w` unchanged, flushing after every chunk, while no line (bytes between `\n`)
/// exceeds `max` bytes.
pub async fn copy_capped<R, W>(r: &mut R, w: &mut W, max: usize) -> CopyEnd
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut line = 0usize;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => return CopyEnd::Eof,
            Ok(n) => n,
            Err(_) => return CopyEnd::Io,
        };
        let chunk = &buf[..n];
        let mut ok_len = n;
        let mut too_long = false;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'\n' {
                line = 0;
            } else {
                line += 1;
                if line > max {
                    ok_len = i;
                    too_long = true;
                    break;
                }
            }
        }
        if w.write_all(&chunk[..ok_len]).await.is_err() || w.flush().await.is_err() {
            return CopyEnd::Io;
        }
        if too_long {
            return CopyEnd::LineTooLong;
        }
    }
}

/// Runs the shim on the given streams; returns the process exit code.
pub async fn run<I, O>(socket: &std::path::Path, mut stdin: I, mut stdout: O) -> i32
where
    I: AsyncRead + Unpin + Send + 'static,
    O: AsyncWrite + Unpin + Send + 'static,
{
    let Ok(stream) = tokio::net::UnixStream::connect(socket).await else {
        return 2;
    };
    let (mut sr, mut sw) = stream.into_split();
    let up = tokio::spawn(async move {
        let end = copy_capped(&mut stdin, &mut sw, MAX_LINE).await;
        let _ = sw.shutdown().await;
        end
    });
    let down = copy_capped(&mut sr, &mut stdout, MAX_LINE).await;
    let up_end = if up.is_finished() {
        up.await.unwrap_or(CopyEnd::Io)
    } else {
        up.abort();
        CopyEnd::Eof
    };
    match (down, up_end) {
        (CopyEnd::Eof, CopyEnd::Eof) => 0,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn copies_unchanged_and_caps_lines() {
        let input = b"{\"a\":1}\n{\"b\":\"\xc3\xa9\"}\n".to_vec();
        let mut out = Vec::new();
        assert_eq!(
            copy_capped(&mut &input[..], &mut out, 16).await,
            CopyEnd::Eof
        );
        assert_eq!(out, input);

        let long = [b'x'; 17];
        let mut data = b"ok\n".to_vec();
        data.extend_from_slice(&long);
        let mut out = Vec::new();
        assert_eq!(
            copy_capped(&mut &data[..], &mut out, 16).await,
            CopyEnd::LineTooLong
        );
        assert_eq!(out.len(), 3 + 16, "nothing past the cap is written");

        let exact = [b'y'; 16];
        let mut out = Vec::new();
        assert_eq!(
            copy_capped(&mut &exact[..], &mut out, 16).await,
            CopyEnd::Eof
        );
    }
}
