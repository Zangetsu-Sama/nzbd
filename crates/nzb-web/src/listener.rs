//! Connection-level hardening (SEC-032).
//!
//! [`serve`] configures Hyper's HTTP/1 parser; [`LimitedListener`] bounds the underlying I/O:
//!
//! * a global connection cap, plus a small reserved pool for loopback peers so the container
//!   `HEALTHCHECK` is never starved by remote clients (excess connections are closed at once
//!   rather than queued);
//! * a per-peer-IP connection cap (IPv6 per /64);
//! * an idle timeout (no read or write progress);
//! * an absolute request-head deadline and head size cap, including heads already buffered
//!   behind an earlier request. Hyper tracks the boundaries of fixed-length and chunked bodies,
//!   so a slow active body is not mistaken for another request head.
//!
//! The header deadline includes the idle keep-alive wait between requests. The connection idle
//! timeout also applies during body transfer. Neither deadline is extended by header drip-feeding.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::serve::{IncomingStream, Listener};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep};
use tower::ServiceExt;

/// Connection limits applied by [`LimitedListener`].
#[derive(Clone, Copy, Debug)]
pub struct ListenerLimits {
    /// Concurrent connections from non-loopback peers.
    pub max_connections: usize,
    /// Extra connections reserved for loopback peers (healthcheck, local tooling).
    pub loopback_reserved: usize,
    /// Concurrent connections per peer IP (non-loopback).
    pub max_per_ip: usize,
    /// Close a connection after this long without read/write progress.
    pub idle: Duration,
    /// Absolute time allowed to receive a request head, including idle keep-alive waiting.
    pub header_timeout: Duration,
    /// Max bytes of one request head (request line plus headers) before it is aborted.
    pub max_head_bytes: usize,
}

/// Wraps a [`Listener`] and enforces [`ListenerLimits`].
pub struct LimitedListener<L> {
    inner: L,
    general: Arc<Semaphore>,
    loopback: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    limits: ListenerLimits,
}

impl<L> LimitedListener<L> {
    /// Wraps `inner`.
    #[must_use]
    pub fn new(inner: L, limits: ListenerLimits) -> Self {
        Self {
            inner,
            general: Arc::new(Semaphore::new(limits.max_connections.max(1))),
            loopback: Arc::new(Semaphore::new(limits.loopback_reserved.max(1))),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            limits,
        }
    }
}

/// Serves the app with the HTTP/1 parser's header deadline and size limits enabled.
///
/// The listener retains the connection/IP caps and idle timer. Request bodies, pipelining and
/// upgrades remain Hyper's responsibility. Once `shutdown` resolves, accepting stops and active
/// connections finish through Hyper's graceful shutdown. Dropping this future aborts its tasks.
///
/// # Errors
/// This adapter currently returns `Ok(())` after graceful shutdown. Individual connection
/// errors are contained and logged; they do not stop the listener or propagate to its caller.
pub async fn serve<L, F>(
    mut listener: LimitedListener<L>,
    router: Router,
    shutdown: F,
) -> io::Result<()>
where
    L: Listener<Addr = SocketAddr>,
    L::Io: Unpin,
    F: Future<Output = ()> + Send,
{
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(listener.limits.header_timeout)
        .max_header_size(listener.limits.max_head_bytes)
        // Hyper requires at least 8 KiB; max_header_size still enforces smaller head caps.
        .max_buf_size(listener.limits.max_head_bytes.max(8192));
    let (stop, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {}
            (io, peer) = listener.accept() => {
                let service = router.clone().map_request(move |mut req: axum::http::Request<Incoming>| {
                    req.extensions_mut().insert(ConnectInfo(PeerAddr(peer)));
                    req.map(Body::new)
                });
                let connection = builder
                    .serve_connection(TokioIo::new(io), TowerToHyperService::new(service))
                    .with_upgrades();
                let mut stopping = stop.subscribe();
                connections.spawn(async move {
                    tokio::pin!(connection);
                    let result = tokio::select! {
                        result = &mut connection => result,
                        _ = stopping.changed() => {
                            connection.as_mut().graceful_shutdown();
                            connection.await
                        }
                    };
                    if result.is_err() {
                        tracing::trace!("HTTP connection ended after a protocol or I/O error");
                    }
                });
            }
        }
    }
    drop(listener);
    let _ = stop.send(true);
    while connections.join_next().await.is_some() {}
    Ok(())
}

/// Socket peer address of a connection accepted through [`LimitedListener`]; use as
/// `into_make_service_with_connect_info::<PeerAddr>()`. (axum's built-in `SocketAddr`
/// connect-info only supports a bare `TcpListener`.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);

impl<L> Connected<IncomingStream<'_, LimitedListener<L>>> for PeerAddr
where
    L: Listener<Addr = SocketAddr>,
    L::Io: Unpin,
{
    fn connect_info(stream: IncomingStream<'_, LimitedListener<L>>) -> Self {
        Self(*stream.remote_addr())
    }
}

/// Per-IP bucket: canonical address, IPv6 reduced to its /64.
fn ip_bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Decrements the per-IP counter when the connection ends.
struct IpGuard {
    map: Arc<Mutex<HashMap<IpAddr, usize>>>,
    key: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(c) = m.get_mut(&self.key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// I/O wrapper holding the connection permits and the timers.
pub struct LimitedIo<Io> {
    io: Io,
    idle_sleep: Pin<Box<Sleep>>,
    idle: Duration,
    _permit: OwnedSemaphorePermit,
    _ip: Option<IpGuard>,
}

fn timed_out<T>(what: &'static str) -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, what)))
}

impl<Io> LimitedIo<Io> {
    fn touch(&mut self) {
        self.idle_sleep.as_mut().reset(Instant::now() + self.idle);
    }
}

impl<Io: AsyncRead + Unpin> AsyncRead for LimitedIo<Io> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(cx).is_ready() {
                    return timed_out("connection idle timeout");
                }
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                let new = buf.filled().get(before..).unwrap_or_default();
                if !new.is_empty() {
                    this.touch();
                }
                Poll::Ready(Ok(()))
            }
            other @ Poll::Ready(_) => other,
        }
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for LimitedIo<Io> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write(cx, buf) {
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(cx).is_ready() {
                    timed_out("connection idle timeout")
                } else {
                    Poll::Pending
                }
            }
            ready @ Poll::Ready(Ok(n)) if n > 0 => {
                this.touch();
                ready
            }
            other @ Poll::Ready(_) => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl<L> LimitedListener<L> {
    /// Reserves a per-IP slot for `ip`; `None` when the peer is at its cap.
    fn take_ip_slot(&self, ip: IpAddr) -> Option<IpGuard> {
        let key = ip_bucket(ip);
        let mut m = self.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
        let cur = m.get(&key).copied().unwrap_or(0);
        if cur >= self.limits.max_per_ip.max(1) {
            return None;
        }
        m.insert(key, cur.saturating_add(1));
        Some(IpGuard {
            map: self.per_ip.clone(),
            key,
        })
    }
}

impl<L> Listener for LimitedListener<L>
where
    L: Listener<Addr = SocketAddr>,
    L::Io: Unpin,
{
    type Io = LimitedIo<L::Io>;
    type Addr = SocketAddr;

    #[allow(clippy::manual_async_fn)] // must match the trait's `impl Future + Send` signature
    fn accept(&mut self) -> impl Future<Output = (Self::Io, Self::Addr)> + Send {
        async move {
            loop {
                let (io, addr) = self.inner.accept().await;
                let loopback = addr.ip().to_canonical().is_loopback();
                // Never wait for a slot: queueing would let remote clients delay the loopback
                // healthcheck behind them. Over-limit connections are closed immediately.
                let sem = if loopback {
                    self.loopback.clone()
                } else {
                    self.general.clone()
                };
                let Ok(permit) = sem.try_acquire_owned() else {
                    tracing::warn!(loopback, "connection limit reached, closing");
                    continue;
                };
                let ip_guard = if loopback {
                    None
                } else if let Some(g) = self.take_ip_slot(addr.ip()) {
                    Some(g)
                } else {
                    tracing::warn!("per-IP connection limit reached, closing");
                    continue;
                };
                let now = Instant::now();
                let io = LimitedIo {
                    io,
                    idle_sleep: Box::pin(tokio::time::sleep_until(now + self.limits.idle)),
                    idle: self.limits.idle,
                    _permit: permit,
                    _ip: ip_guard,
                };
                return (io, addr);
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::{mpsc, oneshot};

    /// Listener fed by the test: each queued item is a connection from a chosen peer.
    struct Fake(mpsc::UnboundedReceiver<(DuplexStream, SocketAddr)>);

    impl Listener for Fake {
        type Io = DuplexStream;
        type Addr = SocketAddr;
        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            match self.0.recv().await {
                Some(v) => v,
                None => std::future::pending().await,
            }
        }
        fn local_addr(&self) -> io::Result<Self::Addr> {
            Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
        }
    }

    fn limits() -> ListenerLimits {
        ListenerLimits {
            max_connections: 4,
            loopback_reserved: 2,
            max_per_ip: 2,
            idle: Duration::from_secs(30),
            header_timeout: Duration::from_millis(300),
            max_head_bytes: 1024,
        }
    }

    fn setup(
        l: ListenerLimits,
    ) -> (
        LimitedListener<Fake>,
        mpsc::UnboundedSender<(DuplexStream, SocketAddr)>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        (LimitedListener::new(Fake(rx), l), tx)
    }

    /// Queues a connection from `peer`; returns the client side.
    fn connect(
        tx: &mpsc::UnboundedSender<(DuplexStream, SocketAddr)>,
        peer: &str,
    ) -> Option<DuplexStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tx.send((server, peer.parse().ok()?)).ok()?;
        Some(client)
    }

    async fn accept_one(l: &mut LimitedListener<Fake>) -> Option<LimitedIo<DuplexStream>> {
        tokio::time::timeout(Duration::from_millis(300), l.accept())
            .await
            .ok()
            .map(|(io, _)| io)
    }

    /// Runs the actual HTTP parser over deterministic in-memory transport, with paused time.
    struct HttpTest {
        client: DuplexStream,
        stop: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<io::Result<()>>,
    }

    impl HttpTest {
        fn start(lim: ListenerLimits, router: Router) -> Self {
            let (listener, tx) = setup(lim);
            let Some(client) = connect(&tx, "192.0.2.1:1000") else {
                panic!("connect");
            };
            let (stop, stopped) = oneshot::channel();
            let task = tokio::spawn(serve(listener, router, async move {
                let _ = stopped.await;
            }));
            Self {
                client,
                stop: Some(stop),
                task,
            }
        }

        async fn send(&mut self, bytes: &[u8]) {
            assert!(self.client.write_all(bytes).await.is_ok());
            // Let the server consume this batch without advancing the test clock.
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
        }

        async fn head(&mut self) -> String {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let byte = self
                    .client
                    .read_u8()
                    .await
                    .unwrap_or_else(|e| panic!("head: {e}"));
                head.push(byte);
                assert!(head.len() < 8192, "bounded test response head");
            }
            String::from_utf8(head).unwrap_or_else(|e| panic!("head utf8: {e}"))
        }

        async fn response(&mut self) -> (String, String) {
            let head = self.head().await;
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            assert!(length < 8192, "bounded test response body");
            let mut body = vec![0; length];
            assert!(self.client.read_exact(&mut body).await.is_ok());
            (
                head,
                String::from_utf8(body).unwrap_or_else(|e| panic!("body utf8: {e}")),
            )
        }

        async fn closed_before_idle(&mut self) {
            let began = Instant::now();
            let mut tail = Vec::new();
            let closed =
                tokio::time::timeout(Duration::from_secs(2), self.client.read_to_end(&mut tail))
                    .await;
            assert!(
                closed.is_ok_and(|result| result.is_ok()),
                "header deadline did not close the connection"
            );
            assert!(began.elapsed() < limits().idle);
        }

        async fn shutdown(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            let joined = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
            assert!(
                matches!(joined, Ok(Ok(Ok(())))),
                "server did not drain: {joined:?}"
            );
        }
    }

    impl Drop for HttpTest {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn ok_router() -> Router {
        Router::new().route("/", get(|| async { "ok" }))
    }

    #[tokio::test]
    async fn sec_032_idle_connection_is_closed() {
        let mut lim = limits();
        lim.idle = Duration::from_millis(100);
        lim.header_timeout = Duration::from_secs(30);
        let (mut l, tx) = setup(lim);
        let _c = connect(&tx, "192.0.2.1:1000");
        let Some(mut io) = accept_one(&mut l).await else {
            panic!("accept");
        };
        let mut buf = [0_u8; 8];
        let r = io.read(&mut buf).await;
        assert_eq!(r.err().map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_slowloris_drip_feed_hits_absolute_header_deadline() {
        let mut http = HttpTest::start(limits(), ok_router());
        http.send(b"GET / HTTP/1.1\r\nHost: localhost\r\nX: ").await;
        let began = Instant::now();
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(80)).await;
            http.send(b"x").await;
        }
        http.closed_before_idle().await;
        assert!(
            began.elapsed() < Duration::from_millis(500),
            "trickles reset the deadline"
        );
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_silent_connection_hits_header_deadline() {
        let mut http = HttpTest::start(limits(), ok_router());
        http.closed_before_idle().await;
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_oversized_head_is_cut_off_before_buffering() {
        let mut http = HttpTest::start(limits(), ok_router());
        let request = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nX: {}\r\n\r\n",
            "a".repeat(8192)
        );
        http.send(request.as_bytes()).await;
        assert!(http.head().await.starts_with("HTTP/1.1 431"));
        http.closed_before_idle().await;
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_body_after_head_is_not_subject_to_header_deadline() {
        let router = Router::new().route(
            "/",
            post(|body: String| async move { body.len().to_string() }),
        );
        let mut http = HttpTest::start(limits(), router);
        http.send(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1800\r\n\r\n")
            .await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(200)).await;
            http.send(&vec![b'\n'; 600]).await;
        }
        let (head, body) = http.response().await;
        assert!(head.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "1800");
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_pipelined_partial_head_keeps_its_deadline() {
        let requests: [&[u8]; 2] = [
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET /",
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbodyGET /",
        ];
        for request in requests {
            let router =
                Router::new().route("/", get(|| async { "ok" }).post(|_: String| async { "ok" }));
            let mut http = HttpTest::start(limits(), router);
            // One read contains a complete request (including its body) and a partial next head.
            // The old byte scanner stopped at the first blank line and lost this next head.
            http.send(request).await;
            let (head, body) = http.response().await;
            assert!(head.starts_with("HTTP/1.1 200"));
            assert_eq!(body, "ok");
            http.closed_before_idle().await;
            http.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_pipelined_head_size_limit_applies_to_buffered_bytes() {
        let mut http = HttpTest::start(limits(), ok_router());
        let requests = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\nX: {}\r\n\r\n",
            "x".repeat(2048)
        );
        http.send(requests.as_bytes()).await;
        assert!(http.response().await.0.starts_with("HTTP/1.1 200"));
        assert!(http.head().await.starts_with("HTTP/1.1 431"));
        http.closed_before_idle().await;
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_valid_pipelining_preserves_connect_info() {
        let router = Router::new().route(
            "/",
            get(|ConnectInfo(peer): ConnectInfo<PeerAddr>| async move { peer.0.to_string() }),
        );
        let mut http = HttpTest::start(limits(), router);
        http.send(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        for _ in 0..2 {
            let (head, body) = http.response().await;
            assert!(head.starts_with("HTTP/1.1 200"));
            assert_eq!(body, "192.0.2.1:1000");
        }
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_idle_keepalive_wait_uses_header_deadline() {
        let mut http = HttpTest::start(limits(), ok_router());
        http.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        assert!(http.response().await.0.starts_with("HTTP/1.1 200"));
        let began = Instant::now();
        // Hyper starts the next head's timer while waiting for its first byte. A browser may
        // open a new connection afterwards; it cannot reserve this keep-alive slot until idle.
        http.closed_before_idle().await;
        assert!(began.elapsed() < Duration::from_millis(500));
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_slow_chunked_body_and_trailers_preserve_next_head_deadline() {
        let router = Router::new().route(
            "/",
            post(|body: String| async move { body.len().to_string() }),
        );
        let mut http = HttpTest::start(limits(), router);
        http.send(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n").await;
        assert!(http.head().await.starts_with("HTTP/1.1 100"));
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(200)).await;
            let chunk = format!("258;test=yes\r\n{}\r\n", "\n".repeat(600));
            http.send(chunk.as_bytes()).await;
        }
        // End the body and trailer section, then begin the next head in the same read.
        http.send(b"0\r\nX-Test: done\r\n\r\nGET /").await;
        let (head, body) = http.response().await;
        assert!(head.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "1800");
        http.closed_before_idle().await;
        http.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn sec_032_slow_streaming_response_survives_header_deadline_and_drains() {
        let (body_tx, body_rx) = mpsc::channel::<Result<&'static str, io::Error>>(2);
        let receiver = Arc::new(Mutex::new(Some(body_rx)));
        let router = Router::new().route(
            "/",
            get(move || {
                let receiver = Arc::clone(&receiver);
                async move {
                    let rx = receiver
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                    let Some(rx) = rx else {
                        panic!("one streaming request");
                    };
                    Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|part| (part, rx))
                    }))
                }
            }),
        );
        let mut http = HttpTest::start(limits(), router);
        assert!(body_tx.send(Ok("first")).await.is_ok());
        http.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        assert!(http.head().await.starts_with("HTTP/1.1 200"));
        let mut first = [0; 10];
        assert!(http.client.read_exact(&mut first).await.is_ok());
        assert_eq!(&first, b"5\r\nfirst\r\n");
        tokio::time::advance(Duration::from_millis(600)).await;
        assert!(body_tx.send(Ok("last")).await.is_ok());
        let mut last = [0; 9];
        assert!(http.client.read_exact(&mut last).await.is_ok());
        assert_eq!(&last, b"4\r\nlast\r\n");
        if let Some(stop) = http.stop.take() {
            let _ = stop.send(());
        }
        tokio::task::yield_now().await;
        assert!(
            !http.task.is_finished(),
            "shutdown must drain the active response"
        );
        assert!(body_tx.send(Ok("done")).await.is_ok());
        drop(body_tx);
        let mut tail = Vec::new();
        assert!(http.client.read_to_end(&mut tail).await.is_ok());
        assert_eq!(tail, b"4\r\ndone\r\n0\r\n\r\n");
        http.shutdown().await;
    }

    #[tokio::test]
    async fn sec_032_per_ip_cap_closes_extra_connections_and_releases() {
        let (mut l, tx) = setup(limits());
        let c1 = connect(&tx, "192.0.2.1:1");
        let c2 = connect(&tx, "192.0.2.1:2");
        let mut c3 = connect(&tx, "192.0.2.1:3");
        let other = connect(&tx, "192.0.2.2:4");
        let Some(io1) = accept_one(&mut l).await else {
            panic!("1");
        };
        let Some(_io2) = accept_one(&mut l).await else {
            panic!("2");
        };
        // The third is closed (skipped); the next accepted connection is the other host's.
        let Some(_io4) = accept_one(&mut l).await else {
            panic!("other host must still be served");
        };
        if let Some(c) = c3.as_mut() {
            let mut b = [0_u8; 1];
            assert_eq!(
                c.read(&mut b).await.ok(),
                Some(0),
                "over-cap peer is closed"
            );
        }
        drop(io1);
        let _c5 = connect(&tx, "192.0.2.1:5");
        assert!(accept_one(&mut l).await.is_some(), "slot released");
        drop((c1, c2, other));
    }

    #[tokio::test]
    async fn sec_032_global_cap_does_not_starve_loopback_healthcheck() {
        let mut lim = limits();
        lim.max_per_ip = 100;
        let (mut l, tx) = setup(lim);
        let mut held = Vec::new();
        let mut clients = Vec::new();
        for i in 0..4 {
            clients.push(connect(&tx, &format!("192.0.2.{}:1", i + 1)));
            held.push(accept_one(&mut l).await);
        }
        assert!(held.iter().all(Option::is_some));
        // At the cap: a remote connection is dropped, a loopback one is served at once.
        let mut extra = connect(&tx, "192.0.2.50:1");
        let _lo = connect(&tx, "127.0.0.1:9");
        assert!(
            accept_one(&mut l).await.is_some(),
            "loopback must be accepted"
        );
        if let Some(c) = extra.as_mut() {
            let mut b = [0_u8; 1];
            assert_eq!(c.read(&mut b).await.ok(), Some(0));
        }
    }
}
