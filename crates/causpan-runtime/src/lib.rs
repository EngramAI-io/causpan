//! A source-level runtime bridge: request spans survive task creation and polling.
//!
//! Install one layer per process. Enter request futures with
//! `tracing::info_span!("causpan.request", causpan_context = context_id)`.
//! Tokio's own blocking-task spans require its `tracing` feature and
//! `RUSTFLAGS="--cfg tokio_unstable"`. No filesystem wrapper or binary patch is used.
//! Marker writes are research instrumentation, not a tamper-resistant boundary.
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    Subscriber,
};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

mod context;
pub use context::{CausalContext, ContextRegistry};

#[derive(Clone)]
pub struct RuntimeLayer {
    sink: Arc<File>,
    operation: Arc<AtomicU64>,
}
#[derive(Clone, Copy)]
struct SpanOwner {
    request: u64,
    relevant: bool,
}
#[derive(Clone, Copy)]
struct Frame {
    span: u64,
    request: u64,
    operation: u64,
}
thread_local! {
    static STACK: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
    static TID: i64 = unsafe { libc::syscall(libc::SYS_gettid) as i64 };
}
#[derive(Default)]
struct RequestField(Option<u64>);
impl Visit for RequestField {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "causpan_context" {
            self.0 = Some(value);
        }
    }
    fn record_debug(&mut self, field: &Field, _: &dyn std::fmt::Debug) {
        assert_ne!(
            field.name(),
            "causpan_context",
            "Causpan context must be a u64"
        );
    }
}
fn current() -> (u64, u64) {
    STACK.with(|stack| {
        stack
            .borrow()
            .last()
            .map(|f| (f.request, f.operation))
            .unwrap_or((0, 0))
    })
}
impl RuntimeLayer {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            sink: Arc::new(
                OpenOptions::new()
                    .append(true)
                    .create_new(true)
                    .open(path)?,
            ),
            operation: Arc::new(AtomicU64::new(1)),
        })
    }
    fn emit(&self, kind: &str, request: u64, operation: u64, pointer: u64) {
        let tid = TID.with(|tid| *tid);
        let line = format!("{{\"csp\":1,\"kind\":\"{kind}\",\"request\":{request},\"operation\":{operation},\"pointer\":{pointer},\"tid\":{tid},\"status\":0,\"unit\":\"span_poll\"}}\n");
        // A bounded single append write makes each marker visible in the syscall trace.
        // Never silently accept a partial record or capture failure.
        loop {
            let result =
                unsafe { libc::write(self.sink.as_raw_fd(), line.as_ptr().cast(), line.len()) };
            if result == line.len() as isize {
                break;
            }
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            panic!(
                "Causpan marker write failed: {}",
                io::Error::last_os_error()
            );
        }
    }
}
impl<S> Layer<S> for RuntimeLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut field = RequestField::default();
        attrs.record(&mut field);
        let explicit = attrs
            .parent()
            .and_then(|id| ctx.span(id))
            .and_then(|span| span.extensions().get::<SpanOwner>().copied());
        // Tokio's async task span has parent: None. The creator's active request is
        // nevertheless the causal parent; capture it at task creation, before a yield.
        let request = field
            .0
            .or_else(|| explicit.map(|owner| owner.request))
            .unwrap_or_else(|| current().0);
        let relevant = attrs.metadata().name() == "causpan.request"
            || attrs.metadata().name() == "runtime.spawn";
        if let Some(span) = ctx.span(id) {
            span.extensions_mut()
                .insert(SpanOwner { request, relevant });
        }
    }
    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let owner = ctx
            .span(id)
            .and_then(|span| span.extensions().get::<SpanOwner>().copied());
        let Some(owner) = owner.filter(|owner| owner.relevant) else {
            return;
        };
        // An operation is one execution interval/poll, not the task's entire lifetime.
        let operation = self.operation.fetch_add(1, Ordering::Relaxed);
        self.emit("SUBMIT", owner.request, operation, id.into_u64());
        self.emit("WORK_ENTER", owner.request, operation, id.into_u64());
        STACK.with(|stack| {
            stack.borrow_mut().push(Frame {
                span: id.into_u64(),
                request: owner.request,
                operation,
            })
        });
    }
    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let mut field = RequestField::default();
        values.record(&mut field);
        if let Some(request) = field.0 {
            let owner = ctx
                .span(id)
                .and_then(|span| span.extensions().get::<SpanOwner>().copied())
                .expect("Causpan missing span owner");
            assert_eq!(
                request, owner.request,
                "Causpan context is immutable after span creation"
            );
        }
    }
    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let owner = ctx
            .span(id)
            .and_then(|span| span.extensions().get::<SpanOwner>().copied());
        if !owner.is_some_and(|owner| owner.relevant) {
            return;
        }
        let frame = STACK
            .with(|stack| stack.borrow_mut().pop())
            .expect("Causpan unbalanced span exit");
        assert_eq!(frame.span, id.into_u64(), "Causpan span restoration order");
        let (request, operation) = current();
        self.emit("WORK_LEAVE", request, operation, frame.span);
        self.emit("COMPLETE", frame.request, frame.operation, frame.span);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;
    pub(crate) fn temp_path() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "causpan-runtime-test-{}-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    #[test]
    fn nested_request_scopes_restore_outer_context() {
        let path = temp_path();
        let layer = RuntimeLayer::new(&path).unwrap();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            let outer = tracing::info_span!("causpan.request", causpan_context = 1_u64);
            let _guard = outer.enter();
            assert_eq!(current().0, 1);
            {
                let inner = tracing::info_span!("causpan.request", causpan_context = 2_u64);
                let _guard = inner.enter();
                assert_eq!(current().0, 2);
            }
            assert_eq!(current().0, 1);
        });
        assert_eq!(current(), (0, 0));
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.iter().filter(|r| r["kind"] == "WORK_ENTER").count(), 2);
        assert_eq!(rows.iter().filter(|r| r["kind"] == "COMPLETE").count(), 2);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn changing_request_identity_is_rejected() {
        let path = temp_path();
        let layer = RuntimeLayer::new(&path).unwrap();
        let result = std::panic::catch_unwind(|| {
            tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
                let span = tracing::info_span!("causpan.request", causpan_context = 1_u64);
                span.record("causpan_context", 2_u64);
            });
        });
        std::fs::remove_file(path).unwrap();
        assert!(
            result.is_err(),
            "identity mutation must not silently change ownership"
        );
    }
}
