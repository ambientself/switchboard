//! Just enough of an executor to drive the gateway's futures in a test, so the fakes and their
//! tests need no async runtime.

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Runs `future` to completion on the calling thread, parking until it is woken. A future
/// that is held at a [`Gate`](crate::Gate) nobody opens parks this thread for good, so a test
/// that holds something uses [`poll_once`] and opens the gate itself.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park(),
        }
    }
}

/// Polls `future` once with a waker that does nothing, and returns what it said. For a test
/// that needs to see a future pending, change something, and poll again.
pub fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    future.poll(&mut context)
}
