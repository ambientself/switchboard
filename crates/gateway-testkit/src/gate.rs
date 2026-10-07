//! A gate a fake waits at until a test lets it through: how a fake is told to hang or to be
//! slow without a real sleep.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

#[derive(Default)]
struct State {
    open: bool,
    waiting: usize,
    wakers: Vec<Waker>,
}

/// A gate that starts closed. Anything waiting at it stays pending until [`open`](Gate::open)
/// is called, and then, and for every later wait, goes straight through.
///
/// Cloning gives another handle to the same gate. It is runtime-agnostic: it wakes the task
/// that polled it, whichever executor that is, so the same fakes serve a test that polls by
/// hand and one under an async runtime.
#[derive(Clone, Default)]
pub struct Gate {
    state: Arc<Mutex<State>>,
}

fn locked(state: &Mutex<State>) -> MutexGuard<'_, State> {
    // A panic in another test thread must not turn every later use of the gate into a second
    // panic.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Gate {
    /// A closed gate.
    pub fn closed() -> Self {
        Self::default()
    }

    /// Lets everything through, now and from here on, and wakes whatever is waiting.
    pub fn open(&self) {
        let wakers = {
            let mut state = locked(&self.state);
            state.open = true;
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// How many waits are pending at the gate right now: how a test sees that a call has
    /// arrived and is held.
    pub fn waiting(&self) -> usize {
        locked(&self.state).waiting
    }

    /// A future that is ready once the gate is open.
    pub fn wait(&self) -> GateWait {
        GateWait {
            state: self.state.clone(),
            counted: false,
        }
    }
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = locked(&self.state);
        f.debug_struct("Gate")
            .field("open", &state.open)
            .field("waiting", &state.waiting)
            .finish()
    }
}

/// The future [`Gate::wait`] returns.
#[must_use = "futures do nothing unless polled"]
pub struct GateWait {
    state: Arc<Mutex<State>>,
    counted: bool,
}

impl Future for GateWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        let mut state = locked(&this.state);
        if state.open {
            if this.counted {
                state.waiting = state.waiting.saturating_sub(1);
                this.counted = false;
            }
            return Poll::Ready(());
        }
        if !this.counted {
            state.waiting += 1;
            this.counted = true;
        }
        state.wakers.push(context.waker().clone());
        Poll::Pending
    }
}

impl Drop for GateWait {
    fn drop(&mut self) {
        if self.counted {
            {
                let mut state = locked(&self.state);
                state.waiting = state.waiting.saturating_sub(1);
            }
        }
    }
}
