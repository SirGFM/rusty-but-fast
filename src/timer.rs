/// Remote timer and access methods to start/stop it.

use std::sync;
use std::sync::mpsc;
use std::time;

enum Message {
    Start,
    Stop,
    Reset,
    Get,
    Quit,
}

/// Remote timer controlled by TCP requests.
///
/// The timer must be initialized by calling `new_server(). This starts a
/// background thread that keeps track of elapsed time. To issue commands
/// to this thread, use [Timer.handle_request] on a previously configured,
/// and accepted, TCP connection.
///
/// The background thread shall be automatically managed by this struct,
/// and is automatically joined when the `Timer` drops.
pub struct Timer {
    /// Channel used to send messages from the main thread to the
    /// timer thread.
    tx: mpsc::Sender<Message>,
    /// Instant when `cur` was last updated.
    last_update: sync::Arc<sync::RwLock<time::Instant>>,
    /// Accumulated time until since `last_update`.
    cur: sync::Arc<sync::RwLock<time::Duration>>,
    /// Joinable handle to the timer thread. Since the scope must get
    /// ownership of the handle to call `.join()` on it, it's stored
    /// inside an `Option<T>`.
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Configures the server-side of the timer. Must be called by the server
/// before it may handle any `timer` request.
pub fn new_server() -> Timer {
    let (tx, rx) = mpsc::channel::<Message>();
    let now = time::Instant::now();
    let t0 = time::Duration::from_millis(0);
    let last_update = sync::RwLock::<time::Instant>::new(now);
    let cur = sync::RwLock::<time::Duration>::new(t0);

    let last_update = sync::Arc::new(last_update);
    let cur = sync::Arc::new(cur);

    let c_last_update = last_update.clone();
    let c_cur = cur.clone();

    let thread = Some(std::thread::spawn(move || {
        let mut running = true;
        let mut did_start = false;
        let mut acc = time::Duration::from_millis(0);
        let mut now = time::Instant::now();

        while running {
            let recv = rx.recv();
            if let Ok(msg) = recv {
                match msg {
                    Message::Start => {
                        if !did_start {
                            now = time::Instant::now();
                            did_start = true;
                        }
                    },
                    Message::Stop => {
                        if did_start {
                            let tmp = time::Instant::now();
                            acc += tmp.duration_since(now);
                            now = tmp;
                            did_start = false;
                        }
                    },
                    Message::Reset => {
                        now = time::Instant::now();
                        acc = time::Duration::from_millis(0);
                    },
                    Message::Get => {
                        let new_cur: time::Duration;
                        let new_now = time::Instant::now();

                        if did_start {
                            new_cur = acc + new_now.duration_since(now);
                        } else {
                            new_cur = time::Duration::from_millis(0);
                        }

                        {
                            let res_w = cur.write();
                            match res_w {
                                Ok(mut w) => {
                                    *w = new_cur;
                                },
                                Err(err) => {
                                    println!("Failed to update the current time!");
                                },
                            }
                        }
                        {
                            let res_w = last_update.write();
                            match res_w {
                                Ok(mut w) => {
                                    *w = new_now;
                                },
                                Err(err) => {
                                    println!("Failed to update the current time!");
                                },
                            }
                        }
                    },
                    Message::Quit => {
                        running = false;
                    },
                }
            } else if let Err(err) = recv {
                println!("timer: Error receiving data on channel: {}", err);
            }
        }
    }));

    let t = Timer{
        tx: tx,
        last_update: c_last_update,
        cur: c_cur,
        thread: thread,
    };

    return t;
}

impl Timer {
    fn handle_start(&self) -> Result<(), mpsc::SendError<Message>> {
        self.tx.send(Message::Start)
    }

    fn handle_stop(&self) -> Result<(), mpsc::SendError<Message>> {
        self.tx.send(Message::Stop)
    }

    fn handle_reset(&self) -> Result<(), mpsc::SendError<Message>> {
        self.tx.send(Message::Reset)
    }

    fn handle_get(&self) -> Result<(), mpsc::SendError<Message>> {
        self.tx.send(Message::Get)
    }

    fn test_get(&self) -> time::Duration {
        let last = time::Instant::now();
        self.handle_get().expect("Failed to get the accumulated time");
        loop {
            let now: time::Instant;
            match self.last_update.read() {
                Ok(r) => {
                    now = *r;
                },
                Err(err) => {
                    now = last;
                },
            }
            if now > last {
                break;
            }
        }
        match self.cur.read() {
            Ok(r) => {
                *r
            },
            Err(err) => {
                panic!("Failed to get the current time: {}", err);
            }
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Err(err) = self.tx.send(Message::Quit) {
            println!("timer: Failed to signal timer to quit: {}", err);
        } else {
            if let Some(thread) = self.thread.take() {
                if let Err(_) = thread.join() {
                    println!("timer: Failed to join on the timer thread");
                }
            } else {
                println!("timer: Failed to retrieve the handle to the timer thread");
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::timer;
    use std::time;

    #[test]
    fn spawn_timer() {
        let t = timer::new_server();

        t.handle_start().expect("Failed to start the timer");
        let exp = time::Duration::from_millis(2);
        std::thread::sleep(exp);
        let dt = t.test_get();
        assert!(dt > exp);
        assert!(dt - exp < time::Duration::from_micros(500));

        t.handle_stop().expect("Failed to pause the timer");
        std::thread::sleep(time::Duration::from_millis(1));
        t.handle_start().expect("Failed to continue the timer");
        let dt = t.test_get();
        assert!(dt > exp);
        assert!(dt - exp < time::Duration::from_micros(500));

        t.handle_reset().expect("Failed to restart the timer");
        let exp = time::Duration::from_millis(0);
        let dt = t.test_get();
        assert!(dt >= exp);
        assert!(dt - exp < time::Duration::from_micros(500));

        let exp = time::Duration::from_millis(1);
        std::thread::sleep(time::Duration::from_millis(1));
        let dt = t.test_get();
        assert!(dt > exp);
        assert!(dt - exp < time::Duration::from_micros(500));
    }
}
