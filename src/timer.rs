/// Remote timer and access methods to start/stop it.

use std::convert::From;
use std::convert::TryFrom;
use std::io::Read;
use std::io::Write;
use std::net;
use std::sync;
use std::sync::mpsc;
use std::time;
use crate::tlv;
use crate::gen_buffer;

/// Commands to control the timer.
#[derive(Clone, Copy, std::cmp::PartialEq)]
enum Message {
    Start,
    Stop,
    Reset,
    Get,
    Quit,
}

impl std::convert::From<u8> for Message {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Message::Start,
            0x01 => Message::Stop,
            0x02 => Message::Reset,
            0x03 => Message::Get,
            _ => panic!("Invalid message!"),
        }
    }
}
impl std::convert::From<Message> for u8 {
    fn from(m: Message) -> Self {
        match m {
            Message::Start => 0x00,
            Message::Stop => 0x01,
            Message::Reset => 0x02,
            Message::Get => 0x03,
            _ => panic!("Invalid message!"),
        }
    }
}

#[derive(std::cmp::PartialEq)]
enum Status {
    Ok,
    NOk,
}

impl std::convert::From<u8> for Status {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Status::Ok,
            0x01 => Status::NOk,
            _ => panic!("Invalid Status"),
        }
    }
}
impl std::convert::From<Status> for u8 {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok => 0x00,
            Status::NOk => 0x01,
        }
    }
}

/// Helper struct updated on Message::Get, and synchronized on [Timer] by
/// a [std::sync::Mutex].
struct SharedTimer {
    /// Whether the struct was updated since sending the last Message::Get.
    updated: bool,
    /// The time elapsed on the last Message::Get.
    cur: time::Duration,
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
    /// Accumulated time when `Message.Get` was last issued.
    shared: sync::Arc<(sync::Mutex<SharedTimer>, sync::Condvar)>,
    /// Joinable handle to the timer thread. Since the scope must get
    /// ownership of the handle to call `.join()` on it, it's stored
    /// inside an `Option<T>`.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::clone::Clone for Timer {
    fn clone(&self) -> Self {
        Timer {
            tx: self.tx.clone(),
            shared: self.shared.clone(),
            thread: None,
        }
    }
}

/// Configures the server-side of the timer. Must be called by the server
/// before it may handle any `timer` request.
pub fn new_server() -> Timer {
    let (tx, rx) = mpsc::channel::<Message>();
    let now = time::Instant::now();

    let data = SharedTimer{
        updated: false,
        cur: time::Duration::from_millis(0),
    };
    let shared = sync::Mutex::new(data);
    let shared = sync::Arc::new((shared, sync::Condvar::new()));
    let c_shared = shared.clone();

    let thread = Some(std::thread::spawn(move || {
        let mut running = true;
        let mut did_start = false;
        let mut acc = time::Duration::from_millis(0);
        let mut now = time::Instant::now();
        let shared = c_shared;

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
                        let (shared, cvar) = &*shared;
                        match shared.lock() {
                            Ok(mut data) => {
                                if did_start {
                                    let new_now = time::Instant::now();
                                    let dt = new_now.duration_since(now);
                                    data.cur = acc + dt;
                                } else {
                                    data.cur = acc;
                                }
                                data.updated = true;
                                cvar.notify_one();
                            },
                            Err(err) => {
                                println!("timer: Failed to update the current time: {}", err);
                            },
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
        shared: shared,
        thread: thread,
    };

    return t;
}

type Error = &'static str;

impl<'a> Timer {
    fn send_get(&self) -> Result<time::Duration, Error> {
        let (shared, cvar) = &*self.shared;
        let mut data = match shared.lock() {
            Ok(mut ok_data) => ok_data,
            Err(err) => {
                println!("timer: Failed to get the current time: {}", err);
                return Err("timer: Failed to get the current time");
            },
        };

        if let Err(err) = self.tx.send(Message::Get) {
            println!("timer: Failed to send a get message: {}", err);
            return Err("timer: Failed to send a get message");
        }

        while !data.updated {
            data = match cvar.wait(data) {
                Ok(mut ok_data) => ok_data,
                Err(err) => {
                    println!("timer: Failed to wait on the conditional variable the current time: {}", err);
                    return Err("timer: Failed to wait for the current time");
                },
            };
        }
        data.updated = false;
        return Ok(data.cur);
    }

    /// Parses and handles a given request.
    pub fn handle_request(&self, req: &'a[u8], conn: &mut net::TcpStream) ->
    Result<&'a[u8], Error>
    {
        let tp;
        match tlv::TagParser::try_from(req) {
            Ok(ok_tp) => tp = ok_tp,
            Err(err) => return Err(err),
        }

        let res;
        let m = Message::from(u8::from(&tp));
        if m == Message::Get {
            res = self.send_get();
        } else {
            res = match self.tx.send(m) {
                Ok(_) => Ok(time::Duration::from_millis(0)),
                Err(err) => {
                    println!("timer: Failed to send message: {}", err);
                    Err("timer: Failed to send message")
                },
            };
        }

        let mut buf;
        match res {
            Err(err) => {
                buf = gen_buffer!(u8);
                let st = u8::from(Status::NOk);
                tlv::encode::<u8>(st, buf.as_mut_slice());
            },
            Ok(dur) => {
                if m == Message::Get {
                    buf = gen_buffer!(u8, u64, u32);
                    let st = u8::from(Status::Ok);
                    let next = buf.as_mut_slice();

                    let next = tlv::encode::<u8>(st, next);
                    let next = tlv::encode::<u64>(dur.as_secs(), next);
                    tlv::encode::<u32>(dur.subsec_nanos(), next);
                } else {
                    buf = gen_buffer!(u8);
                    let st = u8::from(Status::Ok);
                    tlv::encode::<u8>(st, buf.as_mut_slice());
                }
            },
        }

        match conn.write(buf.as_slice()) {
            Ok(_) => {
                return Ok(tp.get_next());
            },
            Err(err) => {
                println!("timer: Failed to reply to client: {}", err);
                return Err("Failed to reply to client");
            },
        }
    }

    fn handle_start(&self) -> Result<(), mpsc::SendError<Message>> {
        self.tx.send(Message::Start)
    }

    fn handle_stop(&self) -> Result<(), mpsc::SendError<Message>> {
        self.tx.send(Message::Stop)
    }

    fn handle_reset(&self) -> Result<(), mpsc::SendError<Message>> {
        self.tx.send(Message::Reset)
    }

    fn test_get(&self) -> time::Duration {
        self.send_get().unwrap()
    }
}

fn send_msg(prefix: &[u8], m: Message, conn: &mut net::TcpStream) ->
Result<(), Error>
{
    let size = prefix.len() + tlv::get_encoded_size::<u8>();
    let mut buf = std::vec::Vec::<u8>::with_capacity(size);
    buf.resize(size, 0);

    let next = buf.as_mut_slice();
    for i in 0..prefix.len() {
        next[i] = prefix[i];
    }
    let next = &mut next[prefix.len()..];
    let m = u8::from(m);
    tlv::encode::<u8>(m, next);

    match conn.write(buf.as_slice()) {
        Ok(_) => {
            return Ok(());
        },
        Err(err) => {
            println!("timer: Failed to send request: {}", err);
            return Err("Failed to send request");
        },
    }
}

fn get_response<'a>(out: &'a mut [u8], conn: &mut net::TcpStream) ->
Result<&'a [u8], Error>
{
    match conn.read(out) {
        Ok(len) => {
            if out.len() != len {
                println!("timer: Didn't get as much data as expected (exp: {}, got: {})", out.len(), len);
                return Err("timer: Didn't get as much data as expected");
            }
            let buf = &out[..];
            let tp = match tlv::TagParser::try_from(buf) {
                Err(err) => {
                    println!("timer: Didn't find seconds in response: {}", err);
                    return Err("timer: Current parse Get reponse");
                },
                Ok(tp) => tp,
            };
            let st = Status::from(u8::from(&tp));
            if st == Status::NOk {
                return Err("timer: Operation failed!");
            } else {
                return Ok(tp.get_next());
            }
        },
        Err(err) => {
            println!("timer: Failed to get a response: {}", err);
            return Err("timer: Failed to get a response");
        },
    }
}

pub fn start(prefix: &[u8], conn: &mut net::TcpStream) ->
Result<(), Error>
{
    let res = send_msg(prefix, Message::Start, conn);
    if let Err(_) = res {
        return res;
    }
    let mut out_buf = gen_buffer!(u8);
    let res = get_response(out_buf.as_mut_slice(), conn);
    if let Err(err) = res {
        return Err(err);
    } else {
        return Ok(());
    }
}

pub fn stop(prefix: &[u8], conn: &mut net::TcpStream) ->
Result<(), Error>
{
    let res = send_msg(prefix, Message::Stop, conn);
    if let Err(_) = res {
        return res;
    }
    let mut out_buf = gen_buffer!(u8);
    let res = get_response(out_buf.as_mut_slice(), conn);
    if let Err(err) = res {
        return Err(err);
    } else {
        return Ok(());
    }
}

pub fn reset(prefix: &[u8], conn: &mut net::TcpStream) ->
Result<(), Error>
{
    let res = send_msg(prefix, Message::Reset, conn);
    if let Err(_) = res {
        return res;
    }
    let mut out_buf = gen_buffer!(u8);
    let res = get_response(out_buf.as_mut_slice(), conn);
    if let Err(err) = res {
        return Err(err);
    } else {
        return Ok(());
    }
}

pub fn get(prefix: &[u8], conn: &mut net::TcpStream) ->
Result<time::Duration, Error>
{
    let res = send_msg(prefix, Message::Get, conn);
    if let Err(err) = res {
        return Err(err);
    }
    let mut out_buf = gen_buffer!(u8, u64, u32);
    let res = get_response(out_buf.as_mut_slice(), conn);
    let next = match res {
        Err(err) => return Err(err),
        Ok(next) => next,
    };
    let tp = match tlv::TagParser::try_from(next) {
        Err(err) => {
            println!("timer: Didn't find seconds in response: {}", err);
            return Err("timer: Current parse Get reponse");
        },
        Ok(tp) => tp,
    };
    let sec = u64::from(&tp);
    let tp = match tlv::TagParser::try_from(tp.get_next()) {
        Err(err) => {
            println!("timer: Didn't find nanoseconds in response: {}", err);
            return Err("timer: Current parse Get reponse");
        },
        Ok(tp) => tp,
    };
    let ns = u32::from(&tp);
    return Ok(time::Duration::new(sec, ns));
}

impl Drop for Timer {
    fn drop(&mut self) {
        /* Avoid issuing a 'Quit' when a non-main thread closes */
        let loc_thread = match self.thread.take() {
            Some(thread) => thread,
            None => return,
        };

        if let Err(err) = self.tx.send(Message::Quit) {
            println!("timer: Failed to signal timer to quit: {}", err);
        } else {
            if let Err(_) = loc_thread.join() {
                println!("timer: Failed to join on the timer thread");
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::timer;
    use std::time;
    use std::time::Duration;

    fn get_time_diff(dt: Duration, exp: Duration, err: Duration) -> Duration {
        let diff;
        if dt >= exp {
            diff = dt - exp;
        } else {
            diff = exp - dt;
        }
        if diff > err {
            println!("dt: {}us", dt.as_micros());
            println!("exp: {}us", exp.as_micros());
            println!("diff: {}us", diff.as_micros());
        }
        return diff;
    }

    #[test]
    fn spawn_timer() {
        let t = timer::new_server();

        // XXX: Usually, the difference stays perfectly under 0.5ms.
        // However, I've seen it get as large as 2.5ms. This shouldn't
        // be that big of an issue, so I just made the default threshold
        // more lenient.
        let err = time::Duration::from_micros(800);

        t.handle_start().expect("Failed to start the timer");
        let exp = time::Duration::from_millis(2);
        std::thread::sleep(exp);
        let dt = t.test_get();
        let diff = get_time_diff(dt, exp, err);
        assert!(diff < err);

        t.handle_stop().expect("Failed to pause the timer");
        std::thread::sleep(time::Duration::from_millis(1));
        t.handle_start().expect("Failed to continue the timer");
        let dt = t.test_get();
        let diff = get_time_diff(dt, exp, err);
        assert!(diff < err);

        t.handle_reset().expect("Failed to restart the timer");
        let exp = time::Duration::from_millis(0);
        let dt = t.test_get();
        let diff = get_time_diff(dt, exp, err);
        assert!(diff < err);

        let exp = time::Duration::from_millis(1);
        std::thread::sleep(time::Duration::from_millis(1));
        let dt = t.test_get();
        let diff = get_time_diff(dt, exp, err);
        assert!(diff < err);
    }
}
