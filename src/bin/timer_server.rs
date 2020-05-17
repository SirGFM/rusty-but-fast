use rusty_but_fast::timer;

use std::sync::atomic::AtomicBool as AtomicBool;

struct ClientData {
    conn: std::net::TcpStream,
    addr: std::net::SocketAddr,
    running: std::sync::Arc<AtomicBool>,
    timer: timer::Timer,
}

fn handle_client(data: ClientData) {
    use std::io::Read;
    use std::io::ErrorKind::WouldBlock as ErrWouldBlock;

    println!("New TCP connection from {}!", data.addr);
    match data.conn.set_nonblocking(false) {
        Err(err) => println!("Couldn't set blocking: {}", err),
        _ => {},
    }

    let mut data = data;
    while data.running.load(std::sync::atomic::Ordering::Relaxed) {
        let mut buf: [u8; 128] = [0; 128];
        let mut buf = &mut buf[..];
        match data.conn.read(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    println!("Closing connection to {}...", data.addr);
                    break;
                }
                let mut next = &buf[..n];
                while next.len() > 0 {
                    next = match data.timer.handle_request(next, &mut data.conn) {
                        Ok(more) => more,
                        Err(err) => {
                            println!("Failed to handle request: {}", err);
                            break;
                        },
                    };
                }
            },
            Err(err) => {
                println!("Couldn't read data: {}", err);
            }
        };
    };
}

fn run_server(addr: [u8; 4], port: u16, running: std::sync::Arc<AtomicBool>) {
    use std::time::Duration as Duration;

    let t = timer::new();

    let addrs = [
        std::net::SocketAddr::from((addr, port)),
    ];
    let listener = std::net::TcpListener::bind(&addrs[..]).expect("Failed to bind the TCP listener");
    listener.set_nonblocking(true).expect("Cannot set non-blocking");

    let mut wait = 10;
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((conn, addr)) => {
                let data = ClientData {
                    conn: conn,
                    addr: addr,
                    running: running.clone(),
                    timer: t.clone(),
                };

                std::thread::spawn(move || {
                    handle_client(data);
                });
                wait = 10;
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(wait));
                if wait < 1000 {
                    wait *= 2;
                } else {
                    wait = 1000;
                }
            },
            Err(e) => {
                println!("Couldn't accept the new connection: {}", e);
            },
        }
    }

    println!("Got signal! Stopping server...");
}

fn main() {
    println!("Starting TCP server...");

    let running = std::sync::Arc::new(AtomicBool::new(true));
    let running_ctrlc = running.clone();
    ctrlc::set_handler(move || {
        running_ctrlc.store(false, std::sync::atomic::Ordering::Relaxed);
    }).expect("Couldn't set Ctrl+C handler");

    let addr = [0, 0, 0, 0];
    let port = 8080;
    run_server(addr, port, running);
    println!("Done!");
}
