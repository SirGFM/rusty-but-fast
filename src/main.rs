use std::sync::atomic::AtomicBool as AtomicBool;
use std::time::Duration as Duration;

fn handle_client(conn: std::net::TcpStream, addr: std::net::SocketAddr, running: std::sync::Arc<AtomicBool>) {
    println!("New TCP connection from {}!", addr);
}

fn run_server(addr: [u8; 4], port: u16, running: std::sync::Arc<AtomicBool>) {
    let addrs = [
        std::net::SocketAddr::from((addr, port)),
    ];
    let listener = std::net::TcpListener::bind(&addrs[..]).expect("Failed to bind the TCP listener");
    listener.set_nonblocking(true).expect("Cannot set non-blocking");

    let mut wait = 10;
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((conn, addr)) => {
                let running_thread = running.clone();
                std::thread::spawn(move || {
                    handle_client(conn, addr, running_thread);
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
