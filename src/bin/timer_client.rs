use rusty_but_fast::timer;

fn do_opt(opt: &str, prefix: &[u8], conn: &mut std::net::TcpStream) -> bool {
    match opt {
        "start" => timer::start(prefix, conn).unwrap(),
        "stop" => timer::stop(prefix, conn).unwrap(),
        "reset" => timer::reset(prefix, conn).unwrap(),
        "get" => {
            let d = match timer::get(prefix, conn) {
                Ok(ok) => ok,
                Err(err) => panic!("Failed to get the current time: {}", err),
            };
            println!("Current time: {}.{}", d.as_secs(), d.subsec_nanos());
        },
        _ => return false,
    }
    return true;
}

fn main() {
    let bin_name = std::env::current_exe().expect("Couldn't get the filename");
    let bin_name = bin_name.to_str().expect("Couldn't get the filename");

    println!("Running the client!");

    let empty: [u8; 0] = [];
    let empty = &empty[..];

    let conn = std::net::TcpStream::connect("127.0.0.1:8080");
    let conn = &mut conn.expect("Couldn't connect to the server...");

    let mut found = 0;
    for arg in std::env::args() {
        if do_opt(&arg, empty, conn) {
            found |= 1;
        }
    }

    if found == 0 {
        println!("Usage: {} [start|stop|reset|get]*", bin_name);
    }
}
