use std::io::{self, Write};
use std::io::Read;
use std::thread;

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("create interface");
    let mut l1 = i.bind(9000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection on 9000!");
            stream.write(b"hello").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n == 0 {
                    eprintln!("no more data!");
                    break;
                } else {
                    eprintln!("got {}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        }
    });

    jh1.join().unwrap();

    Ok(())
}
