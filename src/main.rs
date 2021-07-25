use std::io;
use std::io::Read;
use std::thread;

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("create interface");
    let mut l1 = i.bind(9000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection on 9000!");
            let n = stream.read(&mut [0]).unwrap();
            eprint!("read data");
            assert_eq!(n, 0);
            eprintln!("no more data!");
        }
    });

    jh1.join().unwrap();

    Ok(())
}
