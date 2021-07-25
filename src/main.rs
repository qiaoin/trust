use std::io;
use std::thread;

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    let mut l1 = i.bind(9000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(_stream) = l1.accept() {
            eprintln!("got connection on 9000!");
        }
    });

    jh1.join().unwrap();

    Ok(())
}
