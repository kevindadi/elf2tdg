use std::thread;

#[inline(never)]
fn task_body() {
    println!("task");
}

fn main() {
    let handle = thread::spawn(|| {
        task_body();
    });
    handle.join().unwrap();

    thread::scope(|scope| {
        scope.spawn(|| {
            task_body();
        });
    });
}
