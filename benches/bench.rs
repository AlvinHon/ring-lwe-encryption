use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rng;
use rlwe_encryption::Message;

criterion_group! {
    name = standard;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_micros(600));
    targets = bench_standard_encrypt, bench_standard_decrypt
}

criterion_main!(standard);

fn bench_standard_encrypt(c: &mut Criterion) {
    let rng = &mut rng();
    let (ek, _) = rlwe_encryption::standard(rng);
    let message = Message::random(rng, 256);

    c.bench_function("standard_encrypt", |b| {
        b.iter_batched(
            || message.clone(),
            |message| {
                let _ = ek.encrypt(rng, message);
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_standard_decrypt(c: &mut Criterion) {
    let rng = &mut rng();
    let (ek, dk) = rlwe_encryption::standard(rng);
    let message = Message::random(rng, 256);
    let ciphertext = ek.encrypt(rng, message);

    c.bench_function("standard_decrypt", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |ciphertext| {
                let _ = dk.decrypt(ciphertext);
            },
            criterion::BatchSize::SmallInput,
        )
    });
}
