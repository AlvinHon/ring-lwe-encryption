use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;

criterion_group! {
    name = standard;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_micros(600));
    targets = bench_standard_encrypt, bench_standard_decrypt
}

criterion_main!(standard);

fn bench_standard_encrypt(c: &mut Criterion) {
    let rng = &mut rand::thread_rng();
    let (ek, _) = rlwe_encryption::standard(rng);
    let message = (0..256).map(|_| rng.gen_range(0..2)).collect::<Vec<i32>>();

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
    let rng = &mut rand::thread_rng();
    let (ek, dk) = rlwe_encryption::standard(rng);
    let message = (0..256).map(|_| rng.gen_range(0..2)).collect::<Vec<i32>>();
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
