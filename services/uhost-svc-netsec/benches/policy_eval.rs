use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use uhost_svc_netsec::evaluate_ipv4_cidr_match;

fn bench_ipv4_cidr_eval(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("ipv4_cidr_eval");
    for count in [32_u64, 256, 1024, 4096] {
        let cidrs = build_cidrs(count as u32);
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |bench, _| {
            bench.iter(|| {
                let mut allowed = 0_u64;
                for cidr in &cidrs {
                    if evaluate_ipv4_cidr_match("10.1.2.3", cidr)
                        .unwrap_or_else(|error| panic!("{error}"))
                    {
                        allowed += 1;
                    }
                }
                allowed
            });
        });
    }
    group.finish();
}

fn build_cidrs(count: u32) -> Vec<String> {
    (0..count)
        .map(|index| format!("10.{}.0.0/16", index % 255))
        .collect::<Vec<_>>()
}

criterion_group!(benches, bench_ipv4_cidr_eval);
criterion_main!(benches);
