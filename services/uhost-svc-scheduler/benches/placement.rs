use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use uhost_svc_scheduler::{NodeInventory, PlacementDemand, placement_score};
use uhost_types::{NodeId, OwnershipScope, ResourceMetadata};

fn bench_placement_score(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("placement_score");
    for node_count in [16_u32, 128, 512, 2048] {
        let nodes = build_nodes(node_count);
        let demand = PlacementDemand {
            cpu_millis: 250,
            memory_mb: 512,
        };
        group.throughput(Throughput::Elements(u64::from(node_count)));
        group.bench_with_input(
            BenchmarkId::from_parameter(node_count),
            &node_count,
            |bench, _| {
                bench.iter(|| {
                    let mut best = f64::NEG_INFINITY;
                    for node in &nodes {
                        let score = placement_score(node, demand);
                        if score > best {
                            best = score;
                        }
                    }
                    best
                });
            },
        );
    }
    group.finish();
}

fn build_nodes(count: u32) -> Vec<NodeInventory> {
    (0..count)
        .map(|index| {
            let id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
            NodeInventory {
                id,
                region: if index % 2 == 0 {
                    String::from("us-east")
                } else {
                    String::from("us-west")
                },
                scheduler_pool: if index % 4 == 0 {
                    String::from("gpu")
                } else {
                    String::from("general")
                },
                cpu_millis: 4000,
                memory_mb: 8192,
                free_cpu_millis: 4000 - (index % 1000),
                free_memory_mb: 8192 - u64::from(index % 1024),
                drained: false,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    None,
                    format!("etag-{index}"),
                ),
            }
        })
        .collect::<Vec<_>>()
}

criterion_group!(benches, bench_placement_score);
criterion_main!(benches);
