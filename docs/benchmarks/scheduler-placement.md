# Scheduler Placement Benchmark

Date: March 18, 2026  
Command:

```bash
cargo bench -p uhost-svc-scheduler --bench placement -- --sample-size 10
```

## Results

- `placement_score/16` time `[56.218 ns, 56.897 ns, 57.911 ns]`
- `placement_score/128` time `[450.09 ns, 467.62 ns, 483.69 ns]`
- `placement_score/512` time `[1.8455 us, 1.9307 us, 2.0525 us]`
- `placement_score/2048` time `[7.3473 us, 7.4600 us, 7.6678 us]`

Throughput remained in the `~250M-285M element/s` band across tested sizes,
indicating stable linear behavior for the current pure scoring pass.

## Interpretation

- Placement scoring cost scales linearly with candidate count.
- The current in-memory scoring loop is fast enough for all-in-one mode.
- Next optimization candidates are candidate filtering and batching, not raw
  arithmetic throughput.
