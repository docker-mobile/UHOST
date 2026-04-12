# uhost-svc-stream

Purpose:

- Own managed stream inventory plus durable partition and consumer-subscription records.
- Provide a replayable partitioned-log publish and acknowledge lifecycle with persisted lag summaries.

Primary endpoints:

- `GET /stream`
- `GET /stream/summary`
- `GET/POST /stream/streams`
- `GET /stream/streams/{stream_id}`
- `GET /stream/streams/{stream_id}/partitions`
- `POST /stream/streams/{stream_id}/publish`
- `GET /stream/streams/{stream_id}/replay`
- `GET /stream/streams/{stream_id}/lag-summary`
- `GET/POST /stream/subscriptions`
- `GET /stream/subscriptions/{subscription_id}`
- `POST /stream/subscriptions/{subscription_id}/ack`
- `GET /stream/outbox`

State files:

- `stream/streams.json`
- `stream/partitions.json`
- `stream/log_entries.json`
- `stream/subscriptions.json`
- `stream/audit.log`
- `stream/outbox.json`

Operational notes:

- Streams now use service-managed `stm_...` identifiers instead of reusing shared replication IDs.
- Publishing appends replayable records into a durable partitioned log, advances stream and partition high watermarks, and recomputes subscriber lag for the affected stream.
- Startup reconciliation rebuilds stream, partition, and subscriber lag projections from the retained log so replay state stays consistent after reopen.
- Legacy counter-style publishes still work, but they now materialize synthetic replayable log records so replay surfaces stay consistent.
- Acknowledgements are monotonic and persisted, so lag summaries survive process restarts.
