use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::tempdir;
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::DocumentStore;
use uhost_types::{ChangeRequestId, NodeId, OwnershipScope, ResourceMetadata};

struct ChildGuard {
    child: Child,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeedGovernanceChangeRequest {
    id: ChangeRequestId,
    title: String,
    change_type: String,
    requested_by: String,
    approved_by: Option<String>,
    reviewer_comment: Option<String>,
    required_approvals: u8,
    state: String,
    metadata: ResourceMetadata,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Harness {
    address: SocketAddr,
    approved_change_request_id: String,
    _temp: tempfile::TempDir,
    _config_path: PathBuf,
    _guard: ChildGuard,
}

#[derive(Debug, Clone, Copy)]
struct LatencySummary {
    p50_micros: u64,
    p95_micros: u64,
    p99_micros: u64,
}

#[derive(Debug, Clone, Copy)]
struct LoadProfile {
    workers: usize,
    requests_per_worker: usize,
    p95_budget_ms: u64,
    min_throughput_rps: f64,
    max_error_rate: f64,
}

#[derive(Debug, Clone, Copy)]
struct SoakProfile {
    workers: usize,
    duration_seconds: u64,
    max_error_rate: f64,
}

#[derive(Debug, Clone, Copy)]
struct MixedProfile {
    workers: usize,
    iterations_per_worker: usize,
    max_error_rate: f64,
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default)
}

fn default_load_profile() -> LoadProfile {
    LoadProfile {
        workers: env_usize("UHOST_LOAD_WORKERS", 4),
        requests_per_worker: env_usize("UHOST_LOAD_REQUESTS_PER_WORKER", 40),
        p95_budget_ms: env_u64("UHOST_LOAD_P95_BUDGET_MS", 6000),
        min_throughput_rps: env_f64("UHOST_LOAD_MIN_THROUGHPUT_RPS", 1.5),
        max_error_rate: env_f64("UHOST_LOAD_MAX_ERROR_RATE", 0.02),
    }
}

fn default_soak_profile() -> SoakProfile {
    SoakProfile {
        workers: env_usize("UHOST_SOAK_WORKERS", 8),
        duration_seconds: env_u64("UHOST_SOAK_SECONDS", 300),
        max_error_rate: env_f64("UHOST_SOAK_MAX_ERROR_RATE", 0.01),
    }
}

fn default_mixed_profile() -> MixedProfile {
    MixedProfile {
        workers: env_usize("UHOST_MIXED_WORKERS", 2),
        iterations_per_worker: env_usize("UHOST_MIXED_ITERATIONS_PER_WORKER", 12),
        max_error_rate: env_f64("UHOST_MIXED_MAX_ERROR_RATE", 0.15),
    }
}

fn default_wave1_profile() -> MixedProfile {
    MixedProfile {
        workers: env_usize("UHOST_WAVE1_WORKERS", 2),
        iterations_per_worker: env_usize("UHOST_WAVE1_ITERATIONS_PER_WORKER", 8),
        max_error_rate: env_f64("UHOST_WAVE1_MAX_ERROR_RATE", 0.10),
    }
}

#[test]
#[ignore = "resource intensive profile; run explicitly in performance pipelines"]
fn hyperscale_load_identity_write_profile() {
    let harness = launch_harness();
    let profile = default_load_profile();
    let latencies = Arc::new(Mutex::new(Vec::<u64>::new()));
    let failures = Arc::new(AtomicUsize::new(0));
    let issued = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(AtomicUsize::new(0));

    let start = Instant::now();
    let mut workers = Vec::with_capacity(profile.workers);
    for _ in 0..profile.workers {
        let latencies = latencies.clone();
        let failures = failures.clone();
        let issued = issued.clone();
        let counter = counter.clone();
        let address = harness.address;
        workers.push(thread::spawn(move || {
            for _ in 0..profile.requests_per_worker {
                let request_id = counter.fetch_add(1, Ordering::Relaxed);
                let body = format!(
                    r#"{{"email":"load-{request_id}@example.com","display_name":"Load {request_id}","password":"correct horse battery staple {request_id}"}}"#
                );
                let request_start = Instant::now();
                match request(
                    address,
                    "POST",
                    "/identity/users",
                    Some(("application/json", body.as_bytes())),
                ) {
                    Ok(response) => {
                        if !(200..=299).contains(&response.status) {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let elapsed = request_start.elapsed().as_micros() as u64;
                if let Ok(mut storage) = latencies.lock() {
                    storage.push(elapsed);
                }
                issued.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for worker in workers {
        worker
            .join()
            .unwrap_or_else(|_| panic!("worker thread panicked"));
    }
    let elapsed = start.elapsed();

    let total = issued.load(Ordering::Relaxed);
    let failed = failures.load(Ordering::Relaxed);
    let summary = summarize_latencies(&latencies);
    let error_rate = if total == 0 {
        0.0
    } else {
        failed as f64 / total as f64
    };
    let throughput = if elapsed.as_secs_f64() > 0.0 {
        total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    println!(
        "hyperscale_load_identity_write_profile total={total} failed={failed} error_rate={:.5} elapsed_s={:.3} throughput_rps={:.2} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3}",
        error_rate,
        elapsed.as_secs_f64(),
        throughput,
        micros_to_ms(summary.p50_micros),
        micros_to_ms(summary.p95_micros),
        micros_to_ms(summary.p99_micros),
    );

    assert!(
        error_rate <= profile.max_error_rate,
        "load profile error rate {:.5} exceeded threshold {:.5}",
        error_rate,
        profile.max_error_rate
    );
    assert!(
        micros_to_ms(summary.p95_micros) <= profile.p95_budget_ms as f64,
        "p95 latency {:.3}ms exceeded budget {}ms",
        micros_to_ms(summary.p95_micros),
        profile.p95_budget_ms
    );
    assert!(
        throughput >= profile.min_throughput_rps,
        "throughput {:.2} rps is below floor {:.2} rps",
        throughput,
        profile.min_throughput_rps
    );
}

#[test]
#[ignore = "resource intensive profile; run explicitly in performance pipelines"]
fn hyperscale_mixed_endpoint_profile() {
    let harness = launch_harness();
    let profile = default_mixed_profile();
    let failures = Arc::new(AtomicUsize::new(0));
    let issued = Arc::new(AtomicUsize::new(0));
    let sequence = Arc::new(AtomicUsize::new(0));
    let ingress_change_request_id = harness.approved_change_request_id.clone();

    let _ingress_route_id = {
        let response = request_with_retry(
            harness.address,
            "POST",
            "/ingress/routes",
            Some((
                "application/json",
                serde_json::to_vec(&serde_json::json!({
                    "hostname": "mixed-load.example.com",
                    "protocol": "https",
                    "tls_mode": "strict_https",
                    "backends": [
                        { "target": "http://10.0.0.10:8080", "weight": 1 },
                        { "target": "http://10.0.0.11:8080", "weight": 1 }
                    ],
                    "change_request_id": ingress_change_request_id,
                }))
                .unwrap_or_else(|error| panic!("{error}")),
            )),
            3,
        )
        .unwrap_or_else(|error| panic!("failed to create ingress route: {error}"));
        assert_success_response(&response, "create ingress route");
        let payload: Value =
            serde_json::from_slice(&response.body).unwrap_or_else(|error| panic!("{error}"));
        payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing ingress route id"))
            .to_owned()
    };
    let database_id = {
        let response = request_with_retry(
            harness.address,
            "POST",
            "/data/databases",
            Some((
                "application/json",
                br#"{"engine":"postgres","version":"16.2","storage_gb":40,"replicas":2,"tls_required":true,"primary_region":"us-east-1"}"#
                    .to_vec(),
            )),
            3,
        )
        .unwrap_or_else(|error| panic!("failed to create managed database: {error}"));
        assert_success_response(&response, "create managed database");
        let payload: Value =
            serde_json::from_slice(&response.body).unwrap_or_else(|error| panic!("{error}"));
        payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing managed database id"))
            .to_owned()
    };

    let mut workers = Vec::with_capacity(profile.workers);
    for worker_id in 0..profile.workers {
        let failures = failures.clone();
        let issued = issued.clone();
        let sequence = sequence.clone();
        let database_id = database_id.clone();
        let address = harness.address;
        workers.push(thread::spawn(move || {
            for _ in 0..profile.iterations_per_worker {
                let op_id = sequence.fetch_add(1, Ordering::Relaxed);
                let result = if op_id.is_multiple_of(5) {
                    request_with_retry(address, "GET", "/healthz", None, 3).map(|response| {
                        if response.status != 200 {
                            Err(())
                        } else {
                            Ok(())
                        }
                    })
                } else if op_id % 5 == 1 {
                    let base = op_id * 8;
                    let body = format!(
                        r#"{{"users":[{{"email":"mix-{worker_id}-{base}@example.com","display_name":"Mix {base}","password":"pw-{base}"}},{{"email":"mix-{worker_id}-{base_plus_1}@example.com","display_name":"Mix {base_plus_1}","password":"pw-{base_plus_1}"}},{{"email":"mix-{worker_id}-{base_plus_2}@example.com","display_name":"Mix {base_plus_2}","password":"pw-{base_plus_2}"}}],"fail_fast":false}}"#,
                        base_plus_1 = base + 1,
                        base_plus_2 = base + 2,
                    );
                    request_with_retry(
                        address,
                        "POST",
                        "/identity/users/bulk",
                        Some(("application/json", body.into_bytes())),
                        3,
                    )
                    .map(|response| {
                        if !(200..=299).contains(&response.status) {
                            return Err(());
                        }
                        let payload: Value =
                            serde_json::from_slice(&response.body).map_err(|_| ())?;
                        if payload["created_count"].as_u64().unwrap_or_default() < 2 {
                            Err(())
                        } else {
                            Ok(())
                        }
                    })
                } else if op_id % 5 == 2 {
                    let org_slug = format!("mix-org-{worker_id}-{op_id}");
                    let org_body = format!(r#"{{"name":"{org_slug}","slug":"{org_slug}"}}"#);
                    match request_with_retry(
                        address,
                        "POST",
                        "/tenancy/organizations",
                        Some(("application/json", org_body.into_bytes())),
                        3,
                    ) {
                        Ok(response) if (200..=299).contains(&response.status) => Ok(Ok(())),
                        _ => Ok(Err(())),
                    }
                } else if op_id % 5 == 3 {
                    let body = format!(
                        r#"{{"hostname":"mixed-load.example.com","protocol":"https","client_ip":"198.51.100.{octet}","session_key":"mix-session-{worker_id}-{op_id}"}}"#,
                        octet = (op_id % 200) + 1
                    );
                    request_with_retry(
                        address,
                        "POST",
                        "/ingress/evaluate",
                        Some(("application/json", body.into_bytes())),
                        3,
                    )
                    .map(|response| {
                        if !(200..=299).contains(&response.status) {
                            return Err(());
                        }
                        let payload: Value =
                            serde_json::from_slice(&response.body).map_err(|_| ())?;
                        if !payload["admitted"].as_bool().unwrap_or(false) {
                            Err(())
                        } else {
                            Ok(())
                        }
                    })
                } else {
                    let body = format!(
                        r#"{{"kind":"full","reason":"mixed-profile-{worker_id}-{op_id}"}}"#
                    );
                    request_with_retry(
                        address,
                        "POST",
                        &format!("/data/databases/{database_id}/backups"),
                        Some(("application/json", body.into_bytes())),
                        3,
                    )
                    .map(|response| {
                        if !(200..=299).contains(&response.status) {
                            return Err(());
                        }
                        let payload: Value =
                            serde_json::from_slice(&response.body).map_err(|_| ())?;
                        if payload["state"].as_str().unwrap_or_default() != "completed" {
                            Err(())
                        } else {
                            Ok(())
                        }
                    })
                };
                issued.fetch_add(1, Ordering::Relaxed);
                let failed = match result {
                    Ok(Ok(())) => false,
                    Ok(Err(())) => true,
                    Err(_) => true,
                };
                if failed {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for worker in workers {
        worker
            .join()
            .unwrap_or_else(|_| panic!("worker thread panicked"));
    }
    let total = issued.load(Ordering::Relaxed);
    let failed = failures.load(Ordering::Relaxed);
    let error_rate = if total == 0 {
        0.0
    } else {
        failed as f64 / total as f64
    };
    println!(
        "hyperscale_mixed_endpoint_profile total={total} failed={failed} error_rate={:.5}",
        error_rate,
    );
    assert!(
        error_rate <= profile.max_error_rate,
        "mixed profile error rate {:.5} exceeded threshold {:.5}",
        error_rate,
        profile.max_error_rate
    );
}

#[derive(Debug, Clone)]
struct Wave1ParityProfileContext {
    ingress_hostname: String,
    capability_id: String,
}

#[test]
#[ignore = "focused wave1 parity smoke profile; run explicitly in performance pipelines"]
fn hyperscale_wave1_parity_profile() {
    let harness = launch_harness();
    let profile = default_wave1_profile();
    let context =
        prepare_wave1_parity_profile(harness.address, harness.approved_change_request_id.as_str());
    let failures = Arc::new(AtomicUsize::new(0));
    let issued = Arc::new(AtomicUsize::new(0));
    let sequence = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::with_capacity(profile.workers);
    for worker_id in 0..profile.workers {
        let failures = failures.clone();
        let issued = issued.clone();
        let sequence = sequence.clone();
        let address = harness.address;
        let ingress_hostname = context.ingress_hostname.clone();
        let capability_id = context.capability_id.clone();
        workers.push(thread::spawn(move || {
            for _ in 0..profile.iterations_per_worker {
                let op_id = sequence.fetch_add(1, Ordering::Relaxed);
                let result = match op_id % 4 {
                    0 => {
                        let body = serde_json::json!({
                            "subject": format!("svc:wave1-{worker_id}-{op_id}"),
                            "display_name": format!("Wave1 {op_id}"),
                            "audiences": ["secrets", "identity"],
                            "ttl_seconds": 900,
                        });
                        request_with_retry(
                            address,
                            "POST",
                            "/identity/workload-identities",
                            Some((
                                "application/json",
                                serde_json::to_vec(&body).unwrap_or_else(|error| panic!("{error}")),
                            )),
                            3,
                        )
                        .map(|response| {
                            if !(200..=299).contains(&response.status) {
                                return Err(());
                            }
                            let payload: Value =
                                serde_json::from_slice(&response.body).map_err(|_| ())?;
                            if payload["identity"]["principal"]["kind"] != "workload" {
                                Err(())
                            } else {
                                Ok(())
                            }
                        })
                    }
                    1 => {
                        let body = serde_json::json!({
                            "resource_kind": "service",
                            "action": "deploy",
                            "selector": {
                                "env": "prod",
                                "team": "parity"
                            }
                        });
                        request_with_retry(
                            address,
                            "POST",
                            "/policy/evaluate",
                            Some((
                                "application/json",
                                serde_json::to_vec(&body).unwrap_or_else(|error| panic!("{error}")),
                            )),
                            3,
                        )
                        .map(|response| {
                            if !(200..=299).contains(&response.status) {
                                return Err(());
                            }
                            let payload: Value =
                                serde_json::from_slice(&response.body).map_err(|_| ())?;
                            if payload["decision"].as_str() != Some("allow") {
                                return Err(());
                            }
                            if payload["explanation"]["matched_policy_ids"]
                                .as_array()
                                .is_none_or(|items| items.is_empty())
                            {
                                Err(())
                            } else {
                                Ok(())
                            }
                        })
                    }
                    2 => {
                        let body = serde_json::json!({
                            "hostname": ingress_hostname,
                            "protocol": "https",
                            "client_ip": format!("198.51.100.{}", (op_id % 200) + 1),
                            "session_key": format!("wave1-session-{worker_id}-{op_id}")
                        });
                        request_with_retry(
                            address,
                            "POST",
                            "/ingress/evaluate",
                            Some((
                                "application/json",
                                serde_json::to_vec(&body).unwrap_or_else(|error| panic!("{error}")),
                            )),
                            3,
                        )
                        .map(|response| {
                            if !(200..=299).contains(&response.status) {
                                return Err(());
                            }
                            let payload: Value =
                                serde_json::from_slice(&response.body).map_err(|_| ())?;
                            if !payload["admitted"].as_bool().unwrap_or(false) {
                                Err(())
                            } else {
                                Ok(())
                            }
                        })
                    }
                    _ => {
                        let body = serde_json::json!({
                            "capability_id": capability_id,
                            "guest_architecture": "x86_64",
                            "guest_os": "linux",
                            "vcpu": 2,
                            "memory_mb": 2048,
                            "migration_policy": "cold_only",
                            "require_secure_boot": false,
                            "requires_live_migration": false,
                            "compatibility_requirement": {
                                "guest_architecture": "x86_64",
                                "machine_family": "general_purpose_pci",
                                "guest_profile": "linux_standard",
                                "boot_device": "disk",
                                "claim_tier": "compatible"
                            }
                        });
                        request_with_retry(
                            address,
                            "POST",
                            "/uvm/runtime/preflight",
                            Some((
                                "application/json",
                                serde_json::to_vec(&body).unwrap_or_else(|error| panic!("{error}")),
                            )),
                            3,
                        )
                        .map(|response| {
                            if !(200..=299).contains(&response.status) {
                                return Err(());
                            }
                            let payload: Value =
                                serde_json::from_slice(&response.body).map_err(|_| ())?;
                            if !payload["legal_allowed"].as_bool().unwrap_or(false)
                                || !payload["placement_admitted"].as_bool().unwrap_or(false)
                                || !payload["compatibility_assessment"]["supported"]
                                    .as_bool()
                                    .unwrap_or(false)
                            {
                                Err(())
                            } else {
                                Ok(())
                            }
                        })
                    }
                };
                issued.fetch_add(1, Ordering::Relaxed);
                let failed = match result {
                    Ok(Ok(())) => false,
                    Ok(Err(())) => true,
                    Err(_) => true,
                };
                if failed {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for worker in workers {
        worker
            .join()
            .unwrap_or_else(|_| panic!("worker thread panicked"));
    }

    let total = issued.load(Ordering::Relaxed);
    let failed = failures.load(Ordering::Relaxed);
    let error_rate = if total == 0 {
        0.0
    } else {
        failed as f64 / total as f64
    };
    println!(
        "hyperscale_wave1_parity_profile total={total} failed={failed} error_rate={:.5}",
        error_rate,
    );
    assert!(
        error_rate <= profile.max_error_rate,
        "wave1 parity profile error rate {:.5} exceeded threshold {:.5}",
        error_rate,
        profile.max_error_rate
    );
}

fn prepare_wave1_parity_profile(
    address: SocketAddr,
    ingress_change_request_id: &str,
) -> Wave1ParityProfileContext {
    let allow_policy = serde_json::json!({
        "resource_kind": "service",
        "action": "deploy",
        "effect": "allow",
        "selector": {
            "env": "prod",
            "team": "parity"
        }
    });
    let allow_policy_response = request_with_retry(
        address,
        "POST",
        "/policy/policies",
        Some((
            "application/json",
            serde_json::to_vec(&allow_policy).unwrap_or_else(|error| panic!("{error}")),
        )),
        3,
    )
    .unwrap_or_else(|error| panic!("failed to create parity policy: {error}"));
    assert!((200..=299).contains(&allow_policy_response.status));

    let zone_response = request_with_retry(
        address,
        "POST",
        "/dns/zones",
        Some((
            "application/json",
            serde_json::to_vec(&serde_json::json!({ "domain": "wave1.example.com" }))
                .unwrap_or_else(|error| panic!("{error}")),
        )),
        3,
    )
    .unwrap_or_else(|error| panic!("failed to create dns zone: {error}"));
    assert!((200..=299).contains(&zone_response.status));
    let zone_payload: Value =
        serde_json::from_slice(&zone_response.body).unwrap_or_else(|error| panic!("{error}"));
    let zone_id = zone_payload["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing dns zone id"))
        .to_owned();

    let inspection_response = request_with_retry(
        address,
        "POST",
        "/netsec/inspection-profiles",
        Some((
            "application/json",
            serde_json::to_vec(&serde_json::json!({
                "name": "wave1-edge",
                "blocked_countries": ["RU"],
                "min_waf_score": 600,
                "max_bot_score": 350,
                "ddos_mode": "mitigate"
            }))
            .unwrap_or_else(|error| panic!("{error}")),
        )),
        3,
    )
    .unwrap_or_else(|error| panic!("failed to create inspection profile: {error}"));
    assert!((200..=299).contains(&inspection_response.status));
    let inspection_payload: Value =
        serde_json::from_slice(&inspection_response.body).unwrap_or_else(|error| panic!("{error}"));
    let inspection_profile_id = inspection_payload["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing inspection profile id"))
        .to_owned();
    let ingress_hostname = String::from("api.wave1.example.com");
    let ingress_response = request_with_retry(
        address,
        "POST",
        "/ingress/routes",
        Some((
            "application/json",
            serde_json::to_vec(&serde_json::json!({
                "hostname": ingress_hostname,
                "protocol": "https",
                "tls_mode": "strict_https",
                "backends": [
                    { "target": "http://10.0.0.10:8080", "weight": 1 },
                    { "target": "http://10.0.0.11:8080", "weight": 1 }
                ],
                "change_request_id": ingress_change_request_id,
                "publication": {
                    "exposure": "public",
                    "dns_binding": {
                        "zone_id": zone_id
                    },
                    "security_policy": {
                        "inspection_profile_id": inspection_profile_id
                    }
                }
            }))
            .unwrap_or_else(|error| panic!("{error}")),
        )),
        3,
    )
    .unwrap_or_else(|error| panic!("failed to create ingress publication route: {error}"));
    assert!((200..=299).contains(&ingress_response.status));

    let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let capability_response = request_with_retry(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some((
            "application/json",
            serde_json::to_vec(&serde_json::json!({
                "node_id": node_id.to_string(),
                "architecture": "x86_64",
                "accelerator_backends": ["software_dbt"],
                "max_vcpu": 8,
                "max_memory_mb": 16384,
                "numa_nodes": 1,
                "supports_secure_boot": false,
                "supports_live_migration": false,
                "supports_pci_passthrough": false,
                "software_runner_supported": true,
                "host_evidence_mode": "direct_host"
            }))
            .unwrap_or_else(|error| panic!("{error}")),
        )),
        3,
    )
    .unwrap_or_else(|error| panic!("failed to create node capability: {error}"));
    assert!((200..=299).contains(&capability_response.status));
    let capability_payload: Value =
        serde_json::from_slice(&capability_response.body).unwrap_or_else(|error| panic!("{error}"));
    let capability_id = capability_payload["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing capability id"))
        .to_owned();

    Wave1ParityProfileContext {
        ingress_hostname,
        capability_id,
    }
}

#[test]
#[ignore = "long-running soak profile; run explicitly in dedicated pipelines"]
fn hyperscale_soak_mixed_profile() {
    let harness = launch_harness();
    let profile = default_soak_profile();
    let deadline = Instant::now() + Duration::from_secs(profile.duration_seconds);
    let failures = Arc::new(AtomicUsize::new(0));
    let issued = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(AtomicUsize::new(0));
    let latencies = Arc::new(Mutex::new(Vec::<u64>::new()));

    let mut workers = Vec::with_capacity(profile.workers);
    for worker_id in 0..profile.workers {
        let failures = failures.clone();
        let issued = issued.clone();
        let counter = counter.clone();
        let latencies = latencies.clone();
        let address = harness.address;
        workers.push(thread::spawn(move || {
            while Instant::now() < deadline {
                let request_id = counter.fetch_add(1, Ordering::Relaxed);
                let operation_start = Instant::now();
                let result = if request_id.is_multiple_of(4) {
                    request(address, "GET", "/identity/users", None)
                } else {
                    let body = format!(
                        r#"{{"email":"soak-{worker_id}-{request_id}@example.com","display_name":"Soak {request_id}","password":"correct horse battery staple {request_id}"}}"#
                    );
                    request(
                        address,
                        "POST",
                        "/identity/users",
                        Some(("application/json", body.as_bytes())),
                    )
                };
                let elapsed = operation_start.elapsed().as_micros() as u64;
                if let Ok(mut storage) = latencies.lock() {
                    storage.push(elapsed);
                }
                issued.fetch_add(1, Ordering::Relaxed);
                match result {
                    Ok(response) if (200..=299).contains(&response.status) => {}
                    _ => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for worker in workers {
        worker
            .join()
            .unwrap_or_else(|_| panic!("worker thread panicked"));
    }

    let total = issued.load(Ordering::Relaxed);
    let failed = failures.load(Ordering::Relaxed);
    let summary = summarize_latencies(&latencies);
    let error_rate = if total == 0 {
        0.0
    } else {
        failed as f64 / total as f64
    };
    println!(
        "hyperscale_soak_mixed_profile total={total} failed={failed} error_rate={:.5} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3}",
        error_rate,
        micros_to_ms(summary.p50_micros),
        micros_to_ms(summary.p95_micros),
        micros_to_ms(summary.p99_micros),
    );
    assert!(
        error_rate <= profile.max_error_rate,
        "soak error rate {:.5} exceeded threshold {:.5}",
        error_rate,
        profile.max_error_rate
    );
}

#[test]
#[ignore = "restart/chaos profile; run explicitly in dedicated pipelines"]
fn hyperscale_chaos_restart_profile() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!("skipping hyperscale_chaos_restart_profile: loopback bind not permitted");
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let first_guard = ChildGuard {
        child: spawn_uhostd(&config_path),
    };
    wait_for_health(address);
    run_identity_burst(address, "before");

    drop(first_guard);

    let second_guard = ChildGuard {
        child: spawn_uhostd(&config_path),
    };
    wait_for_health(address);
    run_identity_burst(address, "after");
    drop(second_guard);
}

fn run_identity_burst(address: SocketAddr, marker: &str) {
    let marker = marker.to_owned();
    let failures = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(6);
    for worker_id in 0..6 {
        let marker = marker.clone();
        let failures = failures.clone();
        let counter = counter.clone();
        workers.push(thread::spawn(move || {
            for _ in 0..80 {
                let sequence = counter.fetch_add(1, Ordering::Relaxed);
                let body = format!(
                    r#"{{"email":"chaos-{marker}-{worker_id}-{sequence}@example.com","display_name":"Chaos {sequence}","password":"correct horse battery staple {sequence}"}}"#
                );
                match request(
                    address,
                    "POST",
                    "/identity/users",
                    Some(("application/json", body.as_bytes())),
                ) {
                    Ok(response) if (200..=299).contains(&response.status) => {}
                    _ => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for worker in workers {
        worker
            .join()
            .unwrap_or_else(|_| panic!("worker thread panicked"));
    }
    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "chaos burst `{marker}` observed failures"
    );
}

fn launch_harness() -> Harness {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let approved_change_request_id = seed_governance_change_request(&state_dir, "approved");
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        panic!("loopback bind not permitted in this environment");
    };
    write_test_config(&config_path, address, &state_dir);
    let child = spawn_uhostd(&config_path);
    let guard = ChildGuard { child };
    wait_for_health(address);
    Harness {
        address,
        approved_change_request_id,
        _temp: temp,
        _config_path: config_path,
        _guard: guard,
    }
}

fn spawn_uhostd(config_path: &Path) -> Child {
    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    Command::new(binary)
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"))
}

fn summarize_latencies(storage: &Mutex<Vec<u64>>) -> LatencySummary {
    let mut values = storage
        .lock()
        .unwrap_or_else(|_| panic!("latency storage poisoned"))
        .clone();
    values.sort_unstable();
    if values.is_empty() {
        return LatencySummary {
            p50_micros: 0,
            p95_micros: 0,
            p99_micros: 0,
        };
    }
    let p50_index = percentile_index(values.len(), 50);
    let p95_index = percentile_index(values.len(), 95);
    let p99_index = percentile_index(values.len(), 99);
    LatencySummary {
        p50_micros: values[p50_index],
        p95_micros: values[p95_index],
        p99_micros: values[p99_index],
    }
}

fn percentile_index(length: usize, percentile: usize) -> usize {
    if length <= 1 {
        return 0;
    }
    let rank = (length * percentile).div_ceil(100);
    rank.saturating_sub(1).min(length - 1)
}

fn micros_to_ms(value: u64) -> f64 {
    value as f64 / 1000.0
}

fn reserve_loopback_port() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("failed to allocate test port: {error}"),
    };
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("failed to read test port: {error}"));
    drop(listener);
    Some(address)
}

fn seed_governance_change_request(state_dir: &Path, state: &str) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("failed to build tokio runtime: {error}"));
    runtime.block_on(async {
        let store = DocumentStore::open(state_dir.join("governance").join("change_requests.json"))
            .await
            .unwrap_or_else(|error| panic!("failed to open governance change store: {error}"));
        let id = ChangeRequestId::generate()
            .unwrap_or_else(|error| panic!("failed to generate change request id: {error}"));
        let approved_by = matches!(state, "approved" | "rejected" | "applied")
            .then(|| String::from("operator://hyperscale-seed-approver"));
        store
            .create(
                id.as_str(),
                SeedGovernanceChangeRequest {
                    id: id.clone(),
                    title: String::from("Hyperscale ingress seed"),
                    change_type: String::from("policy_change"),
                    requested_by: String::from("operator://hyperscale-seed-requester"),
                    approved_by,
                    reviewer_comment: None,
                    required_approvals: 1,
                    state: state.to_owned(),
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(id.to_string()),
                        sha256_hex(id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("failed to seed governance change request: {error}"));
        id.to_string()
    })
}

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "test-node"

[secrets]
master_key = "{}"
"#,
        state_dir.display(),
        base64url_encode(&[0x42; 32]),
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn wait_for_health(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(response) = request(address, "GET", "/healthz", None)
            && response.status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("uhostd did not become healthy in time");
}

struct RawResponse {
    status: u16,
    body: Vec<u8>,
}

fn assert_success_response(response: &RawResponse, context: &str) {
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        (200..=299).contains(&response.status),
        "{context} returned status {} with body {body}",
        response.status
    );
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        payload.len(),
    );
    stream.write_all(request.as_bytes())?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid HTTP response framing"))?;
    let (head, body) = response.split_at(split + 4);
    let status_line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP status line"))?;
    let status_line = std::str::from_utf8(&head[..status_line_end])
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;
    let mut status_parts = status_line.split_whitespace();
    let _http_version = status_parts.next();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid status code"))?;

    Ok(RawResponse {
        status,
        body: body.to_vec(),
    })
}

fn request_with_retry(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, Vec<u8>)>,
    attempts: usize,
) -> Result<RawResponse, Error> {
    let attempts = attempts.max(1);
    let mut last_error = None;
    for attempt in 0..attempts {
        let borrowed = body
            .as_ref()
            .map(|(content_type, payload)| (*content_type, payload.as_slice()));
        match request(address, method, path, borrowed) {
            Ok(response) => return Ok(response),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < attempts {
                    let backoff_ms = 25_u64.saturating_mul((attempt as u64).saturating_add(1));
                    thread::sleep(Duration::from_millis(backoff_ms));
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::other("request retry failed")))
}
