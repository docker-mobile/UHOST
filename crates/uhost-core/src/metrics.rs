//! Lightweight metrics primitives.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

/// Histogram snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistogramSnapshot {
    /// Number of samples recorded.
    pub count: u64,
    /// Sum of all samples.
    pub sum: f64,
    /// Minimum sample.
    pub min: f64,
    /// Maximum sample.
    pub max: f64,
}

/// Entire metric registry snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSnapshot {
    /// Counter series.
    pub counters: BTreeMap<String, u64>,
    /// Gauge series.
    pub gauges: BTreeMap<String, f64>,
    /// Histogram series.
    pub histograms: BTreeMap<String, HistogramSnapshot>,
}

#[derive(Debug, Clone, Default)]
struct HistogramState {
    count: u64,
    sum: f64,
    min: f64,
    max: f64,
}

impl HistogramState {
    fn record(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        self.min = if self.count == 1 {
            value
        } else {
            self.min.min(value)
        };
        self.max = if self.count == 1 {
            value
        } else {
            self.max.max(value)
        };
    }

    fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            count: self.count,
            sum: self.sum,
            min: self.min,
            max: self.max,
        }
    }
}

/// In-process metric registry.
#[derive(Debug, Clone, Default)]
pub struct MetricRegistry {
    counters: Arc<RwLock<BTreeMap<String, u64>>>,
    gauges: Arc<RwLock<BTreeMap<String, f64>>>,
    histograms: Arc<RwLock<BTreeMap<String, HistogramState>>>,
}

impl MetricRegistry {
    /// Increment a counter by the given amount.
    pub fn increment_counter(&self, name: &str, amount: u64) {
        if let Ok(mut guard) = self.counters.write() {
            *guard.entry(name.to_owned()).or_insert(0) += amount;
        }
    }

    /// Set a gauge to a new value.
    pub fn set_gauge(&self, name: &str, value: f64) {
        if let Ok(mut guard) = self.gauges.write() {
            guard.insert(name.to_owned(), value);
        }
    }

    /// Record a histogram sample.
    pub fn record_histogram(&self, name: &str, value: f64) {
        if let Ok(mut guard) = self.histograms.write() {
            guard.entry(name.to_owned()).or_default().record(value);
        }
    }

    /// Take a consistent snapshot of all registered metrics.
    pub fn snapshot(&self) -> MetricSnapshot {
        let counters = self
            .counters
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        let gauges = self
            .gauges
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        let histograms = self
            .histograms
            .read()
            .map(|guard| {
                guard
                    .iter()
                    .map(|(name, state)| (name.clone(), state.snapshot()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        MetricSnapshot {
            counters,
            gauges,
            histograms,
        }
    }
}
