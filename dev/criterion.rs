//! A `criterion` [`Measurement`] that counts retired CPU instructions
//! instead of measuring wall-clock time.

use std::time::Duration;

use criterion::Criterion;


#[cfg(all(linux, target_pointer_width = "64", feature = "bench-instrs"))]
mod linux {
    use criterion::measurement::Measurement;
    use criterion::measurement::ValueFormatter;
    use criterion::Throughput;

    use perf_event::events::Hardware;
    use perf_event::Builder;
    use perf_event::Counter;


    /// A `criterion` measurement reporting the number of retired (user space)
    /// instructions executed by the benchmarked code.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct InstructionCount;

    impl Measurement for InstructionCount {
        type Intermediate = Counter;
        type Value = u64;

        fn start(&self) -> Self::Intermediate {
            // The `perf_event` crate excludes kernel and hypervisor events by
            // default, i.e., we only count user space instructions. That keeps
            // results reproducible and works without elevated privileges.
            let mut counter = Builder::new().kind(Hardware::INSTRUCTIONS).build().expect(
                "failed to create instruction counter via `perf_event_open(2)`; ensure it \
             is supported and `/proc/sys/kernel/perf_event_paranoid` is <= 2",
            );
            let () = counter
                .enable()
                .expect("failed to enable instruction counter");
            counter
        }

        fn end(&self, mut counter: Self::Intermediate) -> Self::Value {
            let () = counter
                .disable()
                .expect("failed to disable instruction counter");
            counter.read().expect("failed to read instruction counter")
        }

        fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
            *v1 + *v2
        }

        fn zero(&self) -> Self::Value {
            0
        }

        fn to_f64(&self, value: &Self::Value) -> f64 {
            *value as f64
        }

        fn formatter(&self) -> &dyn ValueFormatter {
            &InstructionCountFormatter
        }
    }


    /// The [`ValueFormatter`] for [`InstructionCount`].
    struct InstructionCountFormatter;

    impl ValueFormatter for InstructionCountFormatter {
        fn scale_values(&self, typical_value: f64, values: &mut [f64]) -> &'static str {
            let (factor, unit) = if typical_value < 10f64.powi(3) {
                (10f64.powi(0), " instr")
            } else if typical_value < 10f64.powi(6) {
                (10f64.powi(-3), "Kinstr")
            } else if typical_value < 10f64.powi(9) {
                (10f64.powi(-6), "Minstr")
            } else {
                (10f64.powi(-9), "Ginstr")
            };

            for val in values {
                *val *= factor;
            }
            unit
        }

        fn scale_throughputs(
            &self,
            _typical_value: f64,
            throughput: &Throughput,
            values: &mut [f64],
        ) -> &'static str {
            // Report throughput as the number of instructions spent per
            // processed unit; fewer instructions per unit is better.
            let (count, unit) = match *throughput {
                Throughput::Bits(n) => (n as f64, "instr/bit"),
                Throughput::Bytes(n) | Throughput::BytesDecimal(n) => (n as f64, "instr/byte"),
                Throughput::Elements(n) => (n as f64, "instr/elem"),
                Throughput::ElementsAndBytes { elements, .. } => (elements as f64, "instr/elem"),
            };

            for val in values {
                *val /= count;
            }
            unit
        }

        fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
            "instr"
        }
    }
}

/// Provide a `criterion` configuration that measures instructions
/// counts instead of wall clock time.
#[cfg(all(linux, target_pointer_width = "64", feature = "bench-instrs"))]
pub fn config() -> Criterion<linux::InstructionCount> {
    use linux::*;

    Criterion::default()
        .warm_up_time(Duration::from_millis(100))
        // Instruction sampling has extremely low noise. Go with the minimum
        // amount of samples.
        .sample_size(10)
        .with_measurement(InstructionCount)
}

/// Provide a default `criterion` configuration.
#[cfg(not(all(linux, target_pointer_width = "64", feature = "bench-instrs")))]
pub fn config() -> Criterion {
    Criterion::default().warm_up_time(Duration::from_secs(1))
}
