//! Hierarchical rate buckets, prefix keys, and memory-overload classification (spec 19.1 and 19.3).

pub mod buckets;
pub mod overload;
pub mod prefix;
mod transport;

pub use buckets::{
    AdmissionRefused, BucketDemand, BucketKey, BucketKind, BucketRate, BucketTable, LoginHashKey,
    RateLimits, TokenBucket, domain_bucket,
};
pub use overload::{
    EvictionCandidate, OverloadClass, OverloadState, admit_backup, admit_write, required_reserve,
    select_evictions, usage_reaches,
};
pub use prefix::PrefixRegistry;
pub use transport::TransportAdmission;
