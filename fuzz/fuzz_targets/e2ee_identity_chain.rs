#![no_main]
#![forbid(unsafe_code)]

use agenc_relay_e2ee::identity::verify_root_chain;
use agenc_relay_e2ee::objects::identity::ArcAccountRootChain;
use agenc_relay_e2ee::{DecodeBudget, TlsDecode as _};
use libfuzzer_sys::fuzz_target;

const BUDGET_BYTES: usize = 1_048_576;
const BUDGET_VALUES: usize = 1_000_000;
const NETWORK: [u8; 32] = [7; 32];

// A root chain either fails to decode, fails to verify, or verifies into
// exactly one head per root with strictly increasing generations. Verifying
// the accepted chain again from its first head must agree.
fuzz_target!(|data: &[u8]| {
    let mut budget = DecodeBudget::new(BUDGET_BYTES, BUDGET_VALUES);
    let Ok(chain) = ArcAccountRootChain::decode_exact(data, &mut budget) else {
        return;
    };
    let roots = chain.roots.as_slice();
    let Ok(verified) = verify_root_chain(&NETWORK, roots, None) else {
        return;
    };
    assert_eq!(verified.len(), roots.len(), "one head per root");
    let mut previous: Option<u64> = None;
    for head in &verified {
        if let Some(generation) = previous {
            assert_eq!(
                generation.checked_add(1),
                Some(head.generation),
                "generations advance by one"
            );
        }
        previous = Some(head.generation);
    }
    if let (Some(first), Some(rest)) = (verified.first(), roots.get(1..)) {
        let again = verify_root_chain(&NETWORK, rest, Some(first))
            .expect("a verified continuation verifies again from its head");
        assert_eq!(again.len(), rest.len());
    }
});
