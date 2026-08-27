#![forbid(unsafe_code)]

//! Exact nested-batch boundary frames.

use std::error::Error;

use agenc_ircd_client_wire::{
    BatchStack, CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState, OutputBudget,
    RenderError,
};

struct TestBudget;

impl OutputBudget for TestBudget {
    type Permit = ();

    fn try_reserve_exact(&mut self, _bytes: usize) -> Result<Self::Permit, RenderError> {
        Ok(())
    }
}

#[test]
fn nested_batch_boundaries_reference_the_same_live_parent() -> Result<(), Box<dyn Error>> {
    let profile = CapabilityProfile::new(vec![
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("labeled-response", None)?,
    ])?;
    let mut capabilities = CapabilityState::default();
    capabilities.ls(Some("302"), &profile)?;
    assert!(matches!(
        capabilities.request("batch labeled-response", &profile)?,
        CapRequestReply::Ack(_)
    ));

    let mut batches = BatchStack::default();
    let outer_open = batches.open(&capabilities, "server.example", "outer", "outer-label")?;
    let inner_open = batches.open(&capabilities, "server.example", "inner", "inner-label")?;
    let inner_close = batches.close("server.example", "inner")?;
    let outer_close = batches.close("server.example", "outer")?;

    let mut budget = TestBudget;
    let rendered = outer_open.measure()?.encode(&mut budget)?;
    assert_eq!(
        rendered.as_bytes(),
        b"@label=outer-label :server.example BATCH +outer labeled-response\r\n"
    );
    let rendered = inner_open.measure()?.encode(&mut budget)?;
    assert_eq!(
        rendered.as_bytes(),
        b"@batch=outer;label=inner-label :server.example BATCH +inner labeled-response\r\n"
    );
    let rendered = inner_close.measure()?.encode(&mut budget)?;
    assert_eq!(
        rendered.as_bytes(),
        b"@batch=outer :server.example BATCH -inner\r\n"
    );
    let rendered = outer_close.measure()?.encode(&mut budget)?;
    assert_eq!(rendered.as_bytes(), b":server.example BATCH -outer\r\n");
    Ok(())
}
