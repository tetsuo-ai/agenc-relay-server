//! Immutable companion objects and the single-fragment cursor given to a writer.

use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::{CompanionFrame, Correlation};
use agenc_relay_e2ee::limits::MAX_FRAGMENT_RAW;
use agenc_relay_e2ee::wire::fragment::{FragmentTag, fragment_count};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_federation_wire::FederationLineText;
use std::sync::Arc;

use crate::budget::MemoryPermit;

/// Conservative temporary backing for validating two candidate physical
/// lines in turn, before the exact per-writer window is known.
pub(crate) const PREFLIGHT_BYTES: usize =
    4096 + 8 * agenc_relay_client_wire::MAX_PHYSICAL_LINE_BYTES;

/// Correlation and direction remain fixed for all fragments of an object.
#[derive(Clone, Copy)]
pub(crate) enum Carrier {
    Request,
    Payload,
    Result,
    Response(u16),
}

pub(crate) struct Segments {
    bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
    id: ObjectId,
    total: u32,
    pub(crate) count: u32,
}

impl Segments {
    pub(crate) fn new<T: AsRef<[u8]> + Send + Sync + 'static>(
        bytes: T,
    ) -> Result<Self, E2eeReplyCode> {
        let data = bytes.as_ref();
        let id = ObjectId::compute(data);
        let total = u32::try_from(data.len()).map_err(|_| E2eeReplyCode::ObjectTooLarge)?;
        let count = fragment_count(total).map_err(|_| E2eeReplyCode::ObjectTooLarge)?;
        Ok(Self {
            bytes: Arc::new(bytes),
            id,
            total,
            count,
        })
    }

    pub(crate) fn fragment(&self, part: u32) -> Option<FragmentTag> {
        if part >= self.count {
            return None;
        }
        let bytes = self.bytes.as_ref().as_ref();
        let start = usize::try_from(part).ok()?.checked_mul(MAX_FRAGMENT_RAW)?;
        let end = start.checked_add(MAX_FRAGMENT_RAW)?.min(bytes.len());
        Some(FragmentTag {
            object_id: self.id,
            part,
            count: self.count,
            total: self.total,
            segment: bytes.get(start..end)?.to_vec(),
        })
    }
}

pub(crate) struct Object {
    segments: Segments,
    carrier: Carrier,
}

impl Object {
    pub(crate) fn new<T: AsRef<[u8]> + Send + Sync + 'static>(
        bytes: T,
        carrier: Carrier,
    ) -> Result<Self, E2eeReplyCode> {
        Ok(Self {
            segments: Segments::new(bytes)?,
            carrier,
        })
    }

    fn frame(&self, correlation: Correlation, part: u32) -> Option<CompanionFrame> {
        let fragment = self.segments.fragment(part)?;
        let object_id = *self.segments.id.as_bytes();
        Some(match self.carrier {
            Carrier::Request => CompanionFrame::Request {
                correlation,
                object_id,
                fragment,
            },
            Carrier::Payload => CompanionFrame::Payload {
                correlation,
                object_id,
                fragment,
            },
            Carrier::Result => CompanionFrame::Result {
                correlation,
                object_id,
                fragment,
            },
            Carrier::Response(response_index) => CompanionFrame::Response {
                correlation,
                response_index,
                object_id,
                fragment,
            },
        })
    }
}

/// A retry and a connection writer share the existing object allocations. Each
/// writer owns its own cursor. The opaque body may hold an ingress/spool permit.
pub(crate) struct Transfer {
    prefix: String,
    pub(crate) correlation: Correlation,
    objects: Vec<Object>,
    window: u64,
    _backing: Option<Arc<MemoryPermit>>,
}

impl Transfer {
    pub(crate) fn new(
        prefix: String,
        correlation: Correlation,
        objects: Vec<Object>,
        backing: Option<Arc<MemoryPermit>>,
    ) -> Result<Self, E2eeReplyCode> {
        // Earlier full segments have exactly this wire length or a shorter
        // decimal part index. The final, potentially short segment is separate.
        let mut window = 0;
        for object in &objects {
            for part in [
                object.segments.count.saturating_sub(2),
                object.segments.count - 1,
            ] {
                let line = Self::render(&prefix, correlation, object, part)?;
                window = window
                    .max(u64::try_from(line.len()).map_err(|_| E2eeReplyCode::ObjectTooLarge)?);
            }
        }
        if window == 0 {
            return Err(E2eeReplyCode::InvalidFragment);
        }
        Ok(Self {
            prefix,
            correlation,
            objects,
            window,
            _backing: backing,
        })
    }

    pub(crate) fn request<T: AsRef<[u8]> + Send + Sync + 'static>(
        prefix: String,
        correlation: Correlation,
        request: Vec<u8>,
        payload: Option<T>,
        backing: Option<Arc<MemoryPermit>>,
    ) -> Result<Arc<Self>, E2eeReplyCode> {
        let mut objects = vec![Object::new(request, Carrier::Request)?];
        if let Some(payload) = payload {
            objects.push(Object::new(payload, Carrier::Payload)?);
        }
        Self::new(prefix, correlation, objects, backing).map(Arc::new)
    }

    pub(crate) fn reserve_writer(
        &self,
        context: &crate::state_core::StateCoreContext,
    ) -> Result<MemoryPermit, E2eeReplyCode> {
        let bytes = self.render_backing();
        context
            .reserve_kept_output(bytes)
            .ok()
            .and_then(|mut held| held.split_exact(bytes))
            .ok_or(E2eeReplyCode::RateLimited)
    }

    fn render(
        prefix: &str,
        correlation: Correlation,
        object: &Object,
        part: u32,
    ) -> Result<FederationLineText, E2eeReplyCode> {
        let frame = object
            .frame(correlation, part)
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let text = frame
            .render(prefix)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        FederationLineText::from_rendered(text).map_err(|_| E2eeReplyCode::InvalidFragment)
    }

    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    /// Covers one segment, the base64/tag temporary, and rendered text
    /// through the completed socket write, including their allocation overheads.
    pub(crate) fn render_backing(&self) -> u64 {
        4096 + 8 * self.window
    }

    pub(crate) fn cursor(self: &Arc<Self>) -> Cursor {
        Cursor {
            transfer: Arc::clone(self),
            object: 0,
            part: 0,
        }
    }
}

pub(crate) struct Cursor {
    transfer: Arc<Transfer>,
    object: usize,
    part: u32,
}

impl Cursor {
    pub(crate) fn remaining(&self) -> bool {
        self.object < self.transfer.objects.len()
    }

    pub(crate) fn next_line(&mut self) -> Result<FederationLineText, E2eeReplyCode> {
        let object = self
            .transfer
            .objects
            .get(self.object)
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let line = Transfer::render(
            &self.transfer.prefix,
            self.transfer.correlation,
            object,
            self.part,
        )?;
        self.part += 1;
        if self.part == object.segments.count {
            self.object += 1;
            self.part = 0;
        }
        Ok(line)
    }
}

/// Owned authenticated result and responses before the live writer takes them.
pub struct Reply {
    prefix: String,
    correlation: Correlation,
    result: Vec<u8>,
    responses: Vec<Vec<u8>>,
    backing: Option<Arc<MemoryPermit>>,
}

impl Reply {
    pub(crate) fn new(
        prefix: &str,
        correlation: Correlation,
        home: [u8; 16],
        result: Vec<u8>,
        responses: Vec<Vec<u8>>,
        backing: Option<Arc<MemoryPermit>>,
    ) -> Self {
        Self {
            prefix: prefix.to_owned(),
            correlation: Correlation {
                peer_server_id: home,
                ..correlation
            },
            result,
            responses,
            backing,
        }
    }

    /// Copy a hot durable result only after all response objects exist and
    /// the destination's complete immutable backing has been charged.
    pub(crate) fn retained(
        prefix: &str,
        correlation: Correlation,
        home: [u8; 16],
        result: &[u8],
        responses: &[&[u8]],
        reserve: impl FnOnce(usize) -> Option<MemoryPermit>,
    ) -> Result<Self, E2eeReplyCode> {
        let capacity = responses
            .iter()
            .try_fold(result.len(), |n, bytes| n.checked_add(bytes.len()))
            .and_then(|n| n.checked_add(responses.len().checked_mul(192)?))
            .and_then(|n| n.checked_add(2048))
            .ok_or(E2eeReplyCode::RateLimited)?;
        let backing = reserve(capacity).ok_or(E2eeReplyCode::RateLimited)?;
        Ok(Self::new(
            prefix,
            correlation,
            home,
            result.to_vec(),
            responses.iter().map(|bytes| bytes.to_vec()).collect(),
            Some(Arc::new(backing)),
        ))
    }

    pub(crate) fn into_transfer(
        mut self,
        context: &crate::state_core::StateCoreContext,
    ) -> Result<Arc<Transfer>, E2eeReplyCode> {
        let _preflight = context
            .reserve_output_backing(PREFLIGHT_BYTES)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        if self.backing.is_none() {
            let capacity = self
                .responses
                .iter()
                .try_fold(self.result.capacity(), |size, bytes| {
                    size.checked_add(bytes.capacity())
                })
                .and_then(|size| size.checked_add(self.responses.capacity().checked_mul(192)?))
                .and_then(|size| size.checked_add(2048))
                .ok_or(E2eeReplyCode::RateLimited)?;
            self.backing = Some(Arc::new(
                context
                    .reserve_output_backing(capacity)
                    .map_err(|_| E2eeReplyCode::RateLimited)?,
            ));
        }
        self.into_backed()
    }

    pub(crate) fn into_backed(self) -> Result<Arc<Transfer>, E2eeReplyCode> {
        let backing = self.backing.ok_or(E2eeReplyCode::RateLimited)?;
        let mut objects = Vec::with_capacity(self.responses.len() + 1);
        objects.push(Object::new(self.result, Carrier::Result)?);
        for (index, bytes) in self.responses.into_iter().enumerate() {
            let index = u16::try_from(index).map_err(|_| E2eeReplyCode::ObjectTooLarge)?;
            objects.push(Object::new(bytes, Carrier::Response(index))?);
        }
        Transfer::new(self.prefix, self.correlation, objects, Some(backing)).map(Arc::new)
    }
}
