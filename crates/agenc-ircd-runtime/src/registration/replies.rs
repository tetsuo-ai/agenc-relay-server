//! One bounded logical reply across coordinator directory pages.

use crate::RuntimeError;
use agenc_ircd_client_wire::{BatchStack, CapabilityState, ParsedMessage, WireMessage};

#[derive(Default)]
pub(crate) struct ReplyPages {
    active: Option<ActiveReply>,
    counter: u64,
}

struct ActiveReply {
    batch: Option<ReplyBatch>,
    next_sequence: u32,
}

struct ReplyBatch {
    batches: BatchStack,
    id: String,
    label: String,
}

impl ReplyPages {
    pub(crate) fn render(
        &mut self,
        capabilities: &CapabilityState,
        prefix: &str,
        request: &ParsedMessage,
        frames: Vec<WireMessage>,
        page: (u32, bool),
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        let (sequence, has_next) = page;
        if sequence != 0 {
            return self.continue_page(prefix, request, frames, sequence, has_next);
        }
        if self.active.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        if !has_next {
            return crate::client_render::logical_frames(prefix, capabilities, request, frames);
        }
        self.start_continuation(capabilities, prefix, request, frames)
    }

    pub(crate) fn start_continuation(
        &mut self,
        capabilities: &CapabilityState,
        prefix: &str,
        request: &ParsedMessage,
        frames: Vec<WireMessage>,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        if self.active.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        let Some(label) =
            request_label(request).filter(|_| capabilities.enabled("labeled-response"))
        else {
            self.active = Some(ActiveReply {
                batch: None,
                next_sequence: 1,
            });
            return Ok(frames);
        };
        self.start_page(capabilities, prefix, label, frames)
    }

    fn start_page(
        &mut self,
        capabilities: &CapabilityState,
        prefix: &str,
        label: &str,
        mut frames: Vec<WireMessage>,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        self.counter = self.counter.checked_add(1).ok_or(RuntimeError::Overflow)?;
        let id = format!("fq{}", self.counter);
        let mut batches = BatchStack::default();
        let opening = batches
            .open(capabilities, prefix, &id, label)
            .map_err(invalid)?;
        for frame in &mut frames {
            batches.attach(&id, frame).map_err(invalid)?;
        }
        frames
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        frames.insert(0, opening);
        self.active = Some(ActiveReply {
            batch: Some(ReplyBatch {
                batches,
                id,
                label: label.to_owned(),
            }),
            next_sequence: 1,
        });
        Ok(frames)
    }

    fn continue_page(
        &mut self,
        prefix: &str,
        request: &ParsedMessage,
        mut frames: Vec<WireMessage>,
        sequence: u32,
        has_next: bool,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        let Some(mut active) = self.active.take() else {
            return Err(RuntimeError::InvalidValue);
        };
        if active.next_sequence != sequence {
            return Err(RuntimeError::InvalidValue);
        }
        if let Some(batch) = active.batch.as_mut() {
            batch.attach(request, &mut frames)?;
        }
        if has_next {
            active.next_sequence = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
            self.active = Some(active);
        } else if let Some(mut batch) = active.batch {
            frames
                .try_reserve_exact(1)
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            frames.push(batch.batches.close(prefix, &batch.id).map_err(invalid)?);
        }
        Ok(frames)
    }

    pub(super) fn failure(
        &mut self,
        capabilities: &CapabilityState,
        prefix: &str,
        request: &ParsedMessage,
        mut frame: WireMessage,
        completes_query: bool,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        if !completes_query || self.active.is_none() {
            return crate::client_render::logical_frames(
                prefix,
                capabilities,
                request,
                vec![frame],
            );
        }
        let active = self.active.take().ok_or(RuntimeError::InvalidValue)?;
        let Some(mut batch) = active.batch else {
            return Ok(vec![frame]);
        };
        if request_label(request) != Some(batch.label.as_str()) {
            return Err(RuntimeError::InvalidValue);
        }
        batch
            .batches
            .attach(&batch.id, &mut frame)
            .map_err(invalid)?;
        Ok(vec![
            frame,
            batch.batches.close(prefix, &batch.id).map_err(invalid)?,
        ])
    }
}

impl ReplyBatch {
    fn attach(
        &mut self,
        request: &ParsedMessage,
        frames: &mut [WireMessage],
    ) -> Result<(), RuntimeError> {
        if request_label(request) != Some(self.label.as_str()) {
            return Err(RuntimeError::InvalidValue);
        }
        for frame in frames {
            self.batches.attach(&self.id, frame).map_err(invalid)?;
        }
        Ok(())
    }
}

pub(super) fn private_account_frames(
    capabilities: &CapabilityState,
    prefix: &str,
    nickname: &str,
    request: &ParsedMessage,
    frames: Vec<WireMessage>,
) -> Result<Vec<WireMessage>, RuntimeError> {
    if request.command() != "ACCT" || capabilities.enabled("standard-replies") {
        return Ok(frames);
    }
    let mut filtered = Vec::new();
    for frame in frames {
        match frame.command() {
            "NOTE" => {}
            "FAIL" => filtered.push(crate::client_render::failure_frame(
                capabilities,
                prefix,
                nickname,
                request,
                agenc_ircd_domain::DomainError::BadState,
                None,
            )?),
            _ => filtered.push(frame),
        }
    }
    Ok(filtered)
}

fn request_label(request: &ParsedMessage) -> Option<&str> {
    request
        .tags()
        .iter()
        .find(|tag| tag.key() == "label")
        .and_then(|tag| tag.value())
}

fn invalid(_: agenc_ircd_client_wire::RenderError) -> RuntimeError {
    RuntimeError::InvalidValue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::negotiated_capabilities;
    use agenc_ircd_client_wire::{
        FramedLine, OutputBudget, RenderError, numeric_reply, parse_message,
    };

    struct Budget;
    impl OutputBudget for Budget {
        type Permit = ();
        fn try_reserve_exact(&mut self, _bytes: usize) -> Result<(), RenderError> {
            Ok(())
        }
    }

    fn lines(frames: Vec<WireMessage>) -> Result<Vec<String>, Box<dyn core::error::Error>> {
        frames
            .into_iter()
            .map(|frame| {
                Ok(String::from_utf8(
                    frame.measure()?.encode(&mut Budget)?.as_bytes().to_vec(),
                )?)
            })
            .collect()
    }

    #[test]
    fn directory_pages_keep_one_label_and_one_batch_until_the_last_page()
    -> Result<(), Box<dyn core::error::Error>> {
        let capabilities = negotiated_capabilities(&["message-tags", "batch", "labeled-response"])?;
        let request = parse_message(FramedLine::new("@label=directory WHO #room")?)?
            .ok_or("empty request")?;
        let mut replies = ReplyPages::default();
        let first = replies.render(
            &capabilities,
            "edge.test",
            &request,
            vec![numeric_reply(
                "edge.test",
                353,
                "sam",
                &["=", "#room"],
                Some("sam"),
            )?],
            (0, true),
        )?;
        assert_eq!(
            lines(first)?,
            vec![
                "@label=directory :edge.test BATCH +fq1 labeled-response\r\n",
                "@batch=fq1 :edge.test 353 sam = #room :sam\r\n",
            ]
        );
        let last = replies.render(
            &capabilities,
            "edge.test",
            &request,
            vec![numeric_reply(
                "edge.test",
                315,
                "sam",
                &["#room"],
                Some("End of WHO list"),
            )?],
            (1, false),
        )?;
        assert_eq!(
            lines(last)?,
            vec![
                "@batch=fq1 :edge.test 315 sam #room :End of WHO list\r\n",
                ":edge.test BATCH -fq1\r\n",
            ]
        );
        Ok(())
    }

    #[test]
    fn a_no_content_directory_result_acknowledges_its_label()
    -> Result<(), Box<dyn core::error::Error>> {
        let capabilities = negotiated_capabilities(&["message-tags", "batch", "labeled-response"])?;
        let request =
            parse_message(FramedLine::new("@label=empty MONITOR S")?)?.ok_or("empty request")?;
        assert_eq!(
            lines(ReplyPages::default().render(
                &capabilities,
                "edge.test",
                &request,
                Vec::new(),
                (0, false)
            )?)?,
            vec!["@label=empty :edge.test ACK\r\n"]
        );
        Ok(())
    }

    fn open_directory_page() -> Result<(ReplyPages, ParsedMessage), Box<dyn core::error::Error>> {
        let capabilities = negotiated_capabilities(&["message-tags", "batch", "labeled-response"])?;
        let request = parse_message(FramedLine::new("@label=directory WHO #room")?)?
            .ok_or("empty request")?;
        let mut replies = ReplyPages::default();
        replies.render(&capabilities, "edge.test", &request, Vec::new(), (0, true))?;
        Ok((replies, request))
    }

    #[test]
    fn a_failed_continuation_closes_its_existing_batch() -> Result<(), Box<dyn core::error::Error>>
    {
        let (mut replies, request) = open_directory_page()?;
        let frames = replies.failure(
            &CapabilityState::default(),
            "edge.test",
            &request,
            numeric_reply("edge.test", 481, "sam", &[], Some("Permission denied"))?,
            true,
        )?;
        assert_eq!(
            lines(frames)?,
            vec![
                "@batch=fq1 :edge.test 481 sam :Permission denied\r\n",
                ":edge.test BATCH -fq1\r\n",
            ]
        );
        assert!(replies.active.is_none());
        Ok(())
    }

    #[test]
    fn a_capability_change_does_not_strand_an_open_reply_batch()
    -> Result<(), Box<dyn core::error::Error>> {
        let (mut replies, request) = open_directory_page()?;
        let frames = replies.render(
            &CapabilityState::default(),
            "edge.test",
            &request,
            vec![numeric_reply(
                "edge.test",
                315,
                "sam",
                &["#room"],
                Some("End of WHO list"),
            )?],
            (1, false),
        )?;
        assert_eq!(
            lines(frames)?,
            vec![
                "@batch=fq1 :edge.test 315 sam #room :End of WHO list\r\n",
                ":edge.test BATCH -fq1\r\n",
            ]
        );
        assert!(replies.active.is_none());
        Ok(())
    }

    #[test]
    fn another_label_or_page_sequence_cannot_join_an_open_reply_batch()
    -> Result<(), Box<dyn core::error::Error>> {
        for (request, sequence) in [
            ("@label=other WHO #room", 1),
            ("@label=directory WHO #room", 2),
        ] {
            let (mut replies, _) = open_directory_page()?;
            let request = parse_message(FramedLine::new(request)?)?.ok_or("empty request")?;
            assert_eq!(
                replies.render(
                    &CapabilityState::default(),
                    "edge.test",
                    &request,
                    Vec::new(),
                    (sequence, false),
                ),
                Err(RuntimeError::InvalidValue)
            );
        }
        Ok(())
    }

    #[test]
    fn unlabeled_directory_pages_reject_an_out_of_order_sequence()
    -> Result<(), Box<dyn core::error::Error>> {
        let request = parse_message(FramedLine::new("WHO #room")?)?.ok_or("empty request")?;
        let mut replies = ReplyPages::default();
        replies.render(
            &CapabilityState::default(),
            "edge.test",
            &request,
            Vec::new(),
            (0, true),
        )?;
        assert_eq!(
            replies.render(
                &CapabilityState::default(),
                "edge.test",
                &request,
                Vec::new(),
                (2, false)
            ),
            Err(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn account_notes_and_failures_follow_the_current_standard_reply_capability()
    -> Result<(), Box<dyn core::error::Error>> {
        let request = parse_message(FramedLine::new("ACCT DELETE")?)?.ok_or("empty request")?;
        let fallback = private_account_frames(
            &CapabilityState::default(),
            "edge.test",
            "sam",
            &request,
            account_frames()?,
        )?;
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback.first().ok_or("missing fallback")?.command(), "481");
        let capabilities = negotiated_capabilities(&["standard-replies"])?;
        assert_eq!(
            private_account_frames(
                &capabilities,
                "edge.test",
                "sam",
                &request,
                account_frames()?,
            )?,
            account_frames()?
        );
        Ok(())
    }

    fn account_frames() -> Result<Vec<WireMessage>, RenderError> {
        Ok(vec![
            WireMessage::new(
                "edge.test",
                "NOTE",
                &["ACCT", "UPDATED"],
                Some("Account setting updated"),
            )?,
            WireMessage::new(
                "edge.test",
                "FAIL",
                &["ACCT", "BAD_STATE"],
                Some("Command is not valid in this state"),
            )?,
        ])
    }
}
