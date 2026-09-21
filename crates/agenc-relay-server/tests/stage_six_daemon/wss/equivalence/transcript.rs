//! Ordered comparison retains commands, numeric codes, text, and identity links.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use super::*;

#[derive(Default)]
pub(super) struct Transcript(Vec<(String, Vec<String>)>);

impl Transcript {
    pub(super) fn record(&mut self, step: &str, lines: Vec<String>) {
        self.0.push((step.into(), lines));
    }

    pub(super) fn command(
        &mut self,
        client: &mut ArcClient,
        command: &str,
        ending: &str,
    ) -> TestResult<Vec<String>> {
        let lines = client
            .send_until(command, ending)
            .map_err(|error| failure(format!("{command}: {error}")))?;
        self.record(command, lines.clone());
        Ok(lines)
    }

    pub(super) fn normalized(self, account: AccountId) -> TestResult<Vec<(String, Vec<String>)>> {
        let mut normalizer = Normalizer::default();
        self.0
            .into_iter()
            .map(|(step, lines)| {
                let lines = lines
                    .into_iter()
                    .map(|line| normalizer.line(&line, account))
                    .collect::<TestResult<Vec<_>>>()?;
                Ok((step, lines))
            })
            .collect()
    }
}

#[derive(Default)]
struct Normalizer {
    messages: BTreeMap<String, String>,
    cloaks: BTreeMap<String, String>,
}

impl Normalizer {
    fn line(&mut self, line: &str, account: AccountId) -> TestResult<String> {
        let mut line = line.replace(&account.to_text(), "<account>");
        self.learn_cloaks(&line)?;
        for (cloak, canonical) in &self.cloaks {
            line = line.replace(cloak, canonical);
        }
        if let Some(tagged) = line.strip_prefix('@') {
            let (tags, body) = tagged
                .split_once(' ')
                .ok_or_else(|| failure("tagged line has no body"))?;
            let tags = tags
                .split(';')
                .map(|tag| self.tag(tag))
                .collect::<TestResult<Vec<_>>>()?;
            line = format!("@{} {body}", tags.join(";"));
        }
        normalize_numeric_time(&normalize_membership_order(&line)?)
    }

    fn tag(&mut self, tag: &str) -> TestResult<String> {
        let Some((key, value)) = tag.split_once('=') else {
            return Ok(tag.into());
        };
        match key {
            "msgid" => {
                let _validated = agenc_relay_types::MessageId::parse(value)?;
                let next = format!("<message-{}>", self.messages.len());
                Ok(format!(
                    "msgid={}",
                    self.messages.entry(value.into()).or_insert(next)
                ))
            }
            "time" => {
                assert!(
                    value.ends_with('Z') && value.contains('T') && value.len() >= 20,
                    "{value}"
                );
                Ok("time=<utc>".into())
            }
            _ => Ok(tag.into()),
        }
    }

    fn learn_cloaks(&mut self, line: &str) -> TestResult {
        for token in line.split_ascii_whitespace() {
            let Some((_, address)) = token.split_once('!') else {
                continue;
            };
            let Some((user, host)) = address.split_once('@') else {
                continue;
            };
            let _validated = agenc_relay_types::PublicCloak::parse(user, host)?;
            let next = format!("<cloak-{}>", self.cloaks.len());
            self.cloaks.entry(address.into()).or_insert(next);
        }
        // WHOIS 311 carries the same cloak in separate user and host fields.
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.get(1) == Some(&"311") {
            let user = fields.get(4).ok_or_else(|| failure("WHOIS user missing"))?;
            let host = fields.get(5).ok_or_else(|| failure("WHOIS host missing"))?;
            let _validated = agenc_relay_types::PublicCloak::parse(user, host)?;
            let next = format!("<cloak-{}>", self.cloaks.len());
            self.cloaks.entry(format!("{user} {host}")).or_insert(next);
        }
        Ok(())
    }
}

fn normalize_numeric_time(line: &str) -> TestResult<String> {
    let mut fields: Vec<_> = line.split(' ').map(str::to_owned).collect();
    let command = usize::from(line.starts_with('@')) + 1;
    let code = fields.get(command).map(String::as_str);
    let indices: &[usize] = match code {
        Some("329") => &[4],
        Some("333") => &[5],
        Some("317") => &[4, 5],
        _ => return Ok(line.into()),
    };
    for index in indices {
        let index = index + usize::from(line.starts_with('@'));
        let field = fields
            .get_mut(index)
            .ok_or_else(|| failure("numeric time field missing"))?;
        let _second: u64 = field.parse()?;
        *field = "<second>".into();
    }
    Ok(fields.join(" "))
}

fn normalize_membership_order(line: &str) -> TestResult<String> {
    let command = usize::from(line.starts_with('@')) + 1;
    if !matches!(line.split(' ').nth(command), Some("353" | "319")) {
        return Ok(line.into());
    }
    let (head, members) = line
        .split_once(" :")
        .ok_or_else(|| failure("membership numeric has no trailing list"))?;
    // These lists traverse fresh UserId/ChannelInstanceId order. Sections
    // 14.3/14.5 impose membership and visibility, not nickname/name order.
    // Sort only complete tokens: retain role prefixes, duplicates, and headers.
    let mut members: Vec<_> = members.split(' ').collect();
    members.sort_unstable();
    Ok(format!("{head} :{}", members.join(" ")))
}

#[test]
fn membership_normalization_retains_roles_duplicates_and_nonmembership_bytes() -> TestResult {
    let first = ":node 353 Viewer = #room :~Member Visitor";
    let reversed = ":node 353 Viewer = #room :Visitor ~Member";
    assert_eq!(
        normalize_membership_order(first)?,
        normalize_membership_order(reversed)?
    );
    for changed in [
        ":node 353 Viewer = #room :Member Visitor",
        ":node 353 Viewer = #room :~Member",
        ":node 353 Viewer = #room :~Member Visitor Visitor",
        ":node 353 Viewer @ #room :~Member Visitor",
    ] {
        assert_ne!(
            normalize_membership_order(first)?,
            normalize_membership_order(changed)?
        );
    }
    let message = ":Member PRIVMSG #room :Visitor ~Member";
    assert_eq!(normalize_membership_order(message)?, message);
    Ok(())
}
