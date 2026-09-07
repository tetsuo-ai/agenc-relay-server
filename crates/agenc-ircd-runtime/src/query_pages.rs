//! Common limits for immutable directory and local JOIN response pages.

use crate::RuntimeError;

pub(crate) const MAX_PAGE_REPLIES: usize = 512;
pub(crate) const MAX_NAMES_USERS: usize = 512;
pub(crate) const MAX_PAGE_BYTES: usize = 65_536;
const PAGE_HEADER_ALLOWANCE: usize = 512;

#[derive(Clone, Copy)]
pub(crate) struct ReplySize {
    pub(crate) encoded: usize,
    pub(crate) rendered: usize,
    pub(crate) names_users: usize,
}

/// Keeps all terminal NAMES replies together on the final bounded page.
pub(crate) fn page_count(
    sizes: &[ReplySize],
    terminal_count: usize,
) -> Result<usize, RuntimeError> {
    let terminal_start = sizes
        .len()
        .checked_sub(terminal_count)
        .ok_or(RuntimeError::InvalidValue)?;
    let mut encoded = PAGE_HEADER_ALLOWANCE;
    let mut rendered = 0_usize;
    let mut users = 0_usize;
    let mut count = 0_usize;
    for size in sizes.iter().take(MAX_PAGE_REPLIES) {
        encoded = encoded
            .checked_add(size.encoded)
            .ok_or(RuntimeError::Overflow)?;
        rendered = rendered
            .checked_add(size.rendered)
            .ok_or(RuntimeError::Overflow)?;
        users = users
            .checked_add(size.names_users)
            .ok_or(RuntimeError::Overflow)?;
        if encoded > MAX_PAGE_BYTES || rendered > MAX_PAGE_BYTES || users > MAX_NAMES_USERS {
            break;
        }
        count += 1;
    }
    if count < sizes.len() && count > terminal_start {
        count = terminal_start;
    }
    if count == 0 && !sizes.is_empty() {
        return Err(RuntimeError::LimitExceeded);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_pages_count_users_and_keep_the_complete_terminal_group() -> Result<(), RuntimeError> {
        let mut sizes = vec![
            ReplySize {
                encoded: 10,
                rendered: 10,
                names_users: 1
            };
            513
        ];
        sizes.extend(
            [ReplySize {
                encoded: 10,
                rendered: 10,
                names_users: 0,
            }; 20],
        );
        assert_eq!(page_count(&sizes, 20)?, 512);
        let remaining = sizes.get(512..).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(page_count(remaining, 20)?, 21);
        let mut split = vec![
            ReplySize {
                encoded: 10,
                rendered: 10,
                names_users: 0
            };
            510
        ];
        split.extend(
            [ReplySize {
                encoded: 10,
                rendered: 10,
                names_users: 0,
            }; 20],
        );
        assert_eq!(page_count(&split, 20)?, 510);
        let remaining = split.get(510..).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(page_count(remaining, 20)?, 20);
        Ok(())
    }

    #[test]
    fn an_unpageable_reply_or_terminal_group_fails_closed() {
        let oversized = [ReplySize {
            encoded: 1,
            rendered: MAX_PAGE_BYTES + 1,
            names_users: 0,
        }];
        assert_eq!(page_count(&oversized, 0), Err(RuntimeError::LimitExceeded));
        let users = [ReplySize {
            encoded: 1,
            rendered: 1,
            names_users: MAX_NAMES_USERS + 1,
        }];
        assert_eq!(page_count(&users, 0), Err(RuntimeError::LimitExceeded));
        let terminals = vec![
            ReplySize {
                encoded: 10,
                rendered: 10,
                names_users: 0
            };
            513
        ];
        assert_eq!(
            page_count(&terminals, 513),
            Err(RuntimeError::LimitExceeded)
        );
    }
}
