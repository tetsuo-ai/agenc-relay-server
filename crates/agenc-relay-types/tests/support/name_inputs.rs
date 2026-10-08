//! Deterministic display-name inputs shared by the preparation tests.
#![forbid(unsafe_code)]

use precis_profiles::Nickname;
use precis_profiles::precis_core::profile::Rules as _;

/// Every `Zs` space separator (Unicode general category Zs).
pub(crate) const SPACE_SEPARATORS: [char; 17] = [
    '\u{0020}', '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
    '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{202f}', '\u{205f}',
    '\u{3000}',
];

/// Context characters from several scripts and planes, marks, spaces and
/// refused classes.
pub(crate) const CONTEXT: [char; 20] = [
    'a',
    'Z',
    '7',
    '\u{00e9}',
    '\u{0101}',
    '\u{0301}',
    '\u{0308}',
    '\u{4e2d}',
    '\u{20ac}',
    '\u{3042}',
    '\u{1f600}',
    '\u{10348}',
    ' ',
    '\u{00a0}',
    '\u{2003}',
    '\u{3000}',
    '\u{1100}',
    '\u{1161}',
    '\u{00ad}',
    '\u{0007}',
];

/// Returns the pinned profile's NFKC form of `text`.
pub(crate) fn nfkc(text: &str) -> String {
    Nickname::new()
        .normalization_rule(text)
        .map_or_else(|_| text.to_owned(), |normalized| normalized.into_owned())
}

/// Every Unicode scalar value.
pub(crate) fn scalar_values() -> impl Iterator<Item = char> {
    (0_u32..=0x0010_ffff).filter_map(char::from_u32)
}

/// Every scalar value whose NFKC form differs from it and contains a space.
pub(crate) fn space_producing() -> Vec<char> {
    scalar_values()
        .filter(|character| !SPACE_SEPARATORS.contains(character))
        .filter(|character| {
            let text = character.to_string();
            let normalized = nfkc(&text);
            normalized != text && normalized.contains(' ')
        })
        .collect()
}

/// Every scalar value whose NFKC form begins with a space followed by a mark.
pub(crate) fn space_and_marks(producing: &[char]) -> Vec<char> {
    producing
        .iter()
        .copied()
        .filter(|character| {
            let normalized = nfkc(&character.to_string());
            let mut rest = normalized.chars();
            rest.next() == Some(' ') && rest.next().is_some()
        })
        .collect()
}

/// A deterministic xorshift generator for the random input family.
pub(crate) struct Xorshift(u64);

impl Xorshift {
    pub(crate) const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    pub(crate) fn below(&mut self, bound: usize) -> usize {
        let Ok(bound) = u64::try_from(bound) else {
            return 0;
        };
        self.next()
            .checked_rem(bound)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0)
    }
}

/// Visits every generated input: each scalar value alone and after context
/// text, each space-producing character in short contexts, every string of up
/// to four characters over a small alphabet, and seeded random strings.
pub(crate) fn for_each_input(random_count: usize, mut visit: impl FnMut(&str)) {
    let producing = space_producing();
    let mut text = String::new();
    for character in scalar_values() {
        for prefix in ["", "a", "\u{00e9}"] {
            text.clear();
            text.push_str(prefix);
            text.push(character);
            visit(&text);
        }
    }
    for &produced in &producing {
        for &first in &CONTEXT {
            for &second in &CONTEXT {
                for pattern in [
                    [Some(first), Some(produced), None, None, None],
                    [Some(first), Some(' '), Some(produced), None, None],
                    [Some(first), Some(first), Some(' '), Some(produced), None],
                    [Some(first), Some(' '), Some(produced), Some(second), None],
                    [Some(first), Some(produced), Some(' '), Some(second), None],
                    [
                        Some(first),
                        Some(' '),
                        Some(produced),
                        Some(' '),
                        Some(second),
                    ],
                    [
                        Some(produced),
                        Some(first),
                        Some(produced),
                        Some(second),
                        None,
                    ],
                    [
                        Some(first),
                        Some(produced),
                        Some(produced),
                        Some(second),
                        None,
                    ],
                ] {
                    text.clear();
                    text.extend(pattern.into_iter().flatten());
                    visit(&text);
                }
            }
        }
    }
    let marks = space_and_marks(&producing);
    let mut alphabet: Vec<char> = [
        'a',
        '\u{00e9}',
        '\u{4e2d}',
        '\u{1f600}',
        '\u{0301}',
        ' ',
        '\u{3000}',
        '\u{00a0}',
    ]
    .into_iter()
    .collect();
    alphabet.extend(marks.iter().copied().take(4));
    alphabet.extend(
        producing
            .iter()
            .copied()
            .filter(|character| !marks.contains(character))
            .take(4),
    );
    let mut indices = Vec::new();
    for length in 1..=4_u32 {
        let total = alphabet.len().pow(length);
        for mut index in 0..total {
            indices.clear();
            for _ in 0..length {
                indices.push(index % alphabet.len());
                index /= alphabet.len();
            }
            text.clear();
            text.extend(
                indices
                    .iter()
                    .filter_map(|&position| alphabet.get(position)),
            );
            visit(&text);
        }
    }
    let mut random = Xorshift::new(0x5eed_0000_0000_0d15);
    for _ in 0..random_count {
        text.clear();
        let length = 1 + random.below(16);
        for _ in 0..length {
            let character = match random.below(4) {
                0 => producing.get(random.below(producing.len())).copied(),
                1 => CONTEXT.get(random.below(CONTEXT.len())).copied(),
                2 => SPACE_SEPARATORS
                    .get(random.below(SPACE_SEPARATORS.len()))
                    .copied(),
                _ => char::from_u32(u32::try_from(random.next() % 0x0011_0000).unwrap_or(0)),
            };
            text.extend(character);
        }
        visit(&text);
    }
}
