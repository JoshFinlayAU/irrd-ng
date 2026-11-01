//! graphql-core's `suggestion_list()`, `did_you_mean()` and
//! `natural_comparison_key()`.

use std::cmp::Ordering;

/// Python's `str.lower()` for the suggestion distance: Unicode lower case.
fn lower(s: &str) -> Vec<char> {
    s.chars().flat_map(char::to_lowercase).collect()
}

/// `LexicalDistance.measure()`
fn measure(input: &str, input_lower: &[char], option: &str, threshold: usize) -> Option<usize> {
    if input == option {
        return Some(0);
    }
    let option_lower = lower(option);
    if input_lower == option_lower.as_slice() {
        return Some(1);
    }
    let (mut a, mut b) = (option_lower.as_slice(), input_lower);
    if a.len() < b.len() {
        std::mem::swap(&mut a, &mut b);
    }
    let (a_len, b_len) = (a.len(), b.len());
    if a_len - b_len > threshold {
        return None;
    }
    let mut rows = vec![vec![0usize; b_len + 1]; 3];
    for (j, c) in rows[0].iter_mut().enumerate() {
        *c = j;
    }
    for i in 1..=a_len {
        let up = (i - 1) % 3;
        let cur = i % 3;
        rows[cur][0] = i;
        let mut smallest = i;
        for j in 1..=b_len {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut cell = (rows[up][j] + 1)
                .min(rows[cur][j - 1] + 1)
                .min(rows[up][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                cell = cell.min(rows[(i - 2) % 3][j - 2] + 1);
            }
            smallest = smallest.min(cell);
            rows[cur][j] = cell;
        }
        if smallest > threshold {
            return None;
        }
    }
    let d = rows[a_len % 3][b_len];
    (d <= threshold).then_some(d)
}

/// One part of `natural_comparison_key()`.
#[derive(Debug, PartialEq, Eq)]
enum Part {
    Text(String),
    Num(num_like::Num, String),
}

mod num_like {
    /// A non-negative integer of any size, compared numerically.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Num(pub(super) String);

    impl PartialOrd for Num {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Num {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            let a = self.0.trim_start_matches('0');
            let b = other.0.trim_start_matches('0');
            a.len().cmp(&b.len()).then_with(|| a.cmp(b))
        }
    }
}

/// `natural_comparison_key()`: text and digit runs alternate, starting
/// with text; digit runs compare as `(int, str)`.
fn natural_key(s: &str) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut digits = false;
    for c in s.chars() {
        // Python's \d matches any Unicode decimal digit; names are ASCII.
        let d = c.is_ascii_digit();
        if d != digits {
            parts.push(if digits {
                Part::Num(num_like::Num(cur.clone()), std::mem::take(&mut cur))
            } else {
                Part::Text(std::mem::take(&mut cur))
            });
            digits = d;
        }
        cur.push(c);
    }
    parts.push(if digits {
        Part::Num(num_like::Num(cur.clone()), cur)
    } else {
        Part::Text(cur)
    });
    parts
}

fn cmp_parts(a: &[Part], b: &[Part]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let o = match (x, y) {
            (Part::Text(p), Part::Text(q)) => p.cmp(q),
            (Part::Num(n, s), Part::Num(m, t)) => n.cmp(m).then_with(|| s.cmp(t)),
            // Same positions always hold the same kind.
            _ => Ordering::Equal,
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

/// Compare two names naturally.
pub(crate) fn natural_cmp(a: &str, b: &str) -> Ordering {
    cmp_parts(&natural_key(a), &natural_key(b))
}

/// `suggestion_list()`
pub(crate) fn suggestion_list(input: &str, options: &[&str]) -> Vec<String> {
    let input_lower = lower(input);
    let threshold = (input.chars().count() as f64 * 0.4) as usize + 1;
    let mut found: Vec<(String, usize)> = Vec::new();
    for o in options {
        if let Some(d) = measure(input, &input_lower, o, threshold) {
            // A dict: a repeated option keeps its first position and its
            // last distance.
            match found.iter_mut().find(|(k, _)| k == o) {
                Some(e) => e.1 = d,
                None => found.push(((*o).to_owned(), d)),
            }
        }
    }
    found.sort_by(|(a, da), (b, db)| da.cmp(db).then_with(|| natural_cmp(a, b)));
    found.into_iter().map(|(o, _)| o).collect()
}

/// `or_list()`
fn or_list(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        2 => format!("{} or {}", items[0], items[1]),
        n => format!("{}, or {}", items[..n - 1].join(", "), items[n - 1]),
    }
}

/// `did_you_mean(suggestions, sub_message)`
pub(crate) fn did_you_mean_with(suggestions: &[String], sub: Option<&str>) -> String {
    if suggestions.is_empty() {
        return String::new();
    }
    let mut msg = " Did you mean ".to_owned();
    if let Some(s) = sub {
        msg.push_str(s);
        msg.push(' ');
    }
    let quoted: Vec<String> = suggestions
        .iter()
        .take(5)
        .map(|s| format!("'{s}'"))
        .collect();
    msg.push_str(&or_list(&quoted));
    msg.push('?');
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_like_graphql_core() {
        assert_eq!(
            suggestion_list(
                "rpslObject",
                &["rpslObjects", "databaseStatus", "asnPrefixes"]
            ),
            vec!["rpslObjects"]
        );
        assert_eq!(
            did_you_mean_with(&["a".into(), "b".into(), "c".into()], None),
            " Did you mean 'a', 'b', or 'c'?"
        );
        assert_eq!(natural_cmp("a10", "a9"), Ordering::Greater);
    }
}
