//! `difflib.unified_diff(a, b, lineterm="")` from CPython 3.13, for the
//! notification mails that show what a modification changed.
//!
//! The diff has to match Python's line for line, so this is a direct port
//! of `SequenceMatcher` (with its "autojunk" heuristic for sequences of 200
//! lines or more) and of `get_grouped_opcodes`.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Match {
    a: usize,
    b: usize,
    size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Equal,
    Replace,
    Delete,
    Insert,
}

type Opcode = (Tag, usize, usize, usize, usize);

struct SequenceMatcher<'s> {
    a: &'s [&'s str],
    b: &'s [&'s str],
    b2j: HashMap<&'s str, Vec<usize>>,
}

impl<'s> SequenceMatcher<'s> {
    fn new(a: &'s [&'s str], b: &'s [&'s str]) -> Self {
        let mut b2j: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, elt) in b.iter().enumerate() {
            b2j.entry(*elt).or_default().push(i);
        }
        // autojunk: purge popular elements (no isjunk function is given, so
        // bjunk stays empty).
        let n = b.len();
        if n >= 200 {
            let ntest = n / 100 + 1;
            let popular: HashSet<&str> = b2j
                .iter()
                .filter(|(_, idxs)| idxs.len() > ntest)
                .map(|(k, _)| *k)
                .collect();
            for elt in popular {
                b2j.remove(elt);
            }
        }
        SequenceMatcher { a, b, b2j }
    }

    fn find_longest_match(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> Match {
        let (a, b) = (self.a, self.b);
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, ai) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(js) = self.b2j.get(ai) {
                for &j in js {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let prev = if j == 0 {
                        0
                    } else {
                        j2len.get(&(j - 1)).copied().unwrap_or(0)
                    };
                    let k = prev + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }
        // bjunk is empty, so only the "not junk" extension loops matter.
        while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && a[besti + bestsize] == b[bestj + bestsize]
        {
            bestsize += 1;
        }
        Match {
            a: besti,
            b: bestj,
            size: bestsize,
        }
    }

    fn matching_blocks(&self) -> Vec<Match> {
        let (la, lb) = (self.a.len(), self.b.len());
        let mut queue = vec![(0, la, 0, lb)];
        let mut blocks: Vec<Match> = Vec::new();
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let x = self.find_longest_match(alo, ahi, blo, bhi);
            let (i, j, k) = (x.a, x.b, x.size);
            if k > 0 {
                blocks.push(x);
                if alo < i && blo < j {
                    queue.push((alo, i, blo, j));
                }
                if i + k < ahi && j + k < bhi {
                    queue.push((i + k, ahi, j + k, bhi));
                }
            }
        }
        blocks.sort();
        let (mut i1, mut j1, mut k1) = (0, 0, 0);
        let mut out = Vec::new();
        for m in blocks {
            if i1 + k1 == m.a && j1 + k1 == m.b {
                k1 += m.size;
            } else {
                if k1 > 0 {
                    out.push(Match {
                        a: i1,
                        b: j1,
                        size: k1,
                    });
                }
                (i1, j1, k1) = (m.a, m.b, m.size);
            }
        }
        if k1 > 0 {
            out.push(Match {
                a: i1,
                b: j1,
                size: k1,
            });
        }
        out.push(Match {
            a: la,
            b: lb,
            size: 0,
        });
        out
    }

    fn opcodes(&self) -> Vec<Opcode> {
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        for m in self.matching_blocks() {
            let tag = if i < m.a && j < m.b {
                Some(Tag::Replace)
            } else if i < m.a {
                Some(Tag::Delete)
            } else if j < m.b {
                Some(Tag::Insert)
            } else {
                None
            };
            if let Some(t) = tag {
                out.push((t, i, m.a, j, m.b));
            }
            i = m.a + m.size;
            j = m.b + m.size;
            if m.size > 0 {
                out.push((Tag::Equal, m.a, i, m.b, j));
            }
        }
        out
    }

    fn grouped_opcodes(&self, n: usize) -> Vec<Vec<Opcode>> {
        let mut codes = self.opcodes();
        if codes.is_empty() {
            codes = vec![(Tag::Equal, 0, 1, 0, 1)];
        }
        if let Some(first) = codes.first_mut()
            && first.0 == Tag::Equal
        {
            let (t, i1, i2, j1, j2) = *first;
            *first = (
                t,
                i1.max(i2.saturating_sub(n)),
                i2,
                j1.max(j2.saturating_sub(n)),
                j2,
            );
        }
        if let Some(last) = codes.last_mut()
            && last.0 == Tag::Equal
        {
            let (t, i1, i2, j1, j2) = *last;
            *last = (t, i1, i2.min(i1 + n), j1, j2.min(j1 + n));
        }
        let nn = n + n;
        let mut groups = Vec::new();
        let mut group: Vec<Opcode> = Vec::new();
        for (tag, mut i1, i2, mut j1, j2) in codes {
            if tag == Tag::Equal && i2 - i1 > nn {
                group.push((tag, i1, i2.min(i1 + n), j1, j2.min(j1 + n)));
                groups.push(std::mem::take(&mut group));
                i1 = i1.max(i2.saturating_sub(n));
                j1 = j1.max(j2.saturating_sub(n));
            }
            group.push((tag, i1, i2, j1, j2));
        }
        if !group.is_empty() && !(group.len() == 1 && group[0].0 == Tag::Equal) {
            groups.push(group);
        }
        groups
    }
}

fn format_range_unified(start: usize, stop: usize) -> String {
    let mut beginning = start + 1;
    let length = stop - start;
    if length == 1 {
        return beginning.to_string();
    }
    if length == 0 {
        beginning -= 1;
    }
    format!("{beginning},{length}")
}

/// `list(difflib.unified_diff(a, b, lineterm=""))`.
pub(crate) fn unified_diff(a: &[&str], b: &[&str]) -> Vec<String> {
    let sm = SequenceMatcher::new(a, b);
    let mut out = Vec::new();
    let mut started = false;
    for group in sm.grouped_opcodes(3) {
        if !started {
            started = true;
            out.push("--- ".to_owned());
            out.push("+++ ".to_owned());
        }
        let (first, last) = (group[0], group[group.len() - 1]);
        out.push(format!(
            "@@ -{} +{} @@",
            format_range_unified(first.1, last.2),
            format_range_unified(first.3, last.4)
        ));
        for (tag, i1, i2, j1, j2) in group {
            if tag == Tag::Equal {
                for line in &a[i1..i2] {
                    out.push(format!(" {line}"));
                }
                continue;
            }
            if matches!(tag, Tag::Replace | Tag::Delete) {
                for line in &a[i1..i2] {
                    out.push(format!("-{line}"));
                }
            }
            if matches!(tag, Tag::Replace | Tag::Insert) {
                for line in &b[j1..j2] {
                    out.push(format!("+{line}"));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_change_like_python() {
        // python3 -c 'import difflib; print(list(difflib.unified_diff(
        //   ["a","b","c","d"], ["a","x","c","d","e"], lineterm="")))'
        let d = unified_diff(&["a", "b", "c", "d"], &["a", "x", "c", "d", "e"]);
        assert_eq!(
            d,
            vec![
                "--- ",
                "+++ ",
                "@@ -1,4 +1,5 @@",
                " a",
                "-b",
                "+x",
                " c",
                " d",
                "+e"
            ]
        );
    }

    #[test]
    fn distant_changes_make_two_hunks() {
        let a: Vec<String> = (0..20).map(|i| i.to_string()).collect();
        let mut b = a.clone();
        b[1] = "x".into();
        b[18] = "y".into();
        let ar: Vec<&str> = a.iter().map(String::as_str).collect();
        let br: Vec<&str> = b.iter().map(String::as_str).collect();
        let d = unified_diff(&ar, &br);
        // Python: ['--- ', '+++ ', '@@ -1,5 +1,5 @@', ' 0', '-1', '+x', ' 2',
        // ' 3', ' 4', '@@ -16,5 +16,5 @@', ' 15', ' 16', ' 17', '-18', '+y', ' 19']
        assert_eq!(d[2], "@@ -1,5 +1,5 @@");
        assert_eq!(d[9], "@@ -16,5 +16,5 @@");
        assert_eq!(d.len(), 16);
    }

    #[test]
    fn identical_is_empty() {
        assert!(unified_diff(&["a"], &["a"]).is_empty());
    }
}
