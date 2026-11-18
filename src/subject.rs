use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Ticket,
    Pr,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ticket => "ticket",
            Self::Pr => "pr",
        }
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct SubjectInput {
    pub subject_kind: SubjectKind,
    /// A Linear ticket key or a GitHub repository and PR number, such as ALT-15706 or org/repo#645.
    pub subject_ref: String,
}

pub struct Subject {
    pub kind: SubjectKind,
    pub reference: String,
}

impl TryFrom<SubjectInput> for Subject {
    type Error = &'static str;

    fn try_from(input: SubjectInput) -> Result<Self, Self::Error> {
        let reference = input.subject_ref.trim();
        if reference.len() > 200 {
            return Err("subject_ref is too long");
        }
        let reference = match input.subject_kind {
            SubjectKind::Ticket => {
                ticket(reference).ok_or("use a Linear ticket key such as ALT-15706")?
            }
            SubjectKind::Pr => {
                pull_request(reference).ok_or("use a GitHub PR reference such as org/repo#645")?
            }
        };
        Ok(Self {
            kind: input.subject_kind,
            reference,
        })
    }
}

fn ticket(input: &str) -> Option<String> {
    let (project, number) = input.rsplit_once('-')?;
    if !project.starts_with(|c: char| c.is_ascii_alphabetic())
        || !project
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    Some(format!(
        "{}-{}",
        project.to_ascii_uppercase(),
        nonzero(number)?
    ))
}

fn pull_request(input: &str) -> Option<String> {
    let (repo, number) = input.rsplit_once('#')?;
    let parts: Vec<_> = repo.split('/').collect();
    if parts.len() > 2
        || !parts.iter().all(|p| {
            !p.is_empty()
                && *p != "."
                && *p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        })
    {
        return None;
    }
    Some(format!(
        "{}#{}",
        repo.to_ascii_lowercase(),
        nonzero(number)?
    ))
}

fn nonzero(input: &str) -> Option<u64> {
    if input.bytes().all(|b| b.is_ascii_digit()) {
        input.parse().ok().filter(|n| *n > 0)
    } else {
        None
    }
}

pub fn one_line(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' | '\u{85}' | '\u{2028}' | '\u{2029}' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect::<String>()
        .trim()
        .to_owned()
}
