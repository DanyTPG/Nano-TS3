use std::collections::HashMap;

/// Escapes a raw string into TeamSpeak 3 command-escaped format.
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '/' => out.push_str(r"\/"),
            ' ' => out.push_str(r"\s"),
            '|' => out.push_str(r"\p"),
            '\x07' => out.push_str(r"\a"),
            '\x08' => out.push_str(r"\b"),
            '\t' => out.push_str(r"\t"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\x0b' => out.push_str(r"\v"),
            '\x0c' => out.push_str(r"\f"),
            _ => out.push(c),
        }
    }
    out
}

/// Unescapes a TeamSpeak 3 command-escaped string into raw text.
pub fn unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    's' => out.push(' '),
                    'p' => out.push('|'),
                    'a' => out.push('\x07'),
                    'b' => out.push('\x08'),
                    't' => out.push('\t'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    'v' => out.push('\x0b'),
                    'f' => out.push('\x0c'),
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Represents a parsed TeamSpeak 3 command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub name: String,
    pub params: HashMap<String, String>,
    pub raw: String,
}

impl Command {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            params: HashMap::new(),
            raw: String::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, val: impl Into<String>) -> &mut Self {
        self.params.insert(key.into(), val.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(|s| s.as_str())
    }

    /// Formats the command into wire-ready string.
    pub fn build(&self) -> String {
        let mut out = self.name.clone();
        for (k, v) in &self.params {
            out.push(' ');
            out.push_str(&escape(k));
            if !v.is_empty() {
                out.push('=');
                out.push_str(&escape(v));
            }
        }
        out
    }

    /// Parses a raw command string.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        let mut parts = trimmed.split_whitespace();
        let name = parts.next()?.to_string();
        let mut params = HashMap::new();

        for part in parts {
            if let Some((k, v)) = part.split_once('=') {
                params.entry(unescape(k)).or_insert_with(|| unescape(v));
            } else {
                params.entry(unescape(part)).or_insert_with(String::new);
            }
        }

        Some(Self {
            name,
            params,
            raw: trimmed.to_string(),
        })
    }

    /// Parses piped parameter sets if the command contains `|`.
    /// E.g. `channeladdperm cid=16 permid=1 val=10|permid=2 val=20` returns a vector of
    /// parameter maps, with common prefix parameters (`cid=16`) propagated to subsequent items.
    pub fn parse_piped_param_sets(&self) -> Vec<HashMap<String, String>> {
        let trimmed = self.raw.trim();
        let Some((_name, rest)) = trimmed.split_once(char::is_whitespace) else {
            return vec![self.params.clone()];
        };
        if !rest.contains('|') {
            return vec![self.params.clone()];
        }
        let items: Vec<&str> = rest.split('|').collect();
        let mut results = Vec::new();
        let mut base_common = HashMap::new();
        for (idx, item) in items.iter().enumerate() {
            let mut map = if idx == 0 {
                HashMap::new()
            } else {
                base_common.clone()
            };
            for part in item.split_whitespace() {
                if let Some((k, v)) = part.split_once('=') {
                    map.entry(unescape(k)).or_insert_with(|| unescape(v));
                } else {
                    map.entry(unescape(part)).or_insert_with(String::new);
                }
            }
            if idx == 0 {
                for (k, v) in &map {
                    if k != "permid"
                        && k != "permsid"
                        && k != "permvalue"
                        && k != "permnegated"
                        && k != "permskip"
                    {
                        base_common.insert(k.clone(), v.clone());
                    }
                }
            }
            results.push(map);
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_unescape() {
        let original = r"Hello World! /|\ Test\nLine";
        let escaped = escape(original);
        assert_eq!(unescape(&escaped), original);
    }

    #[test]
    fn test_command_build_and_parse() {
        let mut cmd = Command::new("clientinit");
        cmd.set("client_nickname", "Tester 1");
        cmd.set("client_version", "3.6.2 [Build: 1695216578]");
        let wire = cmd.build();

        let parsed = Command::parse(&wire).unwrap();
        assert_eq!(parsed.name, "clientinit");
        assert_eq!(parsed.get("client_nickname"), Some("Tester 1"));
        assert_eq!(
            parsed.get("client_version"),
            Some("3.6.2 [Build: 1695216578]")
        );
    }
}
