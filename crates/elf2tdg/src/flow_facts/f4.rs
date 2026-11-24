//! F4 `.ff` flow-fact parser.
//!
//! Supported loop forms:
//!
//! ```text
//! loop 0x08000100 10;
//! loop "function" + 0x24 max 10 total 15;
//! loop "source.c":12 max 10 total 15 in "f" / "g1" / "main";
//! ```

use super::{ContextKind, FlowFactDocument, LoopFact, LoopTarget};

pub(super) fn parse(text: &str, origin: &str) -> Result<FlowFactDocument, String> {
    let mut document = FlowFactDocument {
        origin: origin.to_owned(),
        checksum: None,
        loops: Vec::new(),
        branches: Vec::new(),
        calls: Vec::new(),
        conflicts: Vec::new(),
        warnings: Vec::new(),
    };
    for (index, statement) in statements(text).into_iter().enumerate() {
        let tokens = tokenize(&statement)
            .map_err(|error| format!("{origin}: statement {}: {error}", index + 1))?;
        if tokens.is_empty() {
            continue;
        }
        match tokens.first() {
            Some(Token::Word(word)) if word == "checksum" => {
                document.checksum = Some(statement);
            }
            Some(Token::Word(word)) if word == "nocall" => {
                document.warnings.push(format!(
                    "{origin}: nocall directive ignored; calls remain analyzed"
                ));
            }
            Some(Token::Word(word)) if word == "loop" => {
                let (fact, warnings) = parse_loop(&tokens[1..])
                    .map_err(|error| format!("{origin}: statement {}: {error}", index + 1))?;
                document.loops.push(fact);
                document.warnings.extend(warnings);
            }
            Some(Token::Word(word)) => {
                document.warnings.push(format!(
                    "{origin}: unsupported F4 directive {word:?} ignored"
                ));
            }
            _ => {
                document
                    .warnings
                    .push(format!("{origin}: unsupported F4 statement ignored"));
            }
        }
    }
    Ok(document)
}

fn parse_loop(tokens: &[Token]) -> Result<(LoopFact, Vec<String>), String> {
    let mut warnings = Vec::new();
    let mut index = 0;
    let target = match tokens.get(index) {
        Some(Token::Word(word)) => {
            let address = parse_number(word)?;
            index += 1;
            LoopTarget::Address(address)
        }
        Some(Token::Quoted(name)) => {
            index += 1;
            match tokens.get(index) {
                Some(Token::Symbol(':')) => {
                    index += 1;
                    let line = parse_u32(tokens.get(index))?;
                    index += 1;
                    LoopTarget::SourceLine {
                        function: None,
                        file: name.clone(),
                        line,
                    }
                }
                Some(Token::Symbol('+')) => {
                    index += 1;
                    let offset = parse_u64(tokens.get(index))?;
                    index += 1;
                    LoopTarget::FunctionOffset {
                        function: name.clone(),
                        offset,
                    }
                }
                _ => {
                    return Err("expected ':' or '+' after a quoted loop target".to_owned());
                }
            }
        }
        _ => {
            return Err(
                "expected a loop address, \"function\" + offset, or \"file\":line".to_owned(),
            );
        }
    };
    let max = parse_bound(tokens, &mut index, &mut warnings)?;
    let mut context = Vec::new();
    if let Some(Token::Word(word)) = tokens.get(index)
        && word == "in"
    {
        index += 1;
        while let Some(token) = tokens.get(index) {
            match token {
                Token::Quoted(value) | Token::Word(value) => context.push(value.clone()),
                Token::Symbol(_) => {}
            }
            index += 1;
        }
    }
    if index < tokens.len() {
        warnings.push(format!(
            "{} extra token(s) after loop fact ignored",
            tokens.len() - index
        ));
    }
    if max == 0 {
        return Err("loop max bound must be positive".to_owned());
    }
    Ok((
        LoopFact {
            target,
            max,
            context,
            context_kind: ContextKind::Function,
        },
        warnings,
    ))
}

fn parse_bound(
    tokens: &[Token],
    index: &mut usize,
    warnings: &mut Vec<String>,
) -> Result<u32, String> {
    let Some(token) = tokens.get(*index) else {
        return Err("missing loop bound".to_owned());
    };
    match token {
        Token::Word(word) if word == "max" => {
            *index += 1;
            let max = parse_u32(tokens.get(*index))?;
            *index += 1;
            if let Some(Token::Word(word)) = tokens.get(*index)
                && word == "total"
            {
                *index += 1;
                let _total = parse_u32(tokens.get(*index))?;
                *index += 1;
            }
            Ok(max)
        }
        Token::Word(word) if word == "total" => {
            *index += 1;
            let total = parse_u32(tokens.get(*index))?;
            *index += 1;
            warnings
                .push("loop has only a total count; using it as the per-entry bound".to_owned());
            Ok(total)
        }
        Token::Word(word) => {
            let max = parse_number(word)?;
            *index += 1;
            if let Some(Token::Word(word)) = tokens.get(*index)
                && word == "total"
            {
                *index += 1;
                let _total = parse_u32(tokens.get(*index))?;
                *index += 1;
            }
            u32::try_from(max).map_err(|_| "loop bound exceeds u32".to_owned())
        }
        _ => Err("expected a loop bound or 'max'/'total'".to_owned()),
    }
}

fn parse_u64(token: Option<&Token>) -> Result<u64, String> {
    match token {
        Some(Token::Word(word)) => parse_number(word),
        _ => Err("expected a number".to_owned()),
    }
}

fn parse_u32(token: Option<&Token>) -> Result<u32, String> {
    u32::try_from(parse_u64(token)?).map_err(|_| "number exceeds u32".to_owned())
}

fn parse_number(word: &str) -> Result<u64, String> {
    let cleaned = word.trim().replace('_', "");
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|error| format!("invalid hex number {word:?}: {error}"))
    } else {
        cleaned
            .parse::<u64>()
            .map_err(|error| format!("invalid number {word:?}: {error}"))
    }
}

#[derive(Clone, Debug)]
enum Token {
    Word(String),
    Quoted(String),
    Symbol(char),
}

fn tokenize(statement: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = statement.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        match ch {
            '"' => {
                chars.next();
                let mut value = String::new();
                let mut escaped = false;
                loop {
                    match chars.next() {
                        Some('"') if !escaped => break,
                        Some('\\') if !escaped => {
                            escaped = true;
                            value.push('\\');
                        }
                        Some(next) => {
                            escaped = false;
                            value.push(next);
                        }
                        None => return Err("unterminated quoted string".to_owned()),
                    }
                }
                tokens.push(Token::Quoted(value));
            }
            '+' | ':' | '/' | ',' | '=' => {
                chars.next();
                tokens.push(Token::Symbol(ch));
            }
            _ => {
                let mut value = String::new();
                while let Some(&next) = chars.peek() {
                    if next.is_whitespace()
                        || matches!(next, '+' | ':' | '/' | ',' | '=' | ';' | '"')
                    {
                        break;
                    }
                    value.push(next);
                    chars.next();
                }
                tokens.push(Token::Word(value));
            }
        }
    }
    Ok(tokens)
}

fn statements(text: &str) -> Vec<String> {
    let mut cleaned = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                cleaned.push('\n');
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if in_string {
            cleaned.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
            continue;
        }
        if ch == '"' {
            in_string = true;
        }
        cleaned.push(ch);
    }

    let mut statements = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in cleaned.chars() {
        if in_string {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                current.push(ch);
            }
            ';' => {
                if !current.trim().is_empty() {
                    statements.push(current.trim().to_owned());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        statements.push(current.trim().to_owned());
    }
    statements
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::flow_facts::{ContextKind, LoopTarget};

    #[test]
    fn parses_address_and_standard_bounds() {
        let document = parse(
            "checksum \"fw.elf\" 0x1234;\nloop 0x800013e 7;\nloop 0x8000200 max 3 total 9;",
            "test.ff",
        )
        .expect("parse");
        assert!(document.checksum.is_some());
        assert_eq!(document.loops.len(), 2);
        assert!(matches!(
            document.loops[0].target,
            LoopTarget::Address(0x0800_013e)
        ));
        assert_eq!(document.loops[0].max, 7);
        assert_eq!(document.loops[1].max, 3);
    }

    #[test]
    fn parses_function_offset_and_source_line() {
        let document = parse(
            "loop \"main\" + 0x6 max 10 total 15;\nloop \"main.c\":29 max 4 in \"main\";",
            "test.ff",
        )
        .expect("parse");
        assert_eq!(document.loops.len(), 2);
        assert!(matches!(
            &document.loops[0].target,
            LoopTarget::FunctionOffset { function, offset } if function == "main" && *offset == 6
        ));
        assert_eq!(document.loops[0].max, 10);
        assert!(matches!(
            &document.loops[1].target,
            LoopTarget::SourceLine { function: None, file, line } if file == "main.c" && *line == 29
        ));
        assert_eq!(document.loops[1].context, vec!["main"]);
        assert_eq!(document.loops[1].context_kind, ContextKind::Function);
    }

    #[test]
    fn total_only_uses_total_as_bound_with_a_warning() {
        let document = parse("loop 0x100 max 2 total 9;", "test.ff").expect("parse");
        assert_eq!(document.loops[0].max, 2);
        assert_eq!(document.warnings.len(), 0);

        let document = parse("loop 0x100 total 9;", "test.ff").expect("parse");
        assert_eq!(document.loops[0].max, 9);
        assert!(
            document
                .warnings
                .iter()
                .any(|warning| warning.contains("total"))
        );
    }

    #[test]
    fn nocall_is_ignored_with_a_warning() {
        let document = parse("nocall \"printf\";", "test.ff").expect("parse");
        assert!(document.loops.is_empty());
        assert!(
            document
                .warnings
                .iter()
                .any(|warning| warning.contains("nocall"))
        );
    }
}
