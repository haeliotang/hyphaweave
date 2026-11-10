// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! SPDX licence-expression syntax (§8.7). Only syntax is checked; the verifier
//! must not check the SPDX License List (§8.7, Q14).
//!
//! Grammar, tokens separated by optional ASCII whitespace:
//!
//! ```text
//! expression := or_expression
//! or_expression := and_expression ( "OR" and_expression )*
//! and_expression := simple ( "AND" simple )*
//! simple := identifier ( "WITH" identifier )? | "(" expression ")"
//! identifier := [A-Za-z0-9][A-Za-z0-9.+-]*
//! ```
//!
//! Operators are the uppercase words `AND`, `OR`, `WITH`; identifiers may
//! contain letters, digits, `.`, `+` and `-` (a trailing `+` is part of the
//! identifier).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    And,
    Or,
    With,
    LeftParen,
    RightParen,
    Identifier(&'a str),
}

fn tokenize(text: &str) -> Option<Vec<Token<'_>>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' => index += 1,
            b'(' => {
                tokens.push(Token::LeftParen);
                index += 1;
            }
            b')' => {
                tokens.push(Token::RightParen);
                index += 1;
            }
            _ if byte.is_ascii_alphanumeric() => {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || matches!(bytes[index], b'.' | b'+' | b'-'))
                {
                    index += 1;
                }
                let word = &text[start..index];
                tokens.push(match word {
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "WITH" => Token::With,
                    _ => Token::Identifier(word),
                });
            }
            _ => return None,
        }
    }
    Some(tokens)
}

/// True when `text` is a syntactically valid SPDX licence expression.
#[must_use]
pub fn is_valid_licence_expression(text: &str) -> bool {
    let Some(tokens) = tokenize(text) else {
        return false;
    };
    if tokens.is_empty() {
        return false;
    }
    let mut parser = Parser {
        tokens: &tokens,
        index: 0,
    };
    if parser.parse_or().is_none() {
        return false;
    }
    parser.index == tokens.len()
}

struct Parser<'a> {
    tokens: &'a [Token<'a>],
    index: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<Token<'_>> {
        self.tokens.get(self.index).copied()
    }

    fn parse_or(&mut self) -> Option<()> {
        self.parse_and()?;
        while self.peek() == Some(Token::Or) {
            self.index += 1;
            self.parse_and()?;
        }
        Some(())
    }

    fn parse_and(&mut self) -> Option<()> {
        self.parse_simple()?;
        while self.peek() == Some(Token::And) {
            self.index += 1;
            self.parse_simple()?;
        }
        Some(())
    }

    fn parse_simple(&mut self) -> Option<()> {
        match self.peek()? {
            Token::LeftParen => {
                self.index += 1;
                self.parse_or()?;
                if self.peek()? != Token::RightParen {
                    return None;
                }
                self.index += 1;
                Some(())
            }
            Token::Identifier(_) => {
                self.index += 1;
                if self.peek() == Some(Token::With) {
                    self.index += 1;
                    match self.peek()? {
                        Token::Identifier(_) => {
                            self.index += 1;
                        }
                        _ => return None,
                    }
                }
                Some(())
            }
            _ => None,
        }
    }
}
