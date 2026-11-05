//! Newline-delimited framing with a hard line cap.

use std::io::{self, BufRead};

use oftc_ui_edge::MAX_LINE;

#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// One line, newline removed (and a trailing `\r`).
    Complete(Vec<u8>),
    /// More than [`MAX_LINE`] bytes with no newline: the caller closes.
    TooLong,
    /// The peer closed. A partial last line is dropped.
    Eof,
}

/// Reads the next line without ever buffering more than `MAX_LINE + 1` bytes.
pub fn read_line(reader: &mut impl BufRead) -> io::Result<Line> {
    let mut line = Vec::new();
    loop {
        let (consumed, found) = {
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                return Ok(Line::Eof);
            }
            match buffer.iter().position(|&b| b == b'\n') {
                Some(at) => {
                    line.extend_from_slice(&buffer[..at]);
                    (at + 1, true)
                }
                None => {
                    line.extend_from_slice(buffer);
                    (buffer.len(), false)
                }
            }
        };
        reader.consume(consumed);
        // The cap counts the line, not the newline.
        if line.len() > MAX_LINE {
            return Ok(Line::TooLong);
        }
        if found {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Line::Complete(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    /// A reader that hands out two bytes at a time, so lines span reads.
    struct Dribble(Cursor<Vec<u8>>);

    impl io::Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let end = buf.len().min(2);
            self.0.read(&mut buf[..end])
        }
    }

    fn lines(input: Vec<u8>) -> Vec<Line> {
        let mut reader = BufReader::with_capacity(8, Dribble(Cursor::new(input)));
        let mut all = Vec::new();
        loop {
            let line = read_line(&mut reader).unwrap();
            let done = matches!(line, Line::Eof | Line::TooLong);
            all.push(line);
            if done {
                return all;
            }
        }
    }

    fn complete(text: &str) -> Line {
        Line::Complete(text.as_bytes().to_vec())
    }

    #[test]
    fn splits_lines_across_reads_and_drops_a_partial_tail() {
        assert_eq!(
            lines(b"{\"a\":1}\n\r\nsecond\r\npartial".to_vec()),
            vec![
                complete("{\"a\":1}"),
                complete(""),
                complete("second"),
                Line::Eof
            ]
        );
    }

    /// 64 KiB exactly is a line; one byte more closes, whether or not a newline follows.
    #[test]
    fn the_cap_is_exactly_64_kib() {
        let at_cap = "x".repeat(MAX_LINE);
        let mut input = at_cap.clone().into_bytes();
        input.push(b'\n');
        assert_eq!(lines(input), vec![complete(&at_cap), Line::Eof]);
        let over = "x".repeat(MAX_LINE + 1);
        for tail in ["\n", ""] {
            let input = format!("{over}{tail}").into_bytes();
            assert_eq!(lines(input), vec![Line::TooLong], "tail {tail:?}");
        }
    }
}
