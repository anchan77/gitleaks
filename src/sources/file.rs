//! File source implementation for reading and chunking files.
//!
//! This module provides the `File` struct which implements the `Source` trait
//! for reading content from files or other readers. It handles:
//! - Chunked reading for large files (~100KB chunks)
//! - Binary file detection using MIME type analysis
//! - Safe chunk boundary detection to avoid splitting secrets
//! - Line number tracking for accurate reporting

use super::{Fragment, Source, SourceError};
use std::io::{BufReader, Read};

/// Default buffer size for chunked reading (~100KB)
const DEFAULT_BUFFER_SIZE: usize = 100 * 1_000;

/// Maximum size to read ahead when looking for safe chunk boundaries (~25KB)
const MAX_PEEK_SIZE: usize = 25 * 1_000;

/// Checks if a byte is considered whitespace
#[inline]
fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// A source for yielding fragments from a file or other reader.
///
/// The `File` struct reads content in chunks to avoid loading large files
/// entirely into memory. It uses MIME type detection to skip binary files
/// and implements safe boundary detection to avoid splitting potential secrets.
pub struct File {
    /// The reader providing the file content
    content: Box<dyn Read>,
    /// The file path (used for fragment metadata)
    path: String,
    /// Optional symlink path if the file was accessed via symlink
    symlink: Option<String>,
}

impl File {
    /// Creates a new File source from a reader and path.
    ///
    /// # Arguments
    /// * `content` - A boxed reader providing the file content
    /// * `path` - The file path to include in fragment metadata
    pub fn new(content: Box<dyn Read>, path: String) -> Self {
        Self {
            content,
            path,
            symlink: None,
        }
    }

    /// Creates a new File source with a symlink path.
    ///
    /// # Arguments
    /// * `content` - A boxed reader providing the file content
    /// * `path` - The file path to include in fragment metadata
    /// * `symlink` - The symlink path if the file was accessed via symlink
    pub fn with_symlink(content: Box<dyn Read>, path: String, symlink: String) -> Self {
        Self {
            content,
            path,
            symlink: Some(symlink),
        }
    }
}

/// Reads from the reader until a safe boundary is found.
///
/// A safe boundary is defined as two or more consecutive newlines (with optional
/// whitespace between them). This prevents splitting content in the middle of
/// multi-line secrets. The function will read ahead up to `max_peek_size` bytes
/// to find a safe boundary.
///
/// # Arguments
/// * `reader` - The buffered reader to read from
/// * `initial_bytes_read` - Number of bytes already in the buffer (used to calculate peek limit)
/// * `max_peek_size` - Maximum number of additional bytes to read beyond initial_bytes_read
/// * `buffer` - The buffer containing the initial chunk and where additional bytes will be appended
///
/// # Returns
/// * `Ok(())` if successful (either found a safe boundary or reached limit)
/// * `Err(SourceError)` if an IO error occurs
fn read_until_safe_boundary(
    reader: &mut impl Read,
    initial_bytes_read: usize,
    max_peek_size: usize,
    buffer: &mut Vec<u8>,
) -> Result<(), SourceError> {
    if buffer.is_empty() {
        return Ok(());
    }

    // Check if buffer already ends with consecutive newlines
    let mut newline_count = 0;
    let data = buffer.as_slice();
    let last_char = data[data.len() - 1];

    if is_whitespace(last_char) {
        for &byte in data.iter().rev() {
            if byte == b'\n' {
                newline_count += 1;
                if newline_count >= 2 {
                    return Ok(());
                }
            } else if !is_whitespace(byte) {
                break;
            }
        }
    }

    // Read ahead to find consecutive newlines
    newline_count = 0;
    let mut single_byte = [0u8; 1];

    loop {
        // Stop if we've read enough ahead beyond the initial buffer
        // Matches Go's logic: (peekBuf.Len() - n) >= maxPeekSize
        if (buffer.len() - initial_bytes_read) >= max_peek_size {
            break;
        }

        // Read one byte at a time
        match reader.read(&mut single_byte) {
            Ok(0) => break, // EOF
            Ok(_) => {
                buffer.push(single_byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(SourceError::Io(e)),
        }

        // Check if last character is a newline
        let data = buffer.as_slice();
        let last_char = data[data.len() - 1];

        if last_char == b'\n' {
            newline_count += 1;
            if newline_count >= 2 {
                break;
            }
        } else if is_whitespace(last_char) {
            // Other whitespace doesn't reset the count
        } else {
            newline_count = 0;
        }
    }

    Ok(())
}

impl Source for File {
    fn fragments(&mut self) -> Box<dyn Iterator<Item = Result<Fragment, SourceError>> + '_> {
        Box::new(FileFragmentIterator::new(self))
    }
}

/// Iterator that yields fragments from a file source.
struct FileFragmentIterator<'a> {
    reader: BufReader<Box<dyn Read + 'a>>,
    path: String,
    symlink: Option<String>,
    buffer: Vec<u8>,
    total_lines: usize,
    first_chunk: bool,
    done: bool,
}

impl<'a> FileFragmentIterator<'a> {
    fn new(file: &'a mut File) -> Self {
        // Take ownership of the reader using std::mem::replace
        let content = std::mem::replace(&mut file.content, Box::new(std::io::empty()));

        Self {
            reader: BufReader::new(content),
            path: file.path.clone(),
            symlink: file.symlink.clone(),
            buffer: vec![0u8; DEFAULT_BUFFER_SIZE],
            total_lines: 0,
            first_chunk: true,
            done: false,
        }
    }
}

impl<'a> Iterator for FileFragmentIterator<'a> {
    type Item = Result<Fragment, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // Read a chunk into the buffer
        let n = match self.reader.read(&mut self.buffer) {
            Ok(0) => {
                // EOF
                self.done = true;
                return None;
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // Retry on interrupt
                return self.next();
            }
            Err(e) => {
                self.done = true;
                return Some(Err(SourceError::Io(e)));
            }
        };

        // On first chunk, check MIME type to detect binary files
        if self.first_chunk {
            self.first_chunk = false;

            if let Some(kind) = infer::get(&self.buffer[..n]) {
                let mime_type = kind.mime_type();
                // Skip files with application/* MIME type (binary files)
                if mime_type.starts_with("application/") {
                    log::debug!(
                        "Skipping binary file with MIME type {}: {}",
                        mime_type,
                        self.path
                    );
                    self.done = true;
                    return None;
                }
            }
        }

        // Create a buffer with the chunk and extend to safe boundary
        let mut chunk_buffer = self.buffer[..n].to_vec();

        if let Err(e) = read_until_safe_boundary(
            &mut self.reader,
            n,
            MAX_PEEK_SIZE,
            &mut chunk_buffer,
        ) {
            self.done = true;
            return Some(Err(e));
        }

        // Convert to string (handling invalid UTF-8 gracefully)
        let raw = String::from_utf8_lossy(&chunk_buffer).into_owned();

        // Count newlines for line tracking
        let newline_count = raw.matches('\n').count();

        // Create fragment
        let mut fragment = Fragment::with_start_line(
            raw,
            self.path.clone(),
            self.total_lines + 1,
        );

        if let Some(ref symlink) = self.symlink {
            fragment.symlink_file = Some(symlink.clone());
        }

        self.total_lines += newline_count;

        Some(Ok(fragment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_until_safe_boundary_safe_lf() {
        let remaining = b"defghijklmnop\n\nqrstuvwxyz";
        let mut reader = Cursor::new(remaining);
        let mut buffer = b"abc\n\n".to_vec();

        read_until_safe_boundary(&mut reader, 5, 20, &mut buffer).unwrap();

        assert_eq!(&buffer, b"abc\n\n");
    }

    #[test]
    fn test_read_until_safe_boundary_safe_crlf() {
        let remaining = b"bcdefghijklmnop\n";
        let mut reader = Cursor::new(remaining);
        let mut buffer = b"a\r\n\r\n".to_vec();

        read_until_safe_boundary(&mut reader, 5, 20, &mut buffer).unwrap();

        assert_eq!(&buffer, b"a\r\n\r\n");
    }

    #[test]
    fn test_read_until_safe_boundary_finds_safe_lf() {
        let remaining = b"hijklmnop\n\nqrstuvwxyz";
        let mut reader = Cursor::new(remaining);
        let mut buffer = b"abcde".to_vec();

        read_until_safe_boundary(&mut reader, 5, 20, &mut buffer).unwrap();

        assert_eq!(&buffer, b"abcdehijklmnop\n\n");
    }

    #[test]
    fn test_read_until_safe_boundary_finds_safe_crlf() {
        let remaining = b"hijklmnop\r\n\r\nqrstuvwxyz";
        let mut reader = Cursor::new(remaining);
        let mut buffer = b"abcde".to_vec();

        read_until_safe_boundary(&mut reader, 5, 20, &mut buffer).unwrap();

        assert_eq!(&buffer, b"abcdehijklmnop\r\n\r\n");
    }

    #[test]
    fn test_read_until_safe_boundary_blank_line() {
        let remaining = b"hijklmnop\n\t  \t\nqrstuvwxyz";
        let mut reader = Cursor::new(remaining);
        let mut buffer = b"abcde".to_vec();

        read_until_safe_boundary(&mut reader, 5, 20, &mut buffer).unwrap();

        assert_eq!(&buffer, b"abcdehijklmnop\n\t  \t\n");
    }

    #[test]
    fn test_read_until_safe_boundary_no_safe_split() {
        let remaining = b"hijklmnopqrstuvwxyz";
        let mut reader = Cursor::new(remaining);
        let mut buffer = b"abcde".to_vec();
        let initial_len = buffer.len();

        read_until_safe_boundary(&mut reader, initial_len, 20, &mut buffer).unwrap();

        // Should read until (buffer.len() - initial_len) >= max_peek_size
        // Initial: 5 bytes, max_peek_size: 20
        // Stops when buffer.len() >= 5 + 20 = 25
        // But we only have 19 bytes in reader, so we get all of them
        // Total: 5 + 19 = 24 bytes
        assert_eq!(&buffer, b"abcdehijklmnopqrstuvwxyz");
    }

    #[test]
    fn test_file_source_small_text() {
        let content = b"line1\nline2\nline3\n";
        let mut file = File::new(
            Box::new(Cursor::new(content.to_vec())),
            "test.txt".to_string(),
        );

        let fragments: Vec<_> = file.fragments().collect();
        assert_eq!(fragments.len(), 1);

        let fragment = fragments[0].as_ref().unwrap();
        assert_eq!(fragment.raw, "line1\nline2\nline3\n");
        assert_eq!(fragment.file_path, "test.txt");
        assert_eq!(fragment.start_line, 1);
    }

    #[test]
    fn test_file_source_with_symlink() {
        let content = b"some content\n";
        let mut file = File::with_symlink(
            Box::new(Cursor::new(content.to_vec())),
            "/real/path.txt".to_string(),
            "/link/to/path.txt".to_string(),
        );

        let fragments: Vec<_> = file.fragments().collect();
        assert_eq!(fragments.len(), 1);

        let fragment = fragments[0].as_ref().unwrap();
        assert_eq!(fragment.symlink_file, Some("/link/to/path.txt".to_string()));
        assert_eq!(fragment.file_path, "/real/path.txt");
    }

    #[test]
    fn test_file_source_line_counting() {
        // Create content with known line breaks
        let content = b"line1\nline2\nline3\n";
        let mut file = File::new(
            Box::new(Cursor::new(content.to_vec())),
            "test.txt".to_string(),
        );

        let fragments: Vec<_> = file.fragments().collect();
        assert_eq!(fragments.len(), 1);

        let fragment = fragments[0].as_ref().unwrap();
        assert_eq!(fragment.start_line, 1);
        // Content has 3 newlines, so next chunk would start at line 4
    }

    #[test]
    fn test_file_source_application_binary_skipped() {
        // Create a PDF file header (application/pdf MIME type)
        let pdf_header = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
        let mut file = File::new(
            Box::new(Cursor::new(pdf_header.to_vec())),
            "document.pdf".to_string(),
        );

        let fragments: Vec<_> = file.fragments().collect();
        // PDF files have MIME type "application/pdf"
        // So they ARE skipped by our binary detection
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn test_file_source_image_not_skipped() {
        // Create a PNG file header (image/png MIME type)
        let png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let mut file = File::new(
            Box::new(Cursor::new(png_header.to_vec())),
            "image.png".to_string(),
        );

        let fragments: Vec<_> = file.fragments().collect();
        // PNG files have MIME type "image/png", not "application/*"
        // So they are NOT automatically skipped by our binary detection
        // (Archives will be handled separately in Task 3)
        assert_eq!(fragments.len(), 1);
    }

    #[test]
    fn test_file_source_empty_file() {
        let content = b"";
        let mut file = File::new(
            Box::new(Cursor::new(content.to_vec())),
            "empty.txt".to_string(),
        );

        let fragments: Vec<_> = file.fragments().collect();
        // Empty file produces no fragments
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn test_file_source_multiple_chunks() {
        // Create content larger than DEFAULT_BUFFER_SIZE (100KB) to force multiple chunks
        // Each chunk will be 100,000 'x' characters followed by two newlines (safe boundary)
        let chunk1 = "x".repeat(100_000) + "\n\n";
        let chunk2 = "y".repeat(50_000) + "\n\n";
        let large_content = chunk1.clone() + &chunk2;

        let mut file = File::new(
            Box::new(Cursor::new(large_content.as_bytes().to_vec())),
            "large.txt".to_string(),
        );

        let fragments: Vec<_> = file.fragments().collect();

        // Should have at least 2 fragments since content > 100KB
        assert!(fragments.len() >= 2, "Expected at least 2 fragments, got {}", fragments.len());

        // First fragment should start at line 1
        let frag1 = fragments[0].as_ref().unwrap();
        assert_eq!(frag1.start_line, 1);
        assert_eq!(frag1.file_path, "large.txt");

        // Count newlines in first fragment to determine where second fragment starts
        let newlines_in_frag1 = frag1.raw.matches('\n').count();

        // Second fragment should start at the line after the first fragment
        let frag2 = fragments[1].as_ref().unwrap();
        assert_eq!(frag2.start_line, newlines_in_frag1 + 1);
        assert_eq!(frag2.file_path, "large.txt");

        // Verify all fragments succeeded (no errors)
        for (i, result) in fragments.iter().enumerate() {
            assert!(result.is_ok(), "Fragment {} failed: {:?}", i, result);
        }
    }
}
