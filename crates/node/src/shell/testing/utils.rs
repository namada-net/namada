use std::fmt::Display;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use lazy_static::lazy_static;
use namada_sdk::io::{Io, prompt_aux, read_aux};
use tempfile::tempdir;
use tokio::io::{AsyncRead, ReadBuf};

/// Namada binaries
#[derive(Debug)]
#[allow(dead_code)]
pub enum Bin {
    Node,
    Client,
    Wallet,
    Relayer,
}

/// A temporary directory for testing
#[derive(Debug)]
pub struct TestDir(PathBuf);

impl TestDir {
    /// Creat a new temp directory. This will have to be manually
    /// cleaned up.
    pub fn new() -> Self {
        let temp = tempdir().unwrap();
        Self(temp.into_path())
    }

    /// Get the path of the directory
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Manually remove the test directory from the
    /// file system.
    pub fn clean_up(self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            println!(
                "Failed to clean up test dir at {}: {e:?}",
                self.0.to_string_lossy()
            );
        }
    }
}

impl Default for TestDir {
    fn default() -> Self {
        Self::new()
    }
}

/// The max number of bytes that the is currently remembered from stdout while
/// testing.
const TESTOUT_BUF_SIZE: usize = 100_000;

lazy_static! {
    /// A replacement for stdout in testing. The maximum number of bytes
    /// it holds is limited to prevent memory issues.
    pub static ref TESTOUT: std::sync::Arc<std::sync::Mutex<FixedBuffer<u8>>> =
    std::sync::Arc::new(std::sync::Mutex::new(FixedBuffer::new(TESTOUT_BUF_SIZE)));
}

lazy_static! {
    /// A replacement for stdin in testing.
    pub static ref TESTIN: AtomicBuffer =
    AtomicBuffer(std::sync::Arc::new(std::sync::Mutex::new(vec![])));
}

#[derive(Copy, Clone)]
pub struct TestingIo;

#[async_trait::async_trait(?Send)]
impl Io for TestingIo {
    fn print(&self, output: impl AsRef<str>) {
        let mut testout = TESTOUT.lock().unwrap();
        testout.append(output.as_ref().as_bytes().to_vec());
        print!("{}", output.as_ref());
    }

    fn println(&self, output: impl AsRef<str>) {
        let mut testout = TESTOUT.lock().unwrap();
        let mut bytes = output.as_ref().as_bytes().to_vec();
        bytes.extend_from_slice("\n".as_bytes());
        testout.append(bytes);
        println!("{}", output.as_ref());
    }

    fn write<W: std::io::Write>(
        &self,
        _: W,
        output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        self.print(output);
        Ok(())
    }

    fn writeln<W: std::io::Write>(
        &self,
        _: W,
        output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        self.println(output);
        Ok(())
    }

    fn eprintln(&self, output: impl AsRef<str>) {
        let mut testout = TESTOUT.lock().unwrap();
        let mut bytes = output.as_ref().as_bytes().to_vec();
        bytes.extend_from_slice("\n".as_bytes());
        testout.append(bytes);
        eprintln!("{}", output.as_ref());
    }

    async fn read(&self) -> tokio::io::Result<String> {
        read_aux(&*TESTIN).await
    }

    async fn prompt(&self, question: impl AsRef<str>) -> String {
        prompt_aux(&*TESTIN, tokio::io::stdout(), question.as_ref()).await
    }
}

/// Test helper that captures stdout of
/// a process.
pub struct CapturedOutput<T = ()> {
    pub output: String,
    pub result: T,
    input: String,
}

impl CapturedOutput {
    pub fn with_input(input: String) -> Self {
        Self {
            output: "".to_string(),
            result: (),
            input,
        }
    }
}

impl<T> CapturedOutput<T> {
    /// Run a client command and capture
    /// the output to the mocked stdout.
    pub fn of<F>(func: F) -> Self
    where
        F: FnOnce() -> T,
    {
        let mut capture = Self {
            output: Default::default(),
            result: func(),
            input: Default::default(),
        };
        capture.output = TESTOUT.lock().unwrap().read_string();
        capture
    }

    /// Run a client command with input to the mocked stdin and capture
    /// the output to the mocked stdout
    pub fn run<U, F>(&self, func: F) -> CapturedOutput<U>
    where
        F: FnOnce() -> U,
    {
        {
            // write the input to the mocked stdin
            let mut buf = TESTIN.lock().unwrap();
            buf.clear();
            buf.extend_from_slice(self.input.as_bytes());
        }
        CapturedOutput::of(func)
    }

    /// Return the first capture of the regex from the output.
    pub fn matches(&self, needle: &str) -> Option<&str> {
        let needle = regex::Regex::new(needle).unwrap();
        needle.find(&self.output).map(|x| x.as_str())
    }

    /// Check if the captured output contains the string.
    pub fn contains(&self, needle: &str) -> bool {
        self.matches(needle).is_some()
    }
}

impl<U, E: Display> CapturedOutput<Result<U, E>> {
    pub fn err_contains(&self, needle: &str) -> bool {
        if self.result.is_ok() {
            return false;
        }
        let err_str = match self.result.as_ref() {
            Ok(_) => unreachable!(),
            Err(e) => e.to_string(),
        };
        let needle = regex::Regex::new(needle).unwrap();
        needle.find(&err_str).is_some()
    }
}

/// A buffer with a max size. Drops elements from the front on
/// size overflow.
pub struct FixedBuffer<T: Clone> {
    inner: Vec<T>,
    max_size: usize,
}

impl<T: Clone> FixedBuffer<T> {
    fn new(max_size: usize) -> Self {
        Self {
            inner: vec![],
            max_size,
        }
    }

    /// Remove the first `size` elements from the buffer.
    fn roll(&mut self, size: usize) {
        self.inner = self.inner[size..].to_vec();
    }

    /// Add data to the end of the buffer, deleting from the
    /// front as necessary.
    fn append(&mut self, mut other: Vec<T>) {
        // if new data exceeds max size, take the tail.
        if other.len() > self.max_size {
            self.inner = other[(other.len() - self.max_size)..].to_vec();
            return;
        }
        // check if appending the data overflows buffer
        let free_space = self.max_size - self.inner.len();
        if other.len() > free_space {
            // delete the minimum amount of data from the front of the buffer
            // to fit new data.
            self.roll(other.len() - free_space);
        }
        self.inner.append(&mut other);
    }
}

impl FixedBuffer<u8> {
    /// Read the inner buffer out to string
    pub fn read_string(&mut self) -> String {
        let mut fresh = vec![];
        std::mem::swap(&mut fresh, &mut self.inner);
        String::from_utf8(fresh).unwrap()
    }
}

pub struct AtomicBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl Deref for AtomicBuffer {
    type Target = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsyncRead for &AtomicBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut inner = self.lock().unwrap();
        let buf_before = buf.filled().len();
        let res =
            AsyncRead::poll_read(Pin::new(&mut inner.as_slice()), cx, buf);
        let amount_read = buf.filled().len() - buf_before;
        *inner.deref_mut() = inner[amount_read..].to_vec();
        res
    }
}

#[cfg(test)]
mod testing {
    use super::*;

    #[test]
    fn test_buffer() {
        let mut buffer = FixedBuffer::<u64>::new(10);
        buffer.inner = (1u64..=9_u64).collect();
        buffer.append(vec![10, 11, 12, 13, 14, 15]);
        assert_eq!(buffer.inner, (6u64..=15_u64).collect::<Vec<u64>>());
        buffer.append((20u64..=40_u64).collect());
        assert_eq!(buffer.inner, (31u64..=40_u64).collect::<Vec<u64>>());
    }
}
