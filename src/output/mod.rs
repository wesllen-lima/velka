mod formatter;
mod redact;

pub use formatter::format_output;
pub use formatter::OutputFormat;
pub use redact::{redact_line, redact_secret, RedactionConfig};
