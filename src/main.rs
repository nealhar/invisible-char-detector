use std::collections::HashMap;
use std::fs;
use std::process;

use glob::glob;
use serde::{Deserialize, Serialize};

/// A single detection record describing one suspicious code point occurrence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Detection {
    /// File path where the suspicious character was found.
    file: String,

    /// 1-indexed line number in the file.
    line: usize,

    /// 1-indexed byte offset from start of file (unambiguous for all editors).
    byte_offset: usize,

    /// 1-indexed character index within the line (Unicode scalar count).
    char_index: usize,

    /// The character itself as a string (may be invisible in terminals/editors).
    char: String,

    /// Unicode code point value (scalar value) of the character.
    code: u32,

    /// A human-readable Unicode name or classification label.
    name: String,

    /// A short explanation of why this code point is considered suspicious.
    description: String,
}

/// Configuration for scan behavior.
#[derive(Debug, Clone)]
struct ScanConfig {
    /// Pattern to match files (e.g., "**/*.rs")
    pattern: String,

    /// Output as JSON instead of human-readable text
    json_output: bool,

    /// Show warnings for ignored/unreadable files
    verbose: bool,

    /// Fail with exit code 2 if any files cannot be read (strict mode)
    fail_on_skip: bool,

    /// When true, scan dist/out/build directories (good for bundled extensions)
    /// When false, ignore them (good for source repos)
    scan_bundles: bool,
}

/// Returns a lookup map of high-risk Unicode code points.
///
/// This is intentionally focused on:
/// - Zero-width and formatting characters used for obfuscation
/// - Bidirectional controls (Trojan Source class)
/// - Directional marks
/// - Variation selectors (FE00-FE0F)
/// - Line/paragraph separators
/// - A few frequently abused "blank" characters
fn get_suspicious_chars() -> HashMap<u32, (&'static str, &'static str)> {
    let mut map = HashMap::new();

    // Zero-width characters: visually invisible but alter string/identifier content
    map.insert(0x200B, ("ZERO WIDTH SPACE", "Invisible character used to hide code"));
    map.insert(0x200C, ("ZERO WIDTH NON-JOINER", "Can alter code logic invisibly"));
    map.insert(0x200D, ("ZERO WIDTH JOINER", "Can alter code logic invisibly"));
    map.insert(0x2060, ("WORD JOINER", "Invisible joiner; often used to hide payloads"));
    map.insert(0xFEFF, ("ZERO WIDTH NO-BREAK SPACE", "BOM or invisible space"));

    // Bidirectional (bidi) directional overrides and controls (complete set)
    map.insert(0x202A, ("LEFT-TO-RIGHT EMBEDDING", "Bidi control; can mislead code review"));
    map.insert(0x202B, ("RIGHT-TO-LEFT EMBEDDING", "Bidi control; can mislead code review"));
    map.insert(0x202C, ("POP DIRECTIONAL FORMATTING", "Bidi control; terminates embeddings/overrides"));
    map.insert(0x202D, ("LEFT-TO-RIGHT OVERRIDE", "Bidi override; can reorder displayed code"));
    map.insert(0x202E, ("RIGHT-TO-LEFT OVERRIDE", "Bidi override; can reorder displayed code"));

    // Bidi isolates (Unicode 6.3+)
    map.insert(0x2066, ("LEFT-TO-RIGHT ISOLATE", "Bidi isolate; can affect display order"));
    map.insert(0x2067, ("RIGHT-TO-LEFT ISOLATE", "Bidi isolate; can affect display order"));
    map.insert(0x2068, ("FIRST STRONG ISOLATE", "Bidi isolate; can affect display order"));
    map.insert(0x2069, ("POP DIRECTIONAL ISOLATE", "Bidi isolate terminator"));

    // Directional marks: invisible but affect rendering order/selection
    map.insert(0x200E, ("LEFT-TO-RIGHT MARK", "Invisible directional marker"));
    map.insert(0x200F, ("RIGHT-TO-LEFT MARK", "Invisible directional marker"));
    map.insert(0x061C, ("ARABIC LETTER MARK", "Invisible directional marker"));

    // Variation selectors: modify glyph appearance (U+FE00..U+FE0F)
    // Note: names are simplified; report includes code point.
    map.insert(0xFE00, ("VARIATION SELECTOR-0", "Can modify character appearance"));
    map.insert(0xFE01, ("VARIATION SELECTOR-1", "Can modify character appearance"));
    map.insert(0xFE02, ("VARIATION SELECTOR-2", "Can modify character appearance"));
    map.insert(0xFE03, ("VARIATION SELECTOR-3", "Can modify character appearance"));
    map.insert(0xFE04, ("VARIATION SELECTOR-4", "Can modify character appearance"));
    map.insert(0xFE05, ("VARIATION SELECTOR-5", "Can modify character appearance"));
    map.insert(0xFE06, ("VARIATION SELECTOR-6", "Can modify character appearance"));
    map.insert(0xFE07, ("VARIATION SELECTOR-7", "Can modify character appearance"));
    map.insert(0xFE08, ("VARIATION SELECTOR-8", "Can modify character appearance"));
    map.insert(0xFE09, ("VARIATION SELECTOR-9", "Can modify character appearance"));
    map.insert(0xFE0A, ("VARIATION SELECTOR-10", "Can modify character appearance"));
    map.insert(0xFE0B, ("VARIATION SELECTOR-11", "Can modify character appearance"));
    map.insert(0xFE0C, ("VARIATION SELECTOR-12", "Can modify character appearance"));
    map.insert(0xFE0D, ("VARIATION SELECTOR-13", "Can modify character appearance"));
    map.insert(0xFE0E, ("VARIATION SELECTOR-14", "Can modify character appearance"));
    map.insert(0xFE0F, ("VARIATION SELECTOR-15", "Can modify character appearance"));

    // Line/paragraph separators: can impact parsing/tokenization
    map.insert(0x2028, ("LINE SEPARATOR", "Can break parsing/tokenization"));
    map.insert(0x2029, ("PARAGRAPH SEPARATOR", "Can break parsing/tokenization"));

    // Frequently abused: render as blank in many fonts
    map.insert(0x3164, ("HANGUL FILLER", "Often renders as blank; used for obfuscation"));

    // Soft hyphen: invisible in many contexts
    map.insert(0x00AD, ("SOFT HYPHEN", "Invisible in most contexts; used for obfuscation"));

    // Non-breaking spaces that frequently cause “looks like space, isn’t space” issues
    map.insert(0x00A0, ("NO-BREAK SPACE", "Non-ASCII whitespace; may bypass naive filters"));
    map.insert(0x202F, ("NARROW NO-BREAK SPACE", "Non-ASCII whitespace; may bypass naive filters"));
    map.insert(0x2007, ("FIGURE SPACE", "Non-ASCII whitespace; may bypass naive filters"));

    map
}

/// Returns true if the code point is in one of the Unicode Private Use Area ranges.
fn is_private_use_area(code: u32) -> bool {
    (code >= 0xE000 && code <= 0xF8FF)
        || (code >= 0xF0000 && code <= 0xFFFD)
        || (code >= 0x100000 && code <= 0x10FFFD)
}

/// Returns true if the code point is a suspicious C0/C1 control character.
///
/// Excludes TAB (U+0009), LF (U+000A), and CR (U+000D) since they are common in text.
fn is_suspicious_control_char(code: u32) -> bool {
    (code <= 0x001F && code != 0x0009 && code != 0x000A && code != 0x000D)
        || (code >= 0x007F && code <= 0x009F)
}

/// Check if a path component matches a standard ignored directory.
fn is_ignored_component(component: &str) -> bool {
    matches!(
        component,
        "node_modules" | ".git" | ".cargo" | "target" | ".vscode"
    )
}

/// Check if a path should be ignored, using component-based matching to avoid false positives.
///
/// When `scan_bundles` is false, common build outputs are ignored. For VS Code extensions,
/// consider enabling `--scan-bundles` because the shipped JS often lives in `dist/` or `out/`.
fn should_ignore_path(path: &str, scan_bundles: bool) -> bool {
    // Split by both / and \ for Windows compatibility
    let components: Vec<&str> = path.split(|c| c == '/' || c == '\\').collect();

    for component in &components {
        if is_ignored_component(component) {
            return true;
        }
    }

    if !scan_bundles {
        for component in &components {
            if matches!(*component, "dist" | "build" | "out" | ".next" | ".nuxt") {
                return true;
            }
        }
    }

    false
}

/// Scan file content for suspicious invisible/formatting characters.
///
/// Uses `char_indices()` so `byte_offset` is always correct (no newline guessing).
/// `line` and `char_index` are computed with a simple `\n` line model.
fn detect_invisible_characters(content: &str, file_path: &str) -> Vec<Detection> {
    let suspicious = get_suspicious_chars();
    let mut detections = Vec::new();

    let mut line: usize = 1;        // 1-indexed
    let mut char_index: usize = 0;  // resets per line; incremented on non-newline chars

    for (byte_i, ch) in content.char_indices() {
        if ch == '\n' {
            line += 1;
            char_index = 0;
            continue;
        }

        char_index += 1;
        let code = ch as u32;

        let (name, description) = if let Some(&(n, d)) = suspicious.get(&code) {
            (n.to_string(), d.to_string())
        } else if is_private_use_area(code) {
            (
                "PRIVATE USE AREA".to_string(),
                format!(
                    "Private use character (U+{:04X}) - commonly used for payload hiding",
                    code
                ),
            )
        } else if is_suspicious_control_char(code) {
            (
                "CONTROL CHARACTER".to_string(),
                format!("Suspicious control character (U+{:04X})", code),
            )
        } else {
            continue;
        };

        detections.push(Detection {
            file: file_path.to_string(),
            line,
            byte_offset: byte_i + 1, // 1-indexed
            char_index,
            char: ch.to_string(),
            code,
            name,
            description,
        });
    }

    detections
}

/// Scan all files matched by a glob pattern.
fn scan_files(config: &ScanConfig) -> std::io::Result<(Vec<Detection>, usize, usize)> {
    let mut all_detections = Vec::new();
    let mut scanned_count = 0usize;
    let mut skipped_count = 0usize;

    let glob_results = glob(&config.pattern).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid glob pattern: {}", e),
        )
    })?;

    for entry in glob_results.flatten() {
        let path_str = entry.to_string_lossy();

        // Skip ignored paths
        if should_ignore_path(&path_str, config.scan_bundles) {
            skipped_count += 1;
            if config.verbose {
                eprintln!("  (ignored) {}", path_str);
            }
            continue;
        }

        scanned_count += 1;

        // Try to read file as UTF-8
        match fs::read_to_string(&entry) {
            Ok(content) => {
                let detections = detect_invisible_characters(&content, &path_str);
                all_detections.extend(detections);
            }
            Err(e) => {
                skipped_count += 1;
                if config.verbose {
                    eprintln!("Could not read {}: {}", path_str, e);
                }
            }
        }
    }

    if scanned_count == 0 && skipped_count == 0 {
        eprintln!("No files matched pattern: {}", config.pattern);
    }

    Ok((all_detections, scanned_count, skipped_count))
}

/// Format detections as human-readable text, sorted by file for deterministic output.
fn format_text_output(detections: &[Detection]) -> String {
    if detections.is_empty() {
        return "No suspicious invisible characters detected.".to_string();
    }

    let mut output = format!("Found {} suspicious character(s):\n\n", detections.len());
    let mut grouped: HashMap<&str, Vec<&Detection>> = HashMap::new();

    for detection in detections {
        grouped
            .entry(&detection.file)
            .or_insert_with(Vec::new)
            .push(detection);
    }

    let mut sorted_files: Vec<_> = grouped.keys().copied().collect();
    sorted_files.sort();

    for file in sorted_files {
        let dets = &grouped[file];
        output.push_str(&format!("{}\n", file));

        for d in dets {
            output.push_str(&format!(
                "    Line {}:{} (byte {}) - {} (U+{:04X})\n",
                d.line, d.char_index, d.byte_offset, d.name, d.code
            ));
            output.push_str(&format!("  {}\n", d.description));
        }
        output.push('\n');
    }

    output
}

/// Parse command-line arguments into config.
fn parse_args(args: &[String]) -> Option<ScanConfig> {
    if args.len() < 2 {
        return None;
    }

    if args[1] == "--help" || args[1] == "-h" {
        return None;
    }

    let pattern = args[1].clone();
    let json_output = args.iter().any(|a| a == "--json");
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    let fail_on_skip = args.iter().any(|a| a == "--fail-on-skip");
    let scan_bundles = args.iter().any(|a| a == "--scan-bundles");

    Some(ScanConfig {
        pattern,
        json_output,
        verbose,
        fail_on_skip,
        scan_bundles,
    })
}

/// Print help message.
fn print_help() {
    println!(
        r#"
Invisible Character Detector - Find suspicious Unicode in code

USAGE:
  invisible-char-detector [PATTERN] [OPTIONS]

EXAMPLES:
  invisible-char-detector "**/*.rs"
  invisible-char-detector "src/**/*.ts" --json
  invisible-char-detector "**/*.js" --verbose
  invisible-char-detector "**/*.tsx" --scan-bundles

OPTIONS:
  --json              Output results as JSON (for CI/tooling integration)
  --verbose, -v       Show details about ignored/unreadable files
  --scan-bundles      Include dist/, build/, out/ directories (useful for bundled extensions)
  --fail-on-skip      Exit with code 2 if any files cannot be read (strict mode)
  --help, -h          Show this help message

DETECTS:
  • Zero-width / joiners (U+200B, U+200C, U+200D, U+2060, U+FEFF)
  • Bidirectional controls (U+202A–U+202E, U+2066–U+2069)
  • Directional marks (U+200E, U+200F, U+061C)
  • Variation selectors (U+FE00–U+FE0F)
  • Line/paragraph separators (U+2028, U+2029)
  • Select non-ASCII whitespace (e.g., U+00A0, U+2007, U+202F)
  • Private Use Area characters
  • Suspicious control characters

EXIT CODES:
  0  No suspicious characters found
  1  Suspicious characters detected (fail in CI)
  2  Operational error (invalid pattern, read failure with --fail-on-skip)

"#
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let config = match parse_args(&args) {
        Some(cfg) => cfg,
        None => {
            print_help();
            process::exit(0);
        }
    };

    println!("Scanning files matching: {}", config.pattern);
    if config.verbose {
        println!(
            "Options: json={}, scan_bundles={}, fail_on_skip={}",
            config.json_output, config.scan_bundles, config.fail_on_skip
        );
    }

    let (detections, scanned, skipped) = match scan_files(&config) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error scanning files: {}", e);
            process::exit(2);
        }
    };

    if config.verbose {
        println!("Scanned: {} files, Skipped: {} files\n", scanned, skipped);
    }

    if config.json_output {
        match serde_json::to_string_pretty(&detections) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing to JSON: {}", e);
                process::exit(2);
            }
        }
    } else {
        println!("{}", format_text_output(&detections));
    }

    // Strict mode: treat any unreadable/ignored files as an operational failure.
    if config.fail_on_skip && skipped > 0 {
        eprintln!("{} files were skipped (--fail-on-skip enabled)", skipped);
        process::exit(2);
    }

    if !detections.is_empty() {
        process::exit(1);
    }
}
