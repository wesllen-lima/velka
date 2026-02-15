use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::unbounded;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::config::VelkaConfig;
use crate::domain::{Severity, Sin};
use crate::engine::quarantine;
use crate::engine::remediate;
use crate::engine::{investigate_with_progress, scan_history};

use super::widgets;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Findings,
    Detail,
    Entropy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Scanning,
    Done,
}

pub struct App {
    pub sins: Vec<Sin>,
    pub selected: usize,
    pub scroll_offset: usize,
    pub active_panel: Panel,
    pub detail_scroll: usize,
    pub scan_status: ScanStatus,
    pub show_help: bool,
    pub status_message: Option<(String, Instant)>,
    pub scan_path: PathBuf,
}

impl App {
    fn new(scan_path: PathBuf) -> Self {
        Self {
            sins: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            active_panel: Panel::Findings,
            detail_scroll: 0,
            scan_status: ScanStatus::Scanning,
            show_help: false,
            status_message: None,
            scan_path,
        }
    }

    pub fn selected_sin(&self) -> Option<&Sin> {
        self.sins.get(self.selected)
    }

    fn move_up(&mut self) {
        if self.active_panel == Panel::Detail {
            self.detail_scroll = self.detail_scroll.saturating_sub(1);
            return;
        }
        if self.selected > 0 {
            self.selected -= 1;
            self.detail_scroll = 0;
            if self.selected < self.scroll_offset {
                self.scroll_offset = self.selected;
            }
        }
    }

    fn move_down(&mut self, visible_rows: usize) {
        if self.active_panel == Panel::Detail {
            self.detail_scroll += 1;
            return;
        }
        if self.selected + 1 < self.sins.len() {
            self.selected += 1;
            self.detail_scroll = 0;
            if self.selected >= self.scroll_offset + visible_rows {
                self.scroll_offset = self.selected - visible_rows + 1;
            }
        }
    }

    fn set_status(&mut self, msg: String) {
        self.status_message = Some((msg, Instant::now()));
    }
}

pub fn run_tui(path: &Path, deep_scan: bool) -> Result<()> {
    let canonical = path.canonicalize()?;

    // Scan in background
    let config = Arc::new(VelkaConfig::load()?);
    let (sender, receiver) = unbounded::<Sin>();

    let scan_path = canonical.clone();
    let config_clone = Arc::clone(&config);
    let sender1 = sender.clone();
    std::thread::spawn(move || {
        let _ = investigate_with_progress(&scan_path, &config_clone, &sender1, false);
    });

    if deep_scan {
        let scan_path2 = canonical.clone();
        let config_git = Arc::clone(&config);
        let sender2 = sender.clone();
        std::thread::spawn(move || {
            let _ = scan_history(&scan_path2, &config_git, &sender2);
        });
    }

    drop(sender);

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(canonical);

    // Collect results with non-blocking poll
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();
    let mut scan_done = false;

    loop {
        // Drain available scan results
        if !scan_done {
            loop {
                match receiver.try_recv() {
                    Ok(sin) => app.sins.push(sin),
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        scan_done = true;
                        app.scan_status = ScanStatus::Done;
                        app.sins.sort_by(|a, b| {
                            b.severity
                                .cmp_priority()
                                .cmp(&a.severity.cmp_priority())
                                .then_with(|| a.path.cmp(&b.path))
                                .then_with(|| a.line_number.cmp(&b.line_number))
                        });
                        break;
                    }
                }
            }
        }

        // Clear expired status message
        if let Some((_, ts)) = &app.status_message {
            if ts.elapsed() > Duration::from_secs(3) {
                app.status_message = None;
            }
        }

        terminal.draw(|f| widgets::render(f, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                // Ctrl+C or q always quits
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }

                if app.show_help {
                    app.show_help = false;
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.move_down(terminal.size()?.height.saturating_sub(8) as usize);
                    }
                    KeyCode::Tab => {
                        app.active_panel = match app.active_panel {
                            Panel::Findings => Panel::Detail,
                            Panel::Detail => Panel::Entropy,
                            Panel::Entropy => Panel::Findings,
                        };
                    }
                    KeyCode::Enter => {
                        app.active_panel = Panel::Detail;
                        app.detail_scroll = 0;
                    }
                    KeyCode::Esc => {
                        app.active_panel = Panel::Findings;
                    }
                    KeyCode::Char('?') => {
                        app.show_help = true;
                    }
                    // Quick actions
                    KeyCode::Char('r') => {
                        if let Some(sin) = app.selected_sin() {
                            app.set_status(format!(
                                "Rotation guide: velka rotate --rule {}",
                                sin.rule_id
                            ));
                        }
                    }
                    KeyCode::Char('i') => {
                        if let Some(sin) = app.selected_sin() {
                            app.set_status(format!(
                                "To ignore: add '{}' to velka.toml [rules].disable",
                                sin.rule_id
                            ));
                        }
                    }
                    KeyCode::Char('m') => {
                        if let Some(sin) = app.selected_sin() {
                            app.set_status(format!(
                                "To migrate: velka scan --migrate-to-env (file: {})",
                                sin.path
                            ));
                        }
                    }
                    KeyCode::Char('Q') => {
                        if let Some(sin) = app.selected_sin() {
                            let file_path = std::path::PathBuf::from(&sin.path);
                            match quarantine::quarantine_file(&app.scan_path, &file_path) {
                                Ok(entry) => app.set_status(format!(
                                    "Quarantined: {} -> {}",
                                    sin.path,
                                    entry.quarantine_path.display()
                                )),
                                Err(e) => app.set_status(format!("Quarantine failed: {e}")),
                            }
                        }
                    }
                    KeyCode::Char('p') => {
                        if let Some(sin) = app.selected_sin().cloned() {
                            match remediate::inject_placeholder(&sin, false) {
                                Ok(res) if res.replaced => {
                                    app.set_status(format!(
                                        "Replaced secret with {} in {}:{}",
                                        res.placeholder, res.file_path, res.line_number
                                    ));
                                }
                                Ok(_) => app.set_status(
                                    "No replacement made (secret pattern not matched in line)"
                                        .to_string(),
                                ),
                                Err(e) => {
                                    app.set_status(format!("Placeholder injection failed: {e}"));
                                }
                            }
                        }
                    }
                    KeyCode::Char('v') => {
                        let providers = crate::engine::vault::detect_providers();
                        if providers.is_empty() {
                            app.set_status("No vault providers detected. Set VAULT_ADDR+VAULT_TOKEN or OP_VAULT.".to_string());
                        } else {
                            let names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
                            app.set_status(format!(
                                "Available vaults: {}. Use CLI for sync.",
                                names.join(", ")
                            ));
                        }
                    }
                    KeyCode::Char('e') => {
                        app.active_panel = Panel::Entropy;
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        app.selected = 0;
                        app.scroll_offset = 0;
                        app.detail_scroll = 0;
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        if !app.sins.is_empty() {
                            app.selected = app.sins.len() - 1;
                            let visible = terminal.size()?.height.saturating_sub(8) as usize;
                            app.scroll_offset =
                                app.selected.saturating_sub(visible.saturating_sub(1));
                        }
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

trait SeverityOrd {
    fn cmp_priority(&self) -> u8;
}

impl SeverityOrd for Severity {
    fn cmp_priority(&self) -> u8 {
        match self {
            Severity::Mortal => 1,
            Severity::Venial => 0,
        }
    }
}
