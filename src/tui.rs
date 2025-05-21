// src/tui.rs
use crate::error::{AppResult, TuiError, StoreError};
use crate::models::{PasswordStore, PasswordEntry};
use crate::store; // For load_store

use arboard; // For clipboard
use chrono::Utc; // For updating timestamps
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap, Clear},
};
use std::io::{stdout, Stdout};
use std::path::PathBuf;
use std::time::Duration;
use log;

const NUM_EDIT_FIELDS: usize = 4; // Service, Username, Password, Notes

#[derive(PartialEq, Debug, Clone)] 
pub enum InputMode {
    Normal,
    Editing, 
    EditingExisting { entry_id: String }, 
}

#[derive(Clone, Default)] 
struct EditingEntryData {
    service_name: String,
    username: String,
    password: String,
    notes: String,
}

pub struct App {
    should_quit: bool,
    password_store: Option<PasswordStore>,
    selected_entry_index: Option<usize>,
    list_state: ListState,
    master_password: String,
    store_filepath: PathBuf,
    app_status: String,
    input_mode: InputMode,
    current_input_value: String, 
    editing_field_index: usize, 
    editing_entry_data: EditingEntryData,
}

impl App {
    pub fn new() -> Self {
        App {
            should_quit: false,
            password_store: None,
            selected_entry_index: None,
            list_state: ListState::default(),
            master_password: "testpassword".to_string(), 
            store_filepath: PathBuf::from("passwords.enc"),
            app_status: "Initializing... Press 'a' to add, 'e' to edit, 'd' to delete, 'q' to quit.".to_string(),
            input_mode: InputMode::Normal,
            current_input_value: String::new(),
            editing_field_index: 0,
            editing_entry_data: EditingEntryData::default(),
        }
    }

    fn copy_to_clipboard(&mut self, content: String, field_name: &str) {
        match arboard::Clipboard::new() {
            Ok(mut clipboard) => {
                match clipboard.set_text(content.clone()) {
                    Ok(_) => {
                        self.app_status = format!("{} copied to clipboard!", field_name);
                        log::info!("Copied {} to clipboard.", field_name);
                    }
                    Err(err) => {
                        self.app_status = format!("Error copying {}: {}", field_name, err);
                        log::error!("Error setting clipboard text for {}: {}", field_name, err);
                    }
                }
            }
            Err(err) => {
                self.app_status = format!("Error initializing clipboard: {}", err);
                log::error!("Error initializing clipboard: {}", err);
            }
        }
    }

    pub fn on_key(&mut self, key_event: KeyEvent) { 
        log::debug!("Key event received: {:?}", key_event);
        let key_code = key_event.code; 

        match self.input_mode.clone() { 
            InputMode::Normal => {
                match key_code { 
                    KeyCode::Char('q') => {
                        self.should_quit = true;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        self.move_selection(1);
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.move_selection(-1);
                    }
                    KeyCode::Char('a') => { 
                        self.input_mode = InputMode::Editing;
                        log::info!("Switched to InputMode::Editing (New)");
                        self.editing_entry_data = EditingEntryData::default(); 
                        self.editing_field_index = 0;
                        self.load_current_input_from_field(); 
                        self.app_status = "Adding new entry... (Esc to cancel)".to_string();
                    }
                    KeyCode::Char('e') => { 
                        if let Some(selected_idx) = self.selected_entry_index {
                            if let Some(store) = &self.password_store {
                                if let Some(entry_to_edit) = store.entries.get(selected_idx).cloned() { 
                                    self.input_mode = InputMode::EditingExisting { entry_id: entry_to_edit.id.clone() };
                                    log::info!("Switched to InputMode::EditingExisting for entry_id: {}", entry_to_edit.id);
                                    self.editing_entry_data = EditingEntryData {
                                        service_name: entry_to_edit.service_name.clone(),
                                        username: entry_to_edit.username.clone(),
                                        password: entry_to_edit.password.clone(), 
                                        notes: entry_to_edit.notes.clone().unwrap_or_default(),
                                    };
                                    self.editing_field_index = 0;
                                    let service_name_clone = entry_to_edit.service_name.clone(); 
                                    self.load_current_input_from_field(); 
                                    self.app_status = format!("Editing '{}'... (Esc to cancel)", service_name_clone);
                                }
                            }
                        } else {
                            self.app_status = "No entry selected to edit.".to_string();
                        }
                    }
                    KeyCode::Char('d') => { 
                        if let Some(selected_idx) = self.selected_entry_index {
                            let mut entry_deleted = false;
                            let mut removed_service_name = String::new();

                            if let Some(store) = self.password_store.as_mut() {
                                if selected_idx < store.entries.len() {
                                    let removed_entry = store.entries.remove(selected_idx);
                                    removed_service_name = removed_entry.service_name.clone();
                                    entry_deleted = true;
                                    log::info!("Deleted entry '{}' (ID: {})", removed_service_name, removed_entry.id);
                                }
                            }

                            if entry_deleted {
                                self.save_store_to_file(); 
                                self.app_status = format!("Entry '{}' deleted.", removed_service_name);
                                if let Some(store) = &self.password_store { 
                                    if store.entries.is_empty() {
                                        self.selected_entry_index = None;
                                        self.list_state.select(None);
                                    } else if selected_idx >= store.entries.len() {
                                        self.selected_entry_index = Some(store.entries.len() - 1);
                                        self.list_state.select(self.selected_entry_index);
                                    } else {
                                        self.selected_entry_index = Some(selected_idx);
                                        self.list_state.select(self.selected_entry_index);
                                    }
                                } else { 
                                    self.selected_entry_index = None;
                                    self.list_state.select(None);
                                }
                            } else if self.password_store.is_some() && self.password_store.as_ref().unwrap().entries.is_empty() {
                                self.selected_entry_index = None;
                                self.list_state.select(None);
                            } else {
                                if self.password_store.is_none() || self.password_store.as_ref().unwrap().entries.is_empty() {
                                     self.app_status = "No entries to delete.".to_string();
                                }
                            }
                        } else {
                            self.app_status = "No entry selected to delete.".to_string();
                        }
                    }
                    KeyCode::Char('c') => { 
                        if let Some(selected_idx) = self.selected_entry_index {
                            if let Some(store) = &self.password_store {
                                if let Some(entry) = store.entries.get(selected_idx) {
                                    self.copy_to_clipboard(entry.username.clone(), "Username");
                                }
                            }
                        } else {
                            self.app_status = "No entry selected to copy username.".to_string();
                        }
                    }
                    KeyCode::Char('x') => { 
                        if let Some(selected_idx) = self.selected_entry_index {
                            if let Some(store) = &self.password_store {
                                if let Some(entry) = store.entries.get(selected_idx) {
                                    self.copy_to_clipboard(entry.password.clone(), "Password");
                                }
                            }
                        } else {
                            self.app_status = "No entry selected to copy password.".to_string();
                        }
                    }
                    _ => {} 
                }
            }
            InputMode::Editing | InputMode::EditingExisting { .. } => { 
                match key_code { 
                    KeyCode::Char(c) => {
                        self.current_input_value.push(c);
                    }
                    KeyCode::Backspace => {
                        self.current_input_value.pop();
                    }
                    KeyCode::Tab => {
                        self.store_current_input_to_field();
                        self.editing_field_index = (self.editing_field_index + 1) % NUM_EDIT_FIELDS;
                        self.load_current_input_from_field();
                    }
                    KeyCode::Enter => {
                        self.store_current_input_to_field();
                        if self.editing_field_index == NUM_EDIT_FIELDS - 1 { 
                            if self.editing_entry_data.service_name.is_empty() || self.editing_entry_data.username.is_empty() {
                                self.app_status = "Service Name and Username cannot be empty. (Esc to cancel, Tab to edit)".to_string();
                                if self.editing_entry_data.service_name.is_empty() { self.editing_field_index = 0; }
                                else { self.editing_field_index = 1; }
                                self.load_current_input_from_field();
                                return;
                            }

                            let current_mode_cloned = self.input_mode.clone(); 
                            match current_mode_cloned {
                                InputMode::Editing => { 
                                    let new_entry = PasswordEntry::new(
                                        self.editing_entry_data.service_name.clone(),
                                        self.editing_entry_data.username.clone(),
                                        self.editing_entry_data.password.clone(), 
                                        if self.editing_entry_data.notes.is_empty() { None } else { Some(self.editing_entry_data.notes.clone()) },
                                    );
                                    if let Some(store) = self.password_store.as_mut() {
                                        store.add_entry(new_entry.clone()); 
                                        log::info!("Added new entry for service: {}", new_entry.service_name);
                                        self.app_status = format!("Entry for '{}' added.", self.editing_entry_data.service_name);
                                    }
                                }
                                InputMode::EditingExisting { entry_id } => { 
                                    if let Some(store) = self.password_store.as_mut() {
                                        if let Some(entry_to_update) = store.entries.iter_mut().find(|e| e.id == entry_id) {
                                            entry_to_update.service_name = self.editing_entry_data.service_name.clone();
                                            entry_to_update.username = self.editing_entry_data.username.clone();
                                            entry_to_update.password = self.editing_entry_data.password.clone(); 
                                            entry_to_update.notes = if self.editing_entry_data.notes.is_empty() { None } else { Some(self.editing_entry_data.notes.clone()) };
                                            entry_to_update.updated_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                            log::info!("Updated entry for service: {} (ID: {})", entry_to_update.service_name, entry_id);
                                            let service_name_clone = entry_to_update.service_name.clone(); 
                                            self.app_status = format!("Entry '{}' updated.", service_name_clone);
                                        } else {
                                            log::error!("Failed to find entry with ID {} for update.", entry_id);
                                            self.app_status = "Error: Could not find entry to update.".to_string();
                                        }
                                    }
                                }
                                _ => {} 
                            }
                            
                            let success_status = self.app_status.clone(); 
                            self.save_store_to_file();
                            self.input_mode = InputMode::Normal;
                            log::info!("Switched to InputMode::Normal after saving entry.");
                            self.reset_editing_state();
                            self.app_status = format!("{} | (c) Copy User | (x) Copy Pass", success_status);

                        } else { 
                            self.editing_field_index = (self.editing_field_index + 1) % NUM_EDIT_FIELDS;
                            self.load_current_input_from_field();
                        }
                    }
                    KeyCode::Esc => {
                        let previous_status = match self.input_mode {
                            InputMode::Editing => "Add new entry cancelled.".to_string(),
                            InputMode::EditingExisting { .. } => "Edit entry cancelled.".to_string(),
                            _ => "".to_string(),
                        };
                        self.input_mode = InputMode::Normal;
                        log::info!("Switched to InputMode::Normal via Esc from editing mode.");
                        self.reset_editing_state();
                        self.app_status = format!("{} | (c) Copy User | (x) Copy Pass", previous_status);
                    }
                    _ => {}
                }
            }
        }
    }
    
    fn store_current_input_to_field(&mut self) {
        match self.editing_field_index {
            0 => self.editing_entry_data.service_name = self.current_input_value.clone(),
            1 => self.editing_entry_data.username = self.current_input_value.clone(),
            2 => self.editing_entry_data.password = self.current_input_value.clone(),
            3 => self.editing_entry_data.notes = self.current_input_value.clone(),
            _ => {}
        }
    }

    fn load_current_input_from_field(&mut self) {
        self.current_input_value = match self.editing_field_index {
            0 => self.editing_entry_data.service_name.clone(),
            1 => self.editing_entry_data.username.clone(),
            2 => self.editing_entry_data.password.clone(),
            3 => self.editing_entry_data.notes.clone(),
            _ => String::new(),
        };
    }

    fn reset_editing_state(&mut self) {
        self.editing_entry_data = EditingEntryData::default();
        self.current_input_value = String::new();
        self.editing_field_index = 0;
    }

    fn save_store_to_file(&mut self) {
        if let Some(store) = &self.password_store {
            match crate::store::save_store(store, &self.master_password, &self.store_filepath) {
                Ok(()) => {
                    log::info!("Store saved successfully to {:?}", self.store_filepath);
                }
                Err(e) => {
                    self.app_status = format!("Failed to save store: {}", e);
                    log::error!("Failed to save store: {}", e);
                }
            }
        } else {
            self.app_status = "Cannot save: No password store loaded.".to_string();
            log::warn!("Attempted to save store, but no store was loaded.");
        }
    }

    fn move_selection(&mut self, delta: i32) {
        if self.input_mode != InputMode::Normal { return; }

        if let Some(store) = &self.password_store {
            if store.entries.is_empty() {
                self.selected_entry_index = None;
                self.list_state.select(None);
                return;
            }
            
            let current_index = self.selected_entry_index.unwrap_or(0);
            let num_entries = store.entries.len();
            let mut new_index = current_index as i32 + delta;

            if new_index < 0 {
                new_index = 0;
            } else if new_index >= num_entries as i32 {
                new_index = num_entries as i32 - 1;
            }
            
            if num_entries > 0 { 
                 self.selected_entry_index = Some(new_index as usize);
                 self.list_state.select(self.selected_entry_index);
            } else {
                self.selected_entry_index = None;
                self.list_state.select(None);
            }
        }
    }

    fn load_initial_store(&mut self) {
        log::info!("Attempting to load store from: {:?}", self.store_filepath);
        let base_keys = "(q) Quit | (j/k) Nav | (a) Add | (e) Edit | (d) Del | (c) Copy User | (x) Copy Pass";
        match store::load_store(&self.master_password, &self.store_filepath) {
            Ok(store) => {
                let num_entries = store.entries.len();
                self.password_store = Some(store);
                if num_entries > 0 {
                    self.selected_entry_index = Some(0);
                    self.list_state.select(Some(0));
                    self.app_status = format!("Loaded {} entries. {}", num_entries, base_keys);
                    log::info!("Store loaded successfully with {} entries.", num_entries);
                } else {
                    self.selected_entry_index = None;
                    self.list_state.select(None);
                    self.app_status = format!("Store empty. {}", base_keys);
                    log::info!("Store loaded successfully, but it's empty.");
                }
            }
            Err(StoreError::Io(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                self.app_status = format!("Store file not found at {:?}. {}", self.store_filepath, base_keys);
                self.password_store = Some(PasswordStore::default()); 
                self.selected_entry_index = None;
                self.list_state.select(None);
                log::info!("Store file not found. Initialized with a new empty store.");
            }
            Err(e) => {
                self.app_status = format!("Error loading store: {}. Press 'q' to quit.", e);
                self.password_store = Some(PasswordStore::default());
                self.selected_entry_index = None;
                self.list_state.select(None);
                log::error!("Failed to load store: {}", e);
            }
        }
    }
}

pub fn run_tui() -> AppResult<()> {
    log::info!("Initializing TUI...");
    enable_raw_mode().map_err(|e| { log::error!("Failed to enable raw mode: {}", e); TuiError::Io(e) })?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| { log::error!("Failed to setup terminal screen: {}", e); TuiError::Io(e) })?;
    
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| { log::error!("Failed to create terminal: {}", e); TuiError::Io(e) })?;

    let mut app = App::new();
    app.load_initial_store(); 

    log::info!("Starting TUI application loop.");
    let res = run_app_loop(&mut terminal, &mut app);
    log::info!("TUI application loop finished.");

    disable_raw_mode().map_err(|e| { log::error!("Failed to disable raw mode: {}", e); TuiError::Io(e) })?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(|e| { log::error!("Failed to restore terminal screen: {}", e); TuiError::Io(e) })?;
    
    if let Err(err) = res {
        return Err(err.into()); 
    }
    
    log::info!("TUI shutdown complete.");
    Ok(())
}

fn run_app_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<(), TuiError> {
    while !app.should_quit {
        terminal.draw(|f| ui(f, app)).map_err(|e| { log::error!("Terminal draw error: {}", e); TuiError::Io(e) })?;

        if event::poll(Duration::from_millis(100)).map_err(|e| { log::error!("Event poll error: {}", e); TuiError::Io(e) })? {
            if let Event::Key(key_event) = event::read().map_err(|e| { log::error!("Event read error: {}", e); TuiError::Io(e) })? {
                if key_event.kind == KeyEventKind::Press {
                    app.on_key(key_event); // Pass the full KeyEvent
                }
            }
        }
    }
    Ok(())
}

fn draw_main_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
        .split(f.size());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
        .split(chunks[0]);

    let list_area = main_chunks[0];
    let detail_area = main_chunks[1];
    let status_bar_area = chunks[1]; 

    // Entry List Area
    let entries_block_title = format!("Entries ({})", app.password_store.as_ref().map_or(0, |s| s.entries.len()));
    let entries_block = Block::default().borders(Borders::ALL).title(entries_block_title);
    
    if let Some(store) = &app.password_store {
        if !store.entries.is_empty() {
            let list_items: Vec<ListItem> = store.entries.iter()
                .map(|entry| ListItem::new(Span::raw(format!("{} - {}", entry.service_name, entry.username))))
                .collect();
            let list = List::new(list_items)
                .block(entries_block)
                .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::Gray))
                .highlight_symbol("> ");
            f.render_stateful_widget(list, list_area, &mut app.list_state);
        } else {
            let no_entries_text = Paragraph::new("No entries found.")
                .block(entries_block.clone()).alignment(Alignment::Center).wrap(Wrap { trim: true });
            f.render_widget(no_entries_text, list_area);
        }
    } else {
        let store_not_loaded_text = Paragraph::new("Store not loaded.")
            .block(entries_block.clone()).alignment(Alignment::Center).wrap(Wrap { trim: true });
        f.render_widget(store_not_loaded_text, list_area);
    }

    // Detail View Area
    let details_block = Block::default().borders(Borders::ALL).title("Details");
    if let Some(selected_idx) = app.selected_entry_index {
        if let Some(store) = &app.password_store {
            if let Some(entry) = store.entries.get(selected_idx) {
                let detail_text = vec![
                    Line::from(vec![Span::styled("Service: ", Style::default().bold()), Span::raw(&entry.service_name)]),
                    Line::from(vec![Span::styled("Username: ", Style::default().bold()), Span::raw(&entry.username)]),
                    Line::from(vec![Span::styled("Password: ", Style::default().bold()), Span::raw("********")]),
                    Line::from(vec![Span::styled("Notes: ", Style::default().bold()), Span::raw(entry.notes.as_deref().unwrap_or(""))]),
                    Line::from(vec![Span::styled("Created: ", Style::default().bold()), Span::raw(&entry.created_at)]),
                    Line::from(vec![Span::styled("Updated: ", Style::default().bold()), Span::raw(&entry.updated_at)]),
                ];
                let details_paragraph = Paragraph::new(detail_text).block(details_block).wrap(Wrap { trim: true });
                f.render_widget(details_paragraph, detail_area);
            } else {
                let text = Paragraph::new("Selected entry out of bounds.").block(details_block).alignment(Alignment::Center);
                f.render_widget(text, detail_area);
            }
        }
    } else {
        let text = Paragraph::new("Select an entry to see details.").block(details_block).alignment(Alignment::Center);
        f.render_widget(text, detail_area);
    }
    
    // Status Bar
    let status_text = if app.input_mode == InputMode::Normal {
        let base_keys = "(q) Quit | (j/k) Nav | (a) Add | (e) Edit | (d) Del";
        if app.selected_entry_index.is_some() {
            format!("{} | {} | (c) Copy User | (x) Copy Pass", app.app_status, base_keys)
        } else {
            format!("{} | {}", app.app_status, base_keys)
        }
    } else {
        app.app_status.clone() 
    };
    let status_paragraph = Paragraph::new(status_text).block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status_paragraph, status_bar_area); 
}

fn draw_editing_form(f: &mut Frame, app: &App) {
    let form_title = match app.input_mode {
        InputMode::Editing => "Add New Password Entry",
        InputMode::EditingExisting { .. } => "Edit Password Entry",
        _ => "Form", 
    };

    let form_area = centered_rect(60, 25, f.size()); 
    f.render_widget(Clear, form_area); 

    let form_block = Block::default().title(form_title).borders(Borders::ALL);
    f.render_widget(form_block, form_area);

    let form_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2) 
        .constraints([
            Constraint::Length(3), 
            Constraint::Length(3), 
            Constraint::Length(3), 
            Constraint::Length(3), 
            Constraint::Min(1),    
            Constraint::Length(1), 
        ].as_ref())
        .split(form_area);

    let field_labels = ["Service:", "Username:", "Password:", "Notes:"];
    
    for i in 0..NUM_EDIT_FIELDS {
        let field_text_value = match i {
            0 => &app.editing_entry_data.service_name,
            1 => &app.editing_entry_data.username,
            2 => &app.editing_entry_data.password,
            3 => &app.editing_entry_data.notes,
            _ => unreachable!(),
        };

        let current_text_to_display = if app.editing_field_index == i {
            format!("{}▋", app.current_input_value) 
        } else {
            field_text_value.clone() 
        };
        
        let paragraph = Paragraph::new(current_text_to_display)
            .block(Block::default().borders(Borders::ALL).title(field_labels[i]))
            .style(if app.editing_field_index == i { Style::default().fg(Color::Yellow) } else { Style::default() });
        f.render_widget(paragraph, form_chunks[i]);
    }
    
    let help_text = "(Tab) Next | (Enter) Next/Save | (Esc) Cancel";
    let help_paragraph = Paragraph::new(help_text).alignment(Alignment::Center);
    f.render_widget(help_paragraph, form_chunks[NUM_EDIT_FIELDS + 1]);
}

/// Renders the UI widgets based on the application mode.
fn ui(f: &mut Frame, app: &mut App) {
    match app.input_mode {
        InputMode::Normal => {
            draw_main_ui(f, app);
        }
        InputMode::Editing | InputMode::EditingExisting { .. } => {
            draw_main_ui(f, app); 
            draw_editing_form(f, app);
        }
    }
}

/// Helper to create a centered rect for popups.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
