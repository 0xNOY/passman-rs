// src/tui.rs
use crate::error::{AppResult, TuiError, StoreError};
use crate::models::{PasswordStore, PasswordEntry};
use crate::store; 
use crate::generator::{self, PasswordCriteria}; // Import generator module

use arboard; 
use chrono::Utc; 
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind}, // Added KeyModifiers
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::Position, 
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap, Clear},
};
use std::io::{stdout, Stdout};
use std::path::PathBuf;
use std::time::Duration;
use log;

const NUM_EDIT_FIELDS: usize = 4; 
const NUM_GENERATOR_FIELDS: usize = 7; // Length, 4 toggles, Generate btn, Use Pass btn

#[derive(PartialEq, Debug, Clone)] 
pub enum InputMode {
    Normal,
    Editing, 
    EditingExisting { entry_id: String }, 
    Searching,
    GeneratingPassword { previous_mode: Box<InputMode> }, // Stores the mode to return to
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
    list_state: ListState,
    master_password: String,
    store_filepath: PathBuf,
    app_status: String,
    input_mode: InputMode,
    current_input_value: String, 
    editing_field_index: usize, 
    editing_entry_data: EditingEntryData,
    list_area_rect: Rect,
    detail_area_rect: Rect,
    status_area_rect: Rect,
    form_field_rects: Vec<Rect>,
    show_help: bool,
    search_query: String,
    filtered_entries_indices: Option<Vec<usize>>, 
    selected_list_display_index: Option<usize>, 

    // Password Generator State
    password_criteria: PasswordCriteria,
    generated_password: Option<String>,
    generator_focused_field: usize, // 0:Length, 1:Uppercase, 2:Lowercase, 3:Numbers, 4:Symbols, 5:Generate, 6:Use Password
}

impl App {
    pub fn new() -> Self {
        App {
            should_quit: false,
            password_store: None,
            selected_list_display_index: None,
            list_state: ListState::default(),
            master_password: "testpassword".to_string(), 
            store_filepath: PathBuf::from("passwords.enc"),
            app_status: "Initializing... Press 'h' for help, 'q' to quit.".to_string(),
            input_mode: InputMode::Normal,
            current_input_value: String::new(),
            editing_field_index: 0,
            editing_entry_data: EditingEntryData::default(),
            list_area_rect: Rect::default(),
            detail_area_rect: Rect::default(),
            status_area_rect: Rect::default(),
            form_field_rects: vec![Rect::default(); NUM_EDIT_FIELDS],
            show_help: false,
            search_query: String::new(),
            filtered_entries_indices: None,
            // Generator state
            password_criteria: PasswordCriteria::default(),
            generated_password: None,
            generator_focused_field: 0,
        }
    }
    
    fn get_currently_selected_original_index(&self) -> Option<usize> {
        self.selected_list_display_index.and_then(|display_idx| {
            if let Some(filtered_indices) = &self.filtered_entries_indices {
                filtered_indices.get(display_idx).copied()
            } else {
                if self.password_store.as_ref().map_or(false, |s| display_idx < s.entries.len()) {
                    Some(display_idx)
                } else {
                    None
                }
            }
        })
    }

    fn update_filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_entries_indices = None;
            log::debug!("Search query is empty, filter cleared.");
        } else {
            log::debug!("Updating filter with query: '{}'", self.search_query);
            let query = self.search_query.to_lowercase();
            let mut indices = Vec::new();
            if let Some(store) = &self.password_store {
                for (i, entry) in store.entries.iter().enumerate() {
                    if entry.service_name.to_lowercase().contains(&query) || 
                       entry.username.to_lowercase().contains(&query) ||
                       entry.notes.as_ref().map_or(false, |n| n.to_lowercase().contains(&query)) {
                        indices.push(i);
                    }
                }
            }
            self.filtered_entries_indices = Some(indices);
            log::debug!("Filter updated, found indices: {:?}", self.filtered_entries_indices);
        }

        let displayed_item_count = self.get_displayed_entry_count();
        if displayed_item_count > 0 {
            self.selected_list_display_index = Some(0);
            self.list_state.select(Some(0));
        } else {
            self.selected_list_display_index = None;
            self.list_state.select(None);
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
    
    pub fn handle_event(&mut self, event: Event) {
        if self.show_help {
            if let Event::Key(key_event) = event {
                 if key_event.kind == KeyEventKind::Press {
                    match key_event.code {
                        KeyCode::Char('h') | KeyCode::Char('?') | KeyCode::Esc => {
                            self.show_help = false;
                            self.app_status = "Help closed.".to_string();
                            log::info!("Help popup closed.");
                        }
                        _ => {} 
                    }
                }
            }
            return; 
        }

        match event {
            Event::Key(key_event) => self.handle_key_event(key_event),
            Event::Mouse(mouse_event) => self.handle_mouse_event(mouse_event),
            _ => {} 
        }
    }

    fn handle_mouse_event(&mut self, mouse_event: MouseEvent) {
        if self.show_help { return; } 

        log::debug!("Mouse event received: {:?}", mouse_event);
        match mouse_event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let (col, row) = (mouse_event.column, mouse_event.row);
                match self.input_mode {
                    InputMode::Normal | InputMode::Searching => { 
                        if self.list_area_rect.contains(Position { x: col, y: row }) {
                            let displayed_count = self.get_displayed_entry_count();
                            if displayed_count > 0 {
                                let list_content_start_y = self.list_area_rect.y + 1; 
                                if row >= list_content_start_y {
                                    let clicked_index_in_view = (row - list_content_start_y) as usize;
                                    let actual_display_index = self.list_state.offset().saturating_add(clicked_index_in_view);

                                    if actual_display_index < displayed_count {
                                        self.selected_list_display_index = Some(actual_display_index);
                                        self.list_state.select(Some(actual_display_index));
                                        log::info!("Mouse selected display index: {}", actual_display_index);
                                         if self.input_mode == InputMode::Searching { 
                                            self.input_mode = InputMode::Normal;
                                            let result_count = self.filtered_entries_indices.as_ref().map_or(0, |v| v.len());
                                            self.app_status = format!("Filter active: '{}' ({} results). (Esc) to clear, (/) to edit.", self.search_query, result_count);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    InputMode::Editing | InputMode::EditingExisting { .. } => {
                        for (i, &field_rect) in self.form_field_rects.iter().enumerate() {
                            if field_rect.contains(Position { x: col, y: row }) {
                                if self.editing_field_index != i { 
                                    self.store_current_input_to_field(); 
                                    self.editing_field_index = i;
                                    self.load_current_input_from_field(); 
                                    log::info!("Mouse activated editing field index: {}", i);
                                }
                                break;
                            }
                        }
                    }
                    InputMode::GeneratingPassword { .. } => { /* Mouse clicks on generator popup could be added here */ }
                }
            }
            MouseEventKind::ScrollUp => {
                if (self.input_mode == InputMode::Normal || self.input_mode == InputMode::Searching) && 
                   self.list_area_rect.contains(Position { x: mouse_event.column, y: mouse_event.row }) {
                    self.move_selection(-1);
                    log::debug!("Mouse scrolled up in list area.");
                }
            }
            MouseEventKind::ScrollDown => {
                 if (self.input_mode == InputMode::Normal || self.input_mode == InputMode::Searching) && 
                    self.list_area_rect.contains(Position { x: mouse_event.column, y: mouse_event.row }) {
                    self.move_selection(1);
                    log::debug!("Mouse scrolled down in list area.");
                }
            }
            _ => {} 
        }
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) { 
        log::debug!("Key event: {:?}, mode: {:?}", key_event, self.input_mode);
        let key_code = key_event.code; 
        let modifiers = key_event.modifiers;

        match self.input_mode.clone() { 
            InputMode::Normal => {
                match key_code { 
                    KeyCode::Char('q') => self.should_quit = true,
                    KeyCode::Char('h') | KeyCode::Char('?') => {
                        self.show_help = true;
                        self.app_status = "Displaying help... (Press h, ?, or Esc to close)".to_string();
                        log::info!("Help popup shown.");
                    }
                    KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
                    KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
                    KeyCode::Char('a') => { 
                        self.input_mode = InputMode::Editing;
                        log::info!("Switched to InputMode::Editing (New)");
                        self.editing_entry_data = EditingEntryData::default(); 
                        self.editing_field_index = 0;
                        self.load_current_input_from_field(); 
                        self.app_status = "Adding new entry... (Esc to cancel, Enter to save, Ctrl+g for Generator)".to_string();
                    }
                    KeyCode::Char('e') => { 
                        if let Some(original_idx) = self.get_currently_selected_original_index() {
                            if let Some(store) = &self.password_store {
                                if let Some(entry_to_edit) = store.entries.get(original_idx).cloned() { 
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
                                    self.app_status = format!("Editing '{}'... (Esc to cancel, Enter to save, Ctrl+g for Generator)", service_name_clone);
                                }
                            }
                        } else {
                            self.app_status = "No entry selected to edit.".to_string();
                        }
                    }
                    KeyCode::Char('d') => { 
                        if let Some(original_idx) = self.get_currently_selected_original_index() {
                             if let Some(store) = self.password_store.as_mut() {
                                if original_idx < store.entries.len() {
                                    let removed_entry = store.entries.remove(original_idx);
                                    log::info!("Deleted entry '{}' (ID: {})", removed_entry.service_name, removed_entry.id);
                                    self.save_store_to_file(); 
                                    self.app_status = format!("Entry '{}' deleted.", removed_entry.service_name);
                                    self.update_filter(); 
                                }
                            }
                        } else {
                            self.app_status = "No entry selected to delete.".to_string();
                        }
                    }
                    KeyCode::Char('c') => { 
                        if let Some(original_idx) = self.get_currently_selected_original_index() {
                            if let Some(entry) = self.password_store.as_ref().and_then(|s| s.entries.get(original_idx)) {
                                self.copy_to_clipboard(entry.username.clone(), "Username");
                            }
                        } else {
                            self.app_status = "No entry selected to copy username.".to_string();
                        }
                    }
                    KeyCode::Char('x') => { 
                        if let Some(original_idx) = self.get_currently_selected_original_index() {
                             if let Some(entry) = self.password_store.as_ref().and_then(|s| s.entries.get(original_idx)) {
                                self.copy_to_clipboard(entry.password.clone(), "Password");
                            }
                        } else {
                            self.app_status = "No entry selected to copy password.".to_string();
                        }
                    }
                    KeyCode::Char('/') => {
                        self.input_mode = InputMode::Searching;
                        self.app_status = format!("Search: {}▋", self.search_query);
                        log::info!("Switched to InputMode::Searching. Query: '{}'", self.search_query);
                    }
                    KeyCode::Esc => { 
                        if self.filtered_entries_indices.is_some() {
                            self.search_query.clear();
                            self.update_filter(); 
                            self.app_status = "Filter cleared.".to_string();
                            log::info!("Search filter cleared via Esc in Normal mode.");
                        }
                    }
                    _ => {} 
                }
            }
            InputMode::Searching => {
                match key_code {
                    KeyCode::Char(c) => {
                        self.search_query.push(c);
                        self.update_filter();
                        self.app_status = format!("Search: {}▋", self.search_query);
                    }
                    KeyCode::Backspace => {
                        self.search_query.pop();
                        self.update_filter();
                        self.app_status = format!("Search: {}▋", self.search_query);
                         if self.search_query.is_empty() { 
                            self.app_status = "Search: ▋".to_string();
                        }
                    }
                    KeyCode::Enter => {
                        self.input_mode = InputMode::Normal;
                        if self.search_query.is_empty() {
                             self.app_status = "Search cleared.".to_string();
                        } else {
                            let result_count = self.filtered_entries_indices.as_ref().map_or(0, |v| v.len());
                            self.app_status = format!("Filter active: '{}' ({} results). (Esc) to clear, (/) to edit.", self.search_query, result_count);
                        }
                        log::info!("Exited InputMode::Searching to Normal. Filter query: '{}'", self.search_query);
                    }
                    KeyCode::Esc => {
                        self.input_mode = InputMode::Normal;
                        self.search_query.clear();
                        self.update_filter(); 
                        self.app_status = "Search cancelled.".to_string();
                        log::info!("Cancelled InputMode::Searching to Normal. Filter cleared.");
                    }
                    KeyCode::Up => self.move_selection(-1),
                    KeyCode::Down => self.move_selection(1),
                    _ => {}
                }
            }
            InputMode::Editing | InputMode::EditingExisting { .. } => { 
                if key_code == KeyCode::Char('g') && modifiers == KeyModifiers::CONTROL {
                    self.input_mode = InputMode::GeneratingPassword { previous_mode: Box::new(self.input_mode.clone()) };
                    self.password_criteria = PasswordCriteria::default(); // Reset to defaults
                    self.generated_password = None;
                    self.generator_focused_field = 0; // Focus length initially
                    self.app_status = "Password Generator (Ctrl+g to close, 'g' to gen, 'u' to use)".to_string();
                    log::info!("Switched to InputMode::GeneratingPassword");
                    return;
                }
                match key_code { 
                    KeyCode::Char(c) => self.current_input_value.push(c),
                    KeyCode::Backspace => { self.current_input_value.pop(); },
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
                                        self.update_filter(); 
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
                                            self.update_filter(); 
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
                            self.app_status = format!("{} | (h) Help", success_status);
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
                        self.app_status = format!("{} | (h) Help", previous_status);
                    }
                    _ => {}
                }
            }
            InputMode::GeneratingPassword { ref previous_mode } => {
                 match key_code {
                    KeyCode::Up => self.generator_focused_field = if self.generator_focused_field == 0 { NUM_GENERATOR_FIELDS - 1 } else { self.generator_focused_field - 1 },
                    KeyCode::Down => self.generator_focused_field = (self.generator_focused_field + 1) % NUM_GENERATOR_FIELDS,
                    KeyCode::Left if self.generator_focused_field == 0 => { // Length
                        if self.password_criteria.length > 8 { self.password_criteria.length -= 1; self.generated_password = None; }
                    }
                    KeyCode::Right if self.generator_focused_field == 0 => { // Length
                        if self.password_criteria.length < 128 { self.password_criteria.length += 1; self.generated_password = None; }
                    }
                    KeyCode::Char(' ') | KeyCode::Enter if self.generator_focused_field > 0 && self.generator_focused_field < 5 => { // Toggles
                        match self.generator_focused_field {
                            1 => self.password_criteria.use_uppercase = !self.password_criteria.use_uppercase,
                            2 => self.password_criteria.use_lowercase = !self.password_criteria.use_lowercase,
                            3 => self.password_criteria.use_numbers = !self.password_criteria.use_numbers,
                            4 => self.password_criteria.use_symbols = !self.password_criteria.use_symbols,
                            _ => {}
                        }
                        self.generated_password = None; // Clear old password on criteria change
                    }
                    KeyCode::Char('g') | KeyCode::Enter if self.generator_focused_field == 5 => { // Generate button
                        match generator::generate_password(&self.password_criteria) {
                            Ok(pass) => {
                                self.generated_password = Some(pass.clone());
                                self.app_status = format!("Generated: {} (u to use, Esc to cancel)", pass);
                            }
                            Err(e) => {
                                self.generated_password = None;
                                self.app_status = format!("Error: {}", e);
                            }
                        }
                    }
                    KeyCode::Char('u') | KeyCode::Enter if self.generator_focused_field == 6 => { // Use Password button
                        if let Some(ref pass) = self.generated_password {
                            self.editing_entry_data.password = pass.clone();
                            self.current_input_value = pass.clone(); // Update current input for the password field
                            self.input_mode = *previous_mode.clone(); // Restore previous mode
                            self.editing_field_index = 2; // Ensure password field is focused
                            self.app_status = "Password copied from generator to form.".to_string();
                            log::info!("Used generated password. Switched back to {:?}", self.input_mode);
                        } else {
                            self.app_status = "No password generated yet to use. (g to generate)".to_string();
                        }
                    }
                     KeyCode::Char('g') if key_event.modifiers == KeyModifiers::CONTROL => { // Ctrl+G to close generator
                        self.input_mode = *previous_mode.clone();
                        self.app_status = "Password generator closed.".to_string();
                        log::info!("Password generator closed via Ctrl+G. Switched back to {:?}", self.input_mode);
                    }
                    KeyCode::Esc => {
                        self.input_mode = *previous_mode.clone();
                        self.app_status = "Password generator cancelled.".to_string();
                        log::info!("Password generator cancelled via Esc. Switched back to {:?}", self.input_mode);
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
                Ok(()) => { log::info!("Store saved successfully to {:?}", self.store_filepath); }
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
    
    fn get_displayed_entry_count(&self) -> usize {
        if let Some(indices) = &self.filtered_entries_indices {
            indices.len()
        } else {
            self.password_store.as_ref().map_or(0, |s| s.entries.len())
        }
    }

    fn move_selection(&mut self, delta: i32) {
        if self.input_mode != InputMode::Normal && self.input_mode != InputMode::Searching { return; }

        let count = self.get_displayed_entry_count();
        if count == 0 {
            self.selected_list_display_index = None;
            self.list_state.select(None);
            return;
        }
        
        let current_display_idx = self.selected_list_display_index.unwrap_or(0);
        let mut new_display_idx = current_display_idx as i32 + delta;

        if new_display_idx < 0 {
            new_display_idx = 0;
        } else if new_display_idx >= count as i32 {
            new_display_idx = count as i32 - 1;
        }
        
        self.selected_list_display_index = Some(new_display_idx as usize);
        self.list_state.select(self.selected_list_display_index);
        log::debug!("Selection moved to display index: {}", new_display_idx);
    }

    fn load_initial_store(&mut self) {
        log::info!("Attempting to load store from: {:?}", self.store_filepath);
        let base_keys = "(q) Quit | (/) Search | (j/k) Nav | (a) Add | (e) Edit | (d) Del | (c) Copy User | (x) Copy Pass | (h) Help";
        match store::load_store(&self.master_password, &self.store_filepath) {
            Ok(store) => {
                let num_entries = store.entries.len();
                self.password_store = Some(store);
                if num_entries > 0 {
                    self.selected_list_display_index = Some(0); 
                    self.list_state.select(Some(0));
                    self.app_status = format!("Loaded {} entries. {}", num_entries, base_keys);
                    log::info!("Store loaded successfully with {} entries.", num_entries);
                } else {
                    self.selected_list_display_index = None;
                    self.list_state.select(None);
                    self.app_status = format!("Store empty. {}", base_keys);
                    log::info!("Store loaded successfully, but it's empty.");
                }
            }
            Err(StoreError::Io(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                self.app_status = format!("Store file not found at {:?}. {}", self.store_filepath, base_keys);
                self.password_store = Some(PasswordStore::default()); 
                self.selected_list_display_index = None;
                self.list_state.select(None);
                log::info!("Store file not found. Initialized with a new empty store.");
            }
            Err(e) => {
                self.app_status = format!("Error loading store: {}. Press 'q' to quit.", e);
                self.password_store = Some(PasswordStore::default());
                self.selected_list_display_index = None;
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
            let event = event::read().map_err(|e| { log::error!("Event read error: {}", e); TuiError::Io(e)})?;
            app.handle_event(event); 
        }
    }
    Ok(())
}

fn draw_main_ui(f: &mut Frame, app: &mut App) { 
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
        .split(f.size());

    app.status_area_rect = chunks[1]; 

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
        .split(chunks[0]);

    app.list_area_rect = main_chunks[0]; 
    app.detail_area_rect = main_chunks[1]; 
    
    let entries_block_title = format!("Entries ({})", app.get_displayed_entry_count());
    let entries_block = Block::default().borders(Borders::ALL).title(entries_block_title);
    
    let mut list_items_content: Vec<ListItem> = Vec::new();
    
    if let Some(store) = &app.password_store {
        if let Some(filtered_indices) = &app.filtered_entries_indices {
            if filtered_indices.is_empty() {
                 list_items_content.push(ListItem::new("No matching entries found."));
            } else {
                for &original_idx in filtered_indices {
                    if let Some(entry) = store.entries.get(original_idx) {
                        list_items_content.push(ListItem::new(Span::raw(format!("{} - {}", entry.service_name, entry.username))));
                    }
                }
            }
        } else { 
            if store.entries.is_empty() {
                list_items_content.push(ListItem::new("No entries found."));
            } else {
                for entry in &store.entries {
                    list_items_content.push(ListItem::new(Span::raw(format!("{} - {}", entry.service_name, entry.username))));
                }
            }
        }
    } else { 
         list_items_content.push(ListItem::new("Store not loaded or error during loading."));
    }
    
    let list_widget = List::new(list_items_content)
        .block(entries_block)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::Gray))
        .highlight_symbol("> ");
    f.render_stateful_widget(list_widget, app.list_area_rect, &mut app.list_state);


    let details_block = Block::default().borders(Borders::ALL).title("Details");
    if let Some(original_idx) = app.get_currently_selected_original_index() {
        if let Some(store) = &app.password_store {
            if let Some(entry) = store.entries.get(original_idx) {
                let detail_text = vec![
                    Line::from(vec![Span::styled("Service: ", Style::default().bold()), Span::raw(&entry.service_name)]),
                    Line::from(vec![Span::styled("Username: ", Style::default().bold()), Span::raw(&entry.username)]),
                    Line::from(vec![Span::styled("Password: ", Style::default().bold()), Span::raw("********")]),
                    Line::from(vec![Span::styled("Notes: ", Style::default().bold()), Span::raw(entry.notes.as_deref().unwrap_or(""))]),
                    Line::from(vec![Span::styled("Created: ", Style::default().bold()), Span::raw(&entry.created_at)]),
                    Line::from(vec![Span::styled("Updated: ", Style::default().bold()), Span::raw(&entry.updated_at)]),
                ];
                let details_paragraph = Paragraph::new(detail_text).block(details_block).wrap(Wrap { trim: true });
                f.render_widget(details_paragraph, app.detail_area_rect);
            } else {
                let text = Paragraph::new("Selected entry out of bounds.").block(details_block).alignment(Alignment::Center);
                f.render_widget(text, app.detail_area_rect);
            }
        }
    } else {
        let text = Paragraph::new("Select an entry to see details.").block(details_block).alignment(Alignment::Center);
        f.render_widget(text, app.detail_area_rect);
    }
    
    let status_text = match app.input_mode {
        InputMode::Normal => {
            let base_keys = "(q) Quit | (/) Search | (j/k/↑/↓/Scroll) Nav | (a) Add | (e) Edit | (d) Del | (h) Help";
            if app.get_currently_selected_original_index().is_some() { 
                format!("{} | {} | (c) Copy User | (x) Copy Pass", app.app_status, base_keys)
            } else {
                format!("{} | {}", app.app_status, base_keys)
            }
        }
        InputMode::Searching => {
            format!("Search: {}▋ | (Enter) Apply Filter | (Esc) Cancel Search | (↑/↓) Nav Results", app.search_query)
        }
        InputMode::Editing | InputMode::EditingExisting { .. } => {
             format!("{} | (Ctrl+g) Password Gen", app.app_status)
        }
        InputMode::GeneratingPassword { .. } => {
             app.app_status.clone()
        }
    };
    let status_paragraph = Paragraph::new(status_text).block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status_paragraph, app.status_area_rect); 
}

fn draw_editing_form(f: &mut Frame, app: &mut App) { 
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

    app.form_field_rects.clear();
    for i in 0..NUM_EDIT_FIELDS {
        app.form_field_rects.push(form_chunks[i]);
    }
    
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
        f.render_widget(paragraph, app.form_field_rects[i]);
    }
    
    let help_text = "(Tab) Next | (Enter) Save | (Esc) Cancel | (Ctrl+g) Gen Pass (in Pass field)";
    let help_paragraph = Paragraph::new(help_text).alignment(Alignment::Center);
    f.render_widget(help_paragraph, form_chunks[NUM_EDIT_FIELDS + 1]);
}

fn draw_password_generator_popup(f: &mut Frame, app: &App) {
    let popup_area = centered_rect(60, 50, f.size());
    f.render_widget(Clear, popup_area);
    let block = Block::default().title("Password Generator").borders(Borders::ALL);
    f.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(1), // Length
            Constraint::Length(1), // Uppercase
            Constraint::Length(1), // Lowercase
            Constraint::Length(1), // Numbers
            Constraint::Length(1), // Symbols
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Generated Password (if any)
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Generate button
            Constraint::Length(1), // Use Password button
            Constraint::Min(1),    // Spacer
            Constraint::Length(1), // Help text
        ].as_ref())
        .split(popup_area);

    let length_text = format!("Length: < {} >", app.password_criteria.length);
    let length_style = if app.generator_focused_field == 0 { Style::default().fg(Color::Yellow) } else { Style::default() };
    f.render_widget(Paragraph::new(length_text).style(length_style), chunks[0]);

    let toggles = [
        (app.password_criteria.use_uppercase, "Uppercase"),
        (app.password_criteria.use_lowercase, "Lowercase"),
        (app.password_criteria.use_numbers, "Numbers"),
        (app.password_criteria.use_symbols, "Symbols"),
    ];
    for (i, (enabled, label)) in toggles.iter().enumerate() {
        let text = format!("[{}] {}", if *enabled { "x" } else { " " }, label);
        let style = if app.generator_focused_field == i + 1 { Style::default().fg(Color::Yellow) } else { Style::default() };
        f.render_widget(Paragraph::new(text).style(style), chunks[i + 1]);
    }

    if let Some(ref pass) = app.generated_password {
        f.render_widget(Paragraph::new(format!("Generated: {}", pass)), chunks[6]);
    }

    let generate_button_style = if app.generator_focused_field == 5 { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
    f.render_widget(Paragraph::new("[ Generate Password ]").style(generate_button_style).alignment(Alignment::Center), chunks[8]);
    
    let use_button_style = if app.generator_focused_field == 6 && app.generated_password.is_some() { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } 
                           else if app.generated_password.is_none() { Style::default().fg(Color::DarkGray) } 
                           else { Style::default() };
    f.render_widget(Paragraph::new("[ Use This Password ]").style(use_button_style).alignment(Alignment::Center), chunks[9]);

    let help_text = "(↑/↓) Nav | (←/→) Len | (Space/Enter) Toggle/Action | (g) Gen | (u) Use | (Esc/Ctrl+g) Close";
    f.render_widget(Paragraph::new(help_text).alignment(Alignment::Center), chunks[11]);
}


fn draw_help_popup(f: &mut Frame, _app: &App) { 
    let help_area = centered_rect(70, 60, f.size());
    f.render_widget(Clear, help_area); 

    let help_text = vec![
        Line::from(Span::styled("Help - Keyboard Shortcuts (Normal Mode)", Style::default().bold().add_modifier(Modifier::UNDERLINED))),
        Line::from(""),
        Line::from(vec![Span::styled("q", Style::default().fg(Color::Cyan)), Span::raw(": Quit application")]),
        Line::from(vec![Span::styled("j/↓", Style::default().fg(Color::Cyan)), Span::raw(": Navigate Down in list")]),
        Line::from(vec![Span::styled("k/↑", Style::default().fg(Color::Cyan)), Span::raw(": Navigate Up in list")]),
        Line::from(vec![Span::styled("Scroll", Style::default().fg(Color::Cyan)), Span::raw(": Navigate list with mouse wheel")]),
        Line::from(vec![Span::styled("Click Item", Style::default().fg(Color::Cyan)), Span::raw(": Select list item")]),
        Line::from(""),
        Line::from(vec![Span::styled("a", Style::default().fg(Color::Cyan)), Span::raw(": Add New Entry")]),
        Line::from(vec![Span::styled("e", Style::default().fg(Color::Cyan)), Span::raw(": Edit Selected Entry")]),
        Line::from(vec![Span::styled("d", Style::default().fg(Color::Cyan)), Span::raw(": Delete Selected Entry")]),
        Line::from(""),
        Line::from(vec![Span::styled("c", Style::default().fg(Color::Cyan)), Span::raw(": Copy Username of Selected Entry")]),
        Line::from(vec![Span::styled("x", Style::default().fg(Color::Cyan)), Span::raw(": Copy Password of Selected Entry")]),
        Line::from(""),
        Line::from(vec![Span::styled("/", Style::default().fg(Color::Cyan)), Span::raw(": Enter Search Mode")]),
        Line::from(vec![Span::styled("h/?", Style::default().fg(Color::Cyan)), Span::raw(": Toggle this Help Popup")]),
        Line::from(""),
        Line::from(Span::styled("--- Editing Mode ---", Style::default().bold())),
        Line::from(vec![Span::styled("Tab", Style::default().fg(Color::Cyan)), Span::raw(": Move to next input field")]),
        Line::from(vec![Span::styled("Enter", Style::default().fg(Color::Cyan)), Span::raw(": Move to next field / Save entry on last field")]),
        Line::from(vec![Span::styled("Ctrl+g", Style::default().fg(Color::Cyan)), Span::raw(": Open Password Generator (when Password field is active)")]),
        Line::from(vec![Span::styled("Esc", Style::default().fg(Color::Cyan)), Span::raw(": Cancel editing / Close Help")]),
        Line::from(vec![Span::styled("Click Field", Style::default().fg(Color::Cyan)), Span::raw(": Activate form field")]),
        Line::from(""),
        Line::from(Span::styled("--- Password Generator ---", Style::default().bold())),
        Line::from(vec![Span::styled("↑/↓", Style::default().fg(Color::Cyan)), Span::raw(": Navigate fields/buttons")]),
        Line::from(vec![Span::styled("←/→", Style::default().fg(Color::Cyan)), Span::raw(": Decrease/Increase Length")]),
        Line::from(vec![Span::styled("Space/Enter", Style::default().fg(Color::Cyan)), Span::raw(": Toggle checkbox / Activate button")]),
        Line::from(vec![Span::styled("g", Style::default().fg(Color::Cyan)), Span::raw(": Generate Password (shortcut for button)")]),
        Line::from(vec![Span::styled("u", Style::default().fg(Color::Cyan)), Span::raw(": Use Password (shortcut for button, if generated)")]),
        Line::from(vec![Span::styled("Esc/Ctrl+g", Style::default().fg(Color::Cyan)), Span::raw(": Close Generator")]),
        Line::from(""),
        Line::from("(Press h, ?, or Esc to close this help)"),
    ];

    let help_paragraph = Paragraph::new(help_text)
        .block(Block::default().title("Help").borders(Borders::ALL))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    
    f.render_widget(help_paragraph, help_area);
}


/// Renders the UI widgets based on the application mode.
fn ui(f: &mut Frame, app: &mut App) { 
    match app.input_mode {
        InputMode::Normal | InputMode::Searching => { 
            draw_main_ui(f, app);
        }
        InputMode::Editing | InputMode::EditingExisting { .. } => {
            draw_main_ui(f, app); 
            draw_editing_form(f, app);
        }
        InputMode::GeneratingPassword { .. } => {
            draw_main_ui(f, app); // Draw main UI underneath
            draw_password_generator_popup(f, app);
        }
    }
    if app.show_help {
        draw_help_popup(f, app);
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
