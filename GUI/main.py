import json
import os
import datetime
import shutil
from tkinter import filedialog, messagebox
from collections import defaultdict
import copy 
import sys 
try:
    import customtkinter as ctk
except:
    os.system("py -m pip install customtkinter")
    import customtkinter as ctk

# --- Configuration and Constants ---

# 1. CENTRALIZED CONFIGURATION (STRICTLY THE SOURCE OF TRUTH)
APP_CONFIG = {
    # General App Settings
    "general": {
        "JSON_FILE": "data_entries.json",
        "SOURCE_FOLDER": "./source_files/", 
        "DEFAULT_FOLDER_OPTION": "Default_Project_Folder", # Default folder name for initial setup
    },
    # Frame Names (Used for navigation and selection)
    "frames": {
        "NAV_ADD_ENTRY_FRAME": "add_entry",
        "NAV_VIEW_DATA_FRAME": "view_edit_data",
        "NAV_SETTINGS_FRAME": "settings",
        "NAV_EXPORT_DATA_FRAME": "export_data", # New tab
    },
    # Main Details Section 
    "main_details": {
        "MAIN_TYPE_OPTIONS": ["Folder Lookup", "Custom User Input"], 
        "FOLDER_LOOKUP_OPTION": "Folder Lookup",
        "_DEFAULT": "Folder Lookup" # Default value for the radio buttons
    },
    # Description Section - ONLY USES OPTIONS LISTED HERE
    "description": {
        "DESC_TYPE_OPTIONS": ["Project A", "Project B", "Project C", "Other"],
        "_DEFAULT": "Project A" # Default value for the radio buttons
    },
    # Findings Section
    "findings": {
        # Renaming the options to match the user's example format: "Option 1", "Option 2"
        "FINDING_TYPE_OPTIONS": ["Option 1", "Option 2", "Option 3"], 
        "_DEFAULT": "Option 1", # Default value for the finding type radio buttons
        "VERIFIED_OPTIONS": ["Success", "Failure", "Untested"],
        "_VERIFIED_DEFAULT": "Untested", # Default value for verified radio buttons
        "SUCCESS_STATUS": "Success", 
        "FAILURE_STATUS": "Failure", 
        "UNVERIFIED_STATUS": "Untested"
    },
    # 2. CONFIGURABLE FIELD LABELS
    "field_labels": {
        "main_name": "Main Name (Required)",
        "type_radio": "Type:",
        "filepath_dropdown_label": "Folder/User Path (Required)",
        "requirements_textbox": "Requirements (User Input)", 
        "verification_info_textbox": "Verification (User Input)", 
        "description_type_radio": "Description Type:",
        "description_info_textbox": "Description Info (Required)",
        "finding_type_radio": "Type:",
        "finding_verified_radio": "Verified:",
        "finding_info_textbox": "Info (Required)",
    },
    # Tracking Configuration (GLOBAL SOURCE OF TRUTH)
    "tracking": {
        "data": [
            {
                "filepath": "Project_A_Data",
                "entries": ["Entry_001", "Entry_002", "Entry_003", "Entry_004"]
            },
            {
                "filepath": "Project_B_Data",
                "entries": ["Entry_B_Alpha", "Entry_B_Beta"]
            },
            {
                "filepath": "Default_Project_Folder", 
                "entries": ["Default_Item_1", "Default_Item_2", "Default_Item_3"]
            }
        ]
    },
    # Column Configuration for ViewDataFrame (Updated Order and Weights for alignment)
    "view_columns": {
        # New Order/Weights: ID, Verification, Type (Description), Main Name, Tracking Status, Filepath, Created, Last Edit
        "COLUMNS": [
            {"name": "ID", "weight": 1, "data_key": "id"},
            {"name": "Verification Status", "weight": 3, "data_key": "custom:verification_summary"},
            {"name": "Type (Desc)", "weight": 2, "data_key": "Description.Type"}, # Uses Description Type
            {"name": "Main Name", "weight": 4, "data_key": "Main.MainName"},
            {"name": "Tracking Status", "weight": 3, "data_key": "custom:tracking_status"},
            {"name": "Filepath", "weight": 4, "data_key": "Main.Filepath"}, 
            {"name": "Created (User)", "weight": 2, "data_key": "custom:creation_info"},
            {"name": "Last Edit (User)", "weight": 2, "data_key": "custom:last_edit_info"},
        ],
        "HEADER_TEXT_COLOR": "white", 
        "ROW_TEXT_COLOR": "white", 
        "FONT_SIZE": 12 
    }
}

APP_TITLE = "JSON Entry Manager"
JSON_FILE = APP_CONFIG["general"]["JSON_FILE"]
SOURCE_FOLDER = APP_CONFIG["general"]["SOURCE_FOLDER"]
DEFAULT_FOLDER_OPTION = APP_CONFIG["general"]["DEFAULT_FOLDER_OPTION"]
# Reference the tracking data directly from APP_CONFIG
TRACKING_DATA = APP_CONFIG["tracking"]["data"] 


# Custom Colors 
PURPLE_HUE = "#7B68EE"          # Medium Slate Blue - Primary Accent Color
ERROR_COLOR = "red" 
SUCCESS_COLOR = "green"
DEFAULT_SUBMIT_COLOR = PURPLE_HUE 
UNMATCHED_COLOR = "#A9A9D9"      
LESS_SATURATED_RED = "#CC6666"  
DEFAULT_LABEL_COLOR = ("gray10", "gray90") 
# UPDATED: Use a distinctly darker color for input fields to ensure contrast with the frame background.
INPUT_BG_COLOR = ("#3C3C3C", "#3C3C3C") 

# VIEW DATA COLORS 
FOUND_ENTRY_COLOR_TRACKING = "green"  
MISSING_ENTRY_COLOR = LESS_SATURATED_RED 
DEFAULT_ENTRY_COLOR = ("gray85", "gray20") 

# Row Highlighting based on verification status (Background)
ALL_FAILURE_COLOR_RED_ROW = LESS_SATURATED_RED 
UNVERIFIED_COLOR_BLUE_ROW = "#4682B4" 
ALL_SUCCESS_COLOR_GREEN_ROW = "green" 

HIGHLIGHT_HOVER_COLOR = "#DCD0FF" # Light Hover Color
HIGHLIGHT_TEXT_COLOR = "black"    
# Row Clickability Indicator
CLICK_INDICATOR_COLOR = PURPLE_HUE 

# Set the appearance mode and default color theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# --- Utility Functions for File Management ---

def load_data():
    """
    Loads JSON data from the file, or initializes an empty list if not found.
    """
    if os.path.exists(JSON_FILE):
        try:
            with open(JSON_FILE, 'r') as f:
                data = json.load(f)
                return data
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {JSON_FILE}. Starting with empty data.")
            return []
    return []

def save_data(data):
    """
    Saves the data to the JSON file and creates a dated backup.
    """
    # Create backup
    if os.path.exists(JSON_FILE):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"{JSON_FILE}.{timestamp}.bak"
        try:
            shutil.copy(JSON_FILE, backup_file)
            print(f"Created backup: {backup_file}")
        except Exception as e:
            print(f"Warning: Could not create backup: {e}")

    # Save new data
    try:
        with open(JSON_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Data saved to {JSON_FILE}")
    except Exception as e:
        print(f"Error: Could not save data: {e}")

def get_folder_options(folder_path):
    """
    Gets folder names from a specified folder to use as dropdown options.
    Returns an error message if the path doesn't exist.
    """
    if not os.path.exists(folder_path):
        return [f"Error: Path '{folder_path}' not found."]
    try:
        # List directories only
        folders = [f for f in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, f))]
        
        # Ensure default option is always available if the folder is in tracking data and exists
        for tracking_item in TRACKING_DATA: # Use the global TRACKING_DATA
            if tracking_item["filepath"] not in folders:
                 # Check if the folder exists, if so, add it to the list of options
                 if os.path.exists(os.path.join(folder_path, tracking_item["filepath"])):
                     folders.append(tracking_item["filepath"])

        return folders if folders else ["No folders found"]
    except Exception:
        return ["Error reading folder contents"]

def parse_info_log(info_log):
    """Extracts creation and last edit details from the Main Info log."""
    if not info_log:
        return "N/A", "N/A", "N/A", "N/A"
    
    creation_log = info_log[0]
    last_edit_log = info_log[-1]
    
    def format_log(log):
        try:
            dt = datetime.datetime.fromisoformat(log.get("timestamp"))
            timestamp = dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            timestamp = "N/A"
        user = log.get("user", "Unknown")
        return timestamp, user

    creation_ts, creation_user = format_log(creation_log)
    last_edit_ts, last_edit_user = format_log(last_edit_log)
    
    return creation_ts, creation_user, last_edit_ts, last_edit_user

# --- Main Application Class ---

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Load data (APP_CONFIG is now strictly the source of truth)
        self.data = load_data() 
        self.FRAME_NAMES = APP_CONFIG["frames"]

        # --- Setup Main Window ---
        self.title(APP_TITLE)
        self.geometry("1100x700")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # --- Navigation Frame (Sidebar) ---
        self.navigation_frame = ctk.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(7, weight=1) 

        self.nav_label = ctk.CTkLabel(self.navigation_frame, text="JSON Manager", 
                                      font=ctk.CTkFont(size=15, weight="bold"))
        self.nav_label.grid(row=0, column=0, padx=20, pady=20)

        # Navigation Buttons
        self.add_entry_button = ctk.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, 
                                              text="➕ Add New Entry", fg_color="transparent", text_color=("gray10", "gray90"), 
                                              hover_color=("gray70", "gray30"), command=lambda: self.select_frame_by_name(self.FRAME_NAMES["NAV_ADD_ENTRY_FRAME"]))
        self.add_entry_button.grid(row=1, column=0, sticky="ew")

        # EDIT/VIEW button combined
        self.view_edit_data_button = ctk.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, 
                                             text="📝 View/Edit Data", fg_color="transparent", text_color=("gray10", "gray90"), 
                                             hover_color=("gray70", "gray30"), command=lambda: self.select_frame_by_name(self.FRAME_NAMES["NAV_VIEW_DATA_FRAME"]))
        self.view_edit_data_button.grid(row=2, column=0, sticky="ew") 
        
        # New Export Data Button
        self.export_data_button = ctk.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, 
                                             text="📊 Export Data (TODO)", fg_color="transparent", text_color=("gray10", "gray90"), 
                                             hover_color=("gray70", "gray30"), command=lambda: self.select_frame_by_name(self.FRAME_NAMES["NAV_EXPORT_DATA_FRAME"]))
        self.export_data_button.grid(row=3, column=0, sticky="ew") 

        self.settings_button = ctk.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, 
                                             text="⚙️ Settings (TODO)", fg_color="transparent", text_color=("gray10", "gray90"), 
                                             hover_color=("gray70", "gray30"), command=lambda: self.select_frame_by_name(self.FRAME_NAMES["NAV_SETTINGS_FRAME"]))
        self.settings_button.grid(row=4, column=0, sticky="ew") 

        # Exit/Save Button
        self.save_exit_button = ctk.CTkButton(self.navigation_frame, text="💾 Save & Exit", 
                                              command=self.on_close, fg_color="red", hover_color="darkred")
        self.save_exit_button.grid(row=7, column=0, padx=20, pady=20, sticky="s")


        # --- Main Content Frames ---
        self.add_entry_frame = AddEntryFrame(self, self.data)
        self.settings_frame = self._create_todo_frame("Settings")
        self.export_data_frame = self._create_todo_frame("Export Data") 
        self.view_data_frame = ViewDataFrame(self, self.data, self.load_entry_for_editing) 
        
        # --- Default Selection ---
        self.current_frame = None
        self.select_frame_by_name(self.FRAME_NAMES["NAV_ADD_ENTRY_FRAME"]) 

        # Set protocol for closing the window
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def load_entry_for_editing(self, entry):
        """Callback to load a selected entry into AddEntryFrame."""
        self.select_frame_by_name(self.FRAME_NAMES["NAV_ADD_ENTRY_FRAME"]) 
        self.add_entry_frame.load_entry_for_editing(entry)


    def _create_todo_frame(self, name):
        """Helper to create placeholder frames."""
        frame = ctk.CTkFrame(self)
        label = ctk.CTkLabel(frame, text=f"{name} Interface (TODO)", font=ctk.CTkFont(size=24, weight="bold"))
        label.place(relx=0.5, rely=0.5, anchor="center")
        return frame

    def select_frame_by_name(self, name):
        """Switches the main content frame and updates button appearance."""
        
        frame_map = {
            self.FRAME_NAMES["NAV_ADD_ENTRY_FRAME"]: self.add_entry_frame,
            self.FRAME_NAMES["NAV_VIEW_DATA_FRAME"]: self.view_data_frame,
            self.FRAME_NAMES["NAV_SETTINGS_FRAME"]: self.settings_frame,
            self.FRAME_NAMES["NAV_EXPORT_DATA_FRAME"]: self.export_data_frame, 
        }
        button_map = {
            self.FRAME_NAMES["NAV_ADD_ENTRY_FRAME"]: self.add_entry_button,
            self.FRAME_NAMES["NAV_VIEW_DATA_FRAME"]: self.view_edit_data_button,
            self.FRAME_NAMES["NAV_SETTINGS_FRAME"]: self.settings_button,
            self.FRAME_NAMES["NAV_EXPORT_DATA_FRAME"]: self.export_data_button, 
        }
        
        if name == self.FRAME_NAMES["NAV_VIEW_DATA_FRAME"]:
            # Pass self.data explicitly to update_display
            self.view_data_frame.update_display(self.data)
            self.add_entry_frame.reset_form()
        elif name == self.FRAME_NAMES["NAV_ADD_ENTRY_FRAME"]:
            pass 
        elif name == self.FRAME_NAMES["NAV_EXPORT_DATA_FRAME"]:
             pass 

        # Set button colors
        for frame_name, button in button_map.items():
            if frame_name == name:
                button.configure(fg_color=("gray75", "gray25")) 
            else:
                button.configure(fg_color="transparent") 

        if self.current_frame:
            self.current_frame.grid_forget()

        self.current_frame = frame_map.get(name)
        
        if self.current_frame:
            self.current_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)


    def on_close(self):
        """Handle saving data and closing the application."""
        save_data(self.data)
        self.destroy()

# --- Add Entry Frame Class ---

class AddEntryFrame(ctk.CTkFrame):
    def __init__(self, master, data, **kwargs):
        super().__init__(master, **kwargs)
        self.data = data
        self.master = master 
        self.is_editing = False 
        self.editing_entry_id = None
        self.is_duplicate_found = False
        self.duplicate_entry = None
        
        # Get configuration values
        self.MAIN_TYPE_OPTIONS = APP_CONFIG["main_details"]["MAIN_TYPE_OPTIONS"]
        self.MAIN_TYPE_DEFAULT = APP_CONFIG["main_details"]["_DEFAULT"]
        self.FOLDER_LOOKUP_OPTION = APP_CONFIG["main_details"]["FOLDER_LOOKUP_OPTION"]
        
        self.DESC_TYPE_OPTIONS = APP_CONFIG["description"]["DESC_TYPE_OPTIONS"]
        self.DESC_TYPE_DEFAULT = APP_CONFIG["description"]["_DEFAULT"]
        
        self.FINDING_TYPE_OPTIONS = APP_CONFIG["findings"]["FINDING_TYPE_OPTIONS"]
        self.FINDING_TYPE_DEFAULT = APP_CONFIG["findings"]["_DEFAULT"]
        self.VERIFIED_OPTIONS = APP_CONFIG["findings"]["VERIFIED_OPTIONS"]
        self.VERIFIED_DEFAULT = APP_CONFIG["findings"]["_VERIFIED_DEFAULT"]
        
        # Field Labels
        self.FIELD_LABELS = APP_CONFIG["field_labels"] 
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.form_title_label = ctk.CTkLabel(self, text="New Entry Form", font=ctk.CTkFont(size=20, weight="bold"))
        self.form_title_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        # Feedback label for success/error messages
        self.feedback_label = ctk.CTkLabel(self, text="", text_color=ERROR_COLOR, anchor="w")
        self.feedback_label.grid(row=1, column=0, padx=20, sticky="ew")

        self.scrollable_frame = ctk.CTkScrollableFrame(self)
        self.scrollable_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew") 
        self.scrollable_frame.grid_columnconfigure(0, weight=1)
        
        # FIX: MOVED/INSERTED BUTTON CODE HERE to ensure self.submit_button exists
        self.button_frame = ctk.CTkFrame(self, height=50)
        self.button_frame.grid(row=3, column=0, padx=20, pady=20, sticky="ew") 
        self.button_frame.grid_columnconfigure((0, 1), weight=1)
        
        # Submit Button
        self.submit_button = ctk.CTkButton(self.button_frame, text="✨ Add Entry to JSON", 
                                           command=self.submit_entry, fg_color=DEFAULT_SUBMIT_COLOR, hover_color=PURPLE_HUE)
        self.submit_button.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="ew")

        # Clear Button
        self.clear_button = ctk.CTkButton(self.button_frame, text="🗑️ Clear Form", 
                                          command=self.reset_form, fg_color=LESS_SATURATED_RED, hover_color="#A04040")
        self.clear_button.grid(row=0, column=1, padx=(5, 10), pady=10, sticky="ew")
        # END FIX

        # Now safe to call setup functions
        self._setup_main_frame(self.scrollable_frame)
        self._setup_description_frame(self.scrollable_frame)
        
        self.findings_entries = []
        
        self._setup_findings_entry_area(self.scrollable_frame) 
        
        self.update_ui_for_mode()

    # --- Utility Methods for Required Fields and Custom Validation ---
    
    def _custom_verification_passthrough(self, field_name, value):
        """
        Custom verification function hook.
        
        Returns: (bool, str or None) -> (is_valid, error_message)
        """
        if value and not value.startswith("Error:"): 
            return True, None
        return True, None 

    def _get_required_widgets(self):
        """Returns a dict of human-readable field names and their corresponding CTk widgets/values."""
        
        type_val = self.type_var.get()
        if type_val == self.FOLDER_LOOKUP_OPTION: 
            filepath_widget = self.filepath_dropdown 
            filepath_value = self.filepath_var.get() 
        else:
            filepath_widget = self.filepath_entry
            filepath_value = self.filepath_entry.get()

        required_widgets = {
            self.FIELD_LABELS["main_name"]: (self.main_name_entry, self.main_name_entry.get()),
            self.FIELD_LABELS["filepath_dropdown_label"]: (filepath_widget, filepath_value),
            self.FIELD_LABELS["description_info_textbox"]: (self.description_info_textbox, self.description_info_textbox.get("1.0", "end-1c").strip())
        }

        # Findings Info is only required if a finding frame exists
        for i, finding_frame in enumerate(self.findings_entries):
            info_text = finding_frame.info_textbox.get("1.0", "end-1c").strip()
            key = f"Finding #{i+1} - {self.FIELD_LABELS['finding_info_textbox']}"
            required_widgets[key] = (finding_frame.info_textbox, info_text)
            
        return required_widgets
    
    # Replacement error highlighting functions using fg_color
    def _reset_widget_color(self, widget):
        """Resets the fg_color of a CTk widget to the default background color."""
        
        if hasattr(widget, 'configure'):
            if isinstance(widget, (ctk.CTkEntry, ctk.CTkTextbox)):
                widget.configure(fg_color=INPUT_BG_COLOR)
            elif isinstance(widget, ctk.CTkOptionMenu):
                # Use standard CTk colors for OptionMenu as it's not strictly "user input" box
                default_fg_color = ("#F9F9FA", "#343638") 
                widget.configure(fg_color=default_fg_color)


    def _highlight_widget_error(self, widget):
        """Highlights a required CTk widget background in red."""
        if hasattr(widget, 'configure') and isinstance(widget, (ctk.CTkEntry, ctk.CTkTextbox, ctk.CTkOptionMenu)):
            # Use a slightly less saturated red for highlighting against the dark background
            widget.configure(fg_color="#D94C4C") 


    # --- Section 1: Main Details (Updated Layout) ---
    def _setup_main_frame(self, parent):
        self.main_frame = ctk.CTkFrame(parent)
        self.main_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.main_frame.grid_columnconfigure(0, weight=1) # Left Container
        self.main_frame.grid_columnconfigure(1, weight=1) # Right Container

        ctk.CTkLabel(self.main_frame, text="Main Details", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="w")
        
        # --- LEFT Container (Type, Filepath) ---
        left_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        left_container.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        left_container.grid_columnconfigure(0, weight=1)
        
        current_row = 0
        
        # 1. Type (Radio Buttons) -> TOP LEFT
        ctk.CTkLabel(left_container, text=self.FIELD_LABELS["type_radio"]).grid(row=current_row, column=0, padx=0, pady=(5,0), sticky="w")
        current_row += 1
        
        type_options_frame = ctk.CTkFrame(left_container, fg_color="transparent")
        type_options_frame.grid(row=current_row, column=0, padx=0, pady=5, sticky="w")
        
        self.type_var = ctk.StringVar(value=self.MAIN_TYPE_DEFAULT) 
        for i, option in enumerate(self.MAIN_TYPE_OPTIONS):
            ctk.CTkRadioButton(type_options_frame, text=option, variable=self.type_var, value=option, 
                               command=self._update_filepath_field, fg_color=PURPLE_HUE, hover_color=PURPLE_HUE).grid(row=0, column=i, padx=5, pady=5)
        current_row += 1
        
        # 2. Filepath (Dropdown or Entry) -> BOTTOM LEFT
        self.file_options = get_folder_options(SOURCE_FOLDER)
        self.filepath_var = ctk.StringVar(value=self.file_options[0]) 
        self.filepath_label = ctk.CTkLabel(left_container, text=self.FIELD_LABELS["filepath_dropdown_label"])
        self.filepath_label.grid(row=current_row, column=0, padx=0, pady=(5,0), sticky="w")
        current_row += 1
        
        self.filepath_dropdown = ctk.CTkOptionMenu(left_container, variable=self.filepath_var, values=self.file_options, width=250, button_color=PURPLE_HUE, button_hover_color=PURPLE_HUE, command=lambda e: self.check_for_duplicate_entry())
        # APPLY INPUT COLOR: Filepath Entry
        self.filepath_entry = ctk.CTkEntry(left_container, placeholder_text="Enter custom path data...", width=250, fg_color=INPUT_BG_COLOR) 
        
        self.filepath_dropdown.grid(row=current_row, column=0, padx=0, pady=5, sticky="ew")
        self.filepath_entry.grid(row=current_row, column=0, padx=0, pady=5, sticky="ew")
        current_row += 1
        self.filepath_entry.bind("<KeyRelease>", lambda e: self.check_for_duplicate_entry()) 
        
        # --- RIGHT Container (Main Name, Auto Info) ---
        right_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        right_container.grid(row=1, column=1, padx=10, pady=5, sticky="nsw")
        right_container.grid_columnconfigure(0, weight=1)
        
        current_row = 0

        # 3. Main Name -> TOP RIGHT
        ctk.CTkLabel(right_container, text=self.FIELD_LABELS["main_name"]).grid(row=current_row, column=0, padx=0, pady=(5,0), sticky="w")
        current_row += 1
        # APPLY INPUT COLOR: Main Name Entry
        self.main_name_entry = ctk.CTkEntry(right_container, placeholder_text="Enter main identifier name", width=250, fg_color=INPUT_BG_COLOR) 
        self.main_name_entry.grid(row=current_row, column=0, padx=0, pady=5, sticky="ew")
        current_row += 1
        self.main_name_entry.bind("<KeyRelease>", lambda e: self.check_for_duplicate_entry())
        
        # 4. Auto Info & Duplicate Status -> BOTTOM RIGHT
        auto_info_frame = ctk.CTkFrame(right_container, fg_color="transparent")
        auto_info_frame.grid(row=current_row, column=0, padx=0, pady=(10, 5), sticky="ew")
        auto_info_frame.grid_columnconfigure(0, weight=1)
        auto_info_frame.grid_columnconfigure(1, weight=0) # Button doesn't expand
        
        self.user = os.environ.get('USERNAME') or os.environ.get('USER') or "Unknown_User"
        self.auto_info_label = ctk.CTkLabel(auto_info_frame, text=f"Auto Info: User: {self.user} | Status: Creation", anchor="w")
        self.auto_info_label.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="w")
        
        self.edit_duplicate_button = ctk.CTkButton(auto_info_frame, text="Go to Edit Mode", width=120, fg_color="darkorange", hover_color="#CC8400", command=self._load_duplicate_for_editing)
        self.edit_duplicate_button.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="e")
        self.edit_duplicate_button.grid_remove() # Hide initially
        
        current_row += 1
        
        self._update_filepath_field() 


    def _update_filepath_field(self):
        """Toggles Filepath control between dropdown (for Folder Lookup) and entry box (for other options)."""
        self._reset_widget_color(self.filepath_entry)
        self._reset_widget_color(self.filepath_dropdown)
            
        self.filepath_dropdown.grid_forget()
        self.filepath_entry.grid_forget()
        
        if self.type_var.get() == self.FOLDER_LOOKUP_OPTION:
            self.file_options = get_folder_options(SOURCE_FOLDER)
            self.filepath_dropdown.configure(values=self.file_options)
            
            current_value = self.filepath_var.get()
            if current_value not in self.file_options:
                if self.file_options and self.file_options[0].startswith("Error:"):
                    self.filepath_var.set(self.file_options[0])
                elif DEFAULT_FOLDER_OPTION in self.file_options:
                    self.filepath_var.set(DEFAULT_FOLDER_OPTION)
                elif self.file_options:
                    self.filepath_var.set(self.file_options[0])
            else:
                 self.filepath_var.set(current_value)
            
            # NOTE: Row/Column numbers must match the location in _setup_main_frame
            self.filepath_dropdown.grid(row=4, column=0, padx=0, pady=5, sticky="ew") 
        else:
            # NOTE: Row/Column numbers must match the location in _setup_main_frame
            self.filepath_entry.grid(row=4, column=0, padx=0, pady=5, sticky="ew") 
        
        self.check_for_duplicate_entry()


    # --- Duplicate Check Methods ---
    def check_for_duplicate_entry(self):
        """Checks if an entry with the same Filepath and Main Name already exists."""
        
        # Only check when in 'New Entry' mode
        if self.is_editing:
            self.is_duplicate_found = False
            self.duplicate_entry = None
            self.edit_duplicate_button.grid_remove()
            self.update_ui_for_mode()
            return
            
        main_name = self.main_name_entry.get().strip()
        
        if self.type_var.get() == self.FOLDER_LOOKUP_OPTION:
            filepath_val = self.filepath_var.get()
        else:
            filepath_val = self.filepath_entry.get()
            
        if not main_name or not filepath_val or filepath_val.startswith("Error:"):
            self.is_duplicate_found = False
            self.duplicate_entry = None
            self.edit_duplicate_button.grid_remove()
            self.update_ui_for_mode()
            return

        # Search for a duplicate
        found_entry = next((entry for entry in self.data 
                             if entry.get('Main', {}).get('MainName', '').strip() == main_name
                             and entry.get('Main', {}).get('Filepath', '') == filepath_val), None)

        if found_entry:
            self.is_duplicate_found = True
            self.duplicate_entry = found_entry
            
            dup_id = found_entry.get('id')
            self.feedback_label.configure(text=f"⚠️ WARNING: Entry '{main_name}' (ID: {dup_id}) already exists at this path. Click 'Go to Edit Mode' to modify it.", text_color="darkorange")
            self.auto_info_label.configure(text=f"Auto Info: DUPLICATE FOUND (ID: {dup_id})")
            self.edit_duplicate_button.grid()
            self.submit_button.configure(state="disabled", text_color_disabled="gray50")
        else:
            self.is_duplicate_found = False
            self.duplicate_entry = None
            self.edit_duplicate_button.grid_remove()
            self.feedback_label.configure(text="", text_color=ERROR_COLOR)
            self.update_ui_for_mode() # Resets submit button state

    def _load_duplicate_for_editing(self):
        """Action handler for the 'Go to Edit Mode' button."""
        if self.duplicate_entry:
            # Call the main function to transition to edit mode
            self.load_entry_for_editing(self.duplicate_entry)

    # --- Section 2: Description ---
    def _setup_description_frame(self, parent):
        self.description_frame = ctk.CTkFrame(parent)
        self.description_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.description_frame.grid_columnconfigure(0, weight=0) 
        self.description_frame.grid_columnconfigure(1, weight=1) 

        ctk.CTkLabel(self.description_frame, text="Description", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="w")
        
        # LEFT Container (Description Type)
        options_container = ctk.CTkFrame(self.description_frame, fg_color="transparent")
        options_container.grid(row=1, column=0, padx=10, pady=5, sticky="nsw")
        options_container.grid_columnconfigure(0, weight=1) 
        
        # 1. Description Type (Vertical Radio Buttons)
        self.desc_type_var = ctk.StringVar(value=self.DESC_TYPE_DEFAULT) # Use default from config
        ctk.CTkLabel(options_container, text=self.FIELD_LABELS["description_type_radio"]).grid(row=0, column=0, padx=0, pady=(5,0), sticky="w")
        
        for i, dtype in enumerate(self.DESC_TYPE_OPTIONS):
            ctk.CTkRadioButton(options_container, text=dtype, variable=self.desc_type_var, value=dtype, 
                               fg_color=PURPLE_HUE, hover_color=PURPLE_HUE).grid(row=i + 1, column=0, padx=1, pady=2, sticky="w")
        
        
        # RIGHT Container (Info Text Box)
        text_container = ctk.CTkFrame(self.description_frame, fg_color="transparent")
        text_container.grid(row=1, column=1, padx=10, pady=5, sticky="nsew") 
        text_container.grid_columnconfigure(0, weight=1)
        text_container.grid_rowconfigure(1, weight=1)
        
        # Info Text Box
        ctk.CTkLabel(text_container, text=self.FIELD_LABELS["description_info_textbox"]).grid(row=0, column=0, padx=0, pady=(5,0), sticky="w")
        # APPLY INPUT COLOR: Description Info Textbox
        self.description_info_textbox = ctk.CTkTextbox(text_container, height=120, wrap="word", fg_color=INPUT_BG_COLOR) 
        self.description_info_textbox.grid(row=1, column=0, padx=0, pady=5, sticky="nsew") 


    # --- Section 3: Findings ---
    def _setup_findings_entry_area(self, parent):
        self.findings_container = ctk.CTkFrame(parent)
        self.findings_container.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.findings_container.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.findings_container, text="Findings", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.findings_button_frame = ctk.CTkFrame(self.findings_container, fg_color="transparent")
        self.findings_button_frame.grid(row=999, column=0, padx=10, pady=(10, 5), sticky="w")
        self.findings_button_frame.grid_columnconfigure((0, 1), weight=0)

        self.add_finding_btn = ctk.CTkButton(self.findings_button_frame, text="➕ Add Another Finding", command=self._add_findings_entry, fg_color=PURPLE_HUE, hover_color=PURPLE_HUE)
        self.add_finding_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.remove_finding_btn = ctk.CTkButton(self.findings_button_frame, text="➖ Remove Last Finding", command=self._remove_last_finding, fg_color=LESS_SATURATED_RED, hover_color="#A04040")
        self.remove_finding_btn.grid(row=0, column=1)
        
        self._add_findings_entry(is_initial=True) 
        self._update_remove_button_state()

    # --- Findings Management Methods ---

    def _add_findings_entry(self, is_initial=False, finding_data=None):
        """Creates and adds a new FindingsEntry sub-frame, optionally populating it with data."""
        
        new_entry_row = 1 + len(self.findings_entries) 
        
        new_entry = FindingsEntry(self.findings_container, new_entry_row, accent_color=PURPLE_HUE, 
                                  type_options=self.FINDING_TYPE_OPTIONS, 
                                  verified_options=self.VERIFIED_OPTIONS,
                                  field_labels=self.FIELD_LABELS,
                                  type_options_default=self.FINDING_TYPE_DEFAULT,
                                  verified_options_default=self.VERIFIED_DEFAULT)
        
        if finding_data:
            new_entry.load_data(finding_data)
            
        new_entry.grid(row=new_entry_row, column=0, padx=10, pady=(5, 5), sticky="ew")
        self.findings_entries.append(new_entry)
        
        if not is_initial:
            self._update_remove_button_state()
            self.scrollable_frame._parent_canvas.yview_moveto(1.0)
        
    def _remove_last_finding(self):
        """Removes the last finding entry from the list and the GUI."""
        if self.findings_entries:
            last_entry = self.findings_entries.pop()
            last_entry.destroy()
            self._update_remove_button_state()
        else:
            messagebox.showinfo("Cannot Remove", "No findings to remove.")

    def _update_remove_button_state(self):
        """Disables the remove button if the findings list is empty."""
        if not self.findings_entries:
            self.remove_finding_btn.configure(state="disabled", text_color_disabled="gray50")
        else:
            self.remove_finding_btn.configure(state="normal", text_color_disabled=("gray10", "gray90"))

    # --- Edit Mode Methods ---
    
    def load_entry_for_editing(self, entry):
        """Populates the form with an existing entry's data and sets the state to editing."""
        self.reset_form(keep_state=True) 

        self.is_editing = True
        self.editing_entry_id = entry['id']
        self.is_duplicate_found = False # Clear duplicate flag when explicitly editing
        self.duplicate_entry = None
        self.edit_duplicate_button.grid_remove()
        
        # Main Details
        main = entry['Main']
        main_type_saved = main.get('Type')
        
        # Handle Main Type Conflict
        if main_type_saved in self.MAIN_TYPE_OPTIONS:
            self.type_var.set(main_type_saved)
        else:
            first_option = self.MAIN_TYPE_DEFAULT
            self.type_var.set(first_option)
            messagebox.showwarning("Configuration Conflict", 
                                   f"The saved Main Type '{main_type_saved}' is no longer in the configuration. It was reset to '{first_option}' for editing.")
        
        
        if self.type_var.get() == self.FOLDER_LOOKUP_OPTION:
            filepath_saved = main.get('Filepath', self.file_options[0])
            if filepath_saved not in self.file_options:
                 self.filepath_var.set(self.file_options[0]) 
                 messagebox.showwarning("Configuration Conflict", 
                                   f"The saved folder path '{filepath_saved}' is no longer available in the source folder. It was reset to '{self.file_options[0]}' for editing.")
            else:
                 self.filepath_var.set(filepath_saved)
            self._update_filepath_field()
        else:
            self._update_filepath_field()
            self.filepath_entry.insert(0, main.get('Filepath', ''))

        self.main_name_entry.insert(0, main.get('MainName', ''))
        
        # Auto Info Update
        creation_ts, creation_user, last_edit_ts, last_edit_user = parse_info_log(main.get('Info', []))
        self.auto_info_label.configure(text=f"Auto Info: User: {self.user} | Status: Editing (ID: {self.editing_entry_id})")

        # Description
        description = entry['Description']
        
        # Handle Description Type conflict
        desc_type_saved = description.get('Type')
        if desc_type_saved in self.DESC_TYPE_OPTIONS:
            self.desc_type_var.set(desc_type_saved)
        else:
            first_option = self.DESC_TYPE_DEFAULT
            self.desc_type_var.set(first_option)
            messagebox.showwarning("Configuration Conflict", 
                                   f"The saved Description Type '{desc_type_saved}' is no longer in the configuration. It was reset to '{first_option}' for editing.")
        
        self.description_info_textbox.insert("1.0", description.get('Info', ''))
        
        # Findings
        findings = entry.get('Findings', [])
        
        # Clear default finding
        if self.findings_entries:
            self.findings_entries[0].destroy()
            self.findings_entries.clear()

        # Load existing findings
        for finding in findings:
            self._add_findings_entry(is_initial=False, finding_data=finding)
        
        self._update_remove_button_state()
        self.update_ui_for_mode()
        self.scrollable_frame._parent_canvas.yview_moveto(0.0) 
        
    def update_ui_for_mode(self):
        """Updates the button text and title based on the editing state."""
        if self.is_editing:
            self.form_title_label.configure(text=f"Edit Entry (ID: {self.editing_entry_id})")
            self.submit_button.configure(text="💾 Update Existing Entry", fg_color="darkgreen", hover_color="#458B00", state="normal")
            self.clear_button.configure(text="❌ Cancel Edit / Clear Form", fg_color=LESS_SATURATED_RED, hover_color="#A04040") 
            self.edit_duplicate_button.grid_remove() # Ensure hidden in edit mode
        elif self.is_duplicate_found:
             self.submit_button.configure(state="disabled", text_color_disabled="gray50")
        else:
            self.form_title_label.configure(text="New Entry Form")
            self.submit_button.configure(text="✨ Add New Entry to JSON", fg_color=DEFAULT_SUBMIT_COLOR, hover_color=PURPLE_HUE, state="normal")
            self.clear_button.configure(text="🗑️ Clear Form", fg_color=LESS_SATURATED_RED, hover_color="#A04040")
            self.auto_info_label.configure(text=f"Auto Info: User: {self.user} | Status: Creation")
            self.edit_duplicate_button.grid_remove()

    def submit_entry(self):
        """Handles both creating a new entry and updating an existing one."""
        # --- 1. Reset Feedback and Highlights ---
        self.feedback_label.configure(text="", text_color=ERROR_COLOR)
        required_widgets = self._get_required_widgets() 

        for name, (widget, value) in required_widgets.items():
            self._reset_widget_color(widget)
        
        # --- 2. Data Collection and Validation ---
        missing_fields = []
        custom_errors = {}
        
        for name, (widget, value) in required_widgets.items():
            is_filepath_error = name.startswith(self.FIELD_LABELS["filepath_dropdown_label"]) and value.startswith("Error:")
            
            # CHECK 1: Required Field Validation
            if not value or is_filepath_error:
                missing_fields.append(name.replace(" (Required)", "").strip())
                self._highlight_widget_error(widget)
            else:
                # CHECK 2: Custom Validation Hook (only for Main Name and Filepath)
                is_valid = True
                error_msg = None
                
                if name == self.FIELD_LABELS["main_name"]:
                    is_valid, error_msg = self._custom_verification_passthrough("Main Name", value)
                elif name == self.FIELD_LABELS["filepath_dropdown_label"]:
                    is_valid, error_msg = self._custom_verification_passthrough("Filepath", value)

                if not is_valid:
                    custom_errors[name] = error_msg
                    self._highlight_widget_error(widget)


        if missing_fields or custom_errors:
            error_msg = ""
            if missing_fields:
                error_msg += "❗ Required fields missing or path error: " + ", ".join(missing_fields)
            if custom_errors:
                if error_msg:
                    error_msg += "\n\n"
                error_msg += "🛑 Custom Validation Failed:\n" + "\n".join(f"- {n.replace(' (Required)', '')}: {e}" for n, e in custom_errors.items())
                
            # Set the message color to RED on validation failure
            self.feedback_label.configure(text=error_msg, text_color=ERROR_COLOR) 
            return

        # --- 3. JSON Object Construction ---
        main_name = required_widgets[self.FIELD_LABELS["main_name"]][1]
        filepath_val = required_widgets[self.FIELD_LABELS["filepath_dropdown_label"]][1]
        description_info = required_widgets[self.FIELD_LABELS["description_info_textbox"]][1]
        current_time = datetime.datetime.now().isoformat()
        
        # Findings list now includes Requirements and Verification Info
        findings_list = [f.get_data() for f in self.findings_entries]

        if self.is_editing:
            # --- UPDATE EXISTING ENTRY ---
            try:
                idx = next(i for i, entry in enumerate(self.data) if entry.get('id') == self.editing_entry_id)
            except StopIteration:
                self.feedback_label.configure(text="Error: Could not find original entry to update.", text_color=ERROR_COLOR)
                self.reset_form()
                return

            original_entry = self.data[idx]
            info_log = original_entry.get("Main", {}).get("Info", [])
            
            info_log_copy = copy.deepcopy(info_log) 
            info_log_copy.append({
                "user": self.user,
                "timestamp": current_time,
                "change": "edit"
            })

            original_entry['Main']['Type'] = self.type_var.get()
            original_entry['Main']['Filepath'] = filepath_val
            original_entry['Main']['MainName'] = main_name
            original_entry['Main']['Info'] = info_log_copy 
            
            # NOTE: Removed original Details section as fields are now in Findings
            if 'Details' in original_entry:
                 del original_entry['Details']
            
            original_entry['Description']['Type'] = self.desc_type_var.get()
            original_entry['Description']['Info'] = description_info
            original_entry['Findings'] = findings_list

            self.feedback_label.configure(text=f"✅ Success! Entry '{main_name}' (ID: {self.editing_entry_id}) updated.", text_color=SUCCESS_COLOR)
            self.reset_form()

        else:
            # --- CREATE NEW ENTRY ---
            if self.is_duplicate_found:
                 # Should not happen if button is disabled, but as a safety check
                 self.feedback_label.configure(text="Error: Duplicate entry detected. Please use the 'Go to Edit Mode' button to modify the existing entry.", text_color=ERROR_COLOR)
                 return

            # Get the highest existing ID or start at 1 if data is empty
            if self.data:
                new_entry_id = max(entry.get('id', 0) for entry in self.data) + 1
            else:
                new_entry_id = 1

            new_entry = {
                "id": new_entry_id,
                "Main": {
                    "Type": self.type_var.get(),
                    "Filepath": filepath_val,
                    "MainName": main_name,
                    "Info": [
                        {
                            "user": self.user,
                            "timestamp": current_time,
                            "change": "creation"
                        }
                    ]
                },
                # NOTE: Details section is intentionally omitted as fields were moved
                "Description": {
                    "Type": self.desc_type_var.get(),
                    "Info": description_info
                },
                "Findings": findings_list
            }
            self.data.append(new_entry)
            self.feedback_label.configure(text=f"✅ Success! Entry '{main_name}' added (ID: {new_entry_id}).", text_color=SUCCESS_COLOR)
            self.reset_form()

    def reset_form(self, keep_state=False):
        """Rerets all fields in the Add Entry form."""
        self.main_name_entry.delete(0, 'end')
        self.type_var.set(self.MAIN_TYPE_DEFAULT) # Use default
        self.description_info_textbox.delete("1.0", 'end')
        self.desc_type_var.set(self.DESC_TYPE_DEFAULT) # Use default
        self.feedback_label.configure(text="")

        # Reset colors
        self._reset_widget_color(self.main_name_entry)
        self._reset_widget_color(self.description_info_textbox)
        
        # Clear findings frames and reset their textboxes (including the new ones)
        for entry in self.findings_entries:
            entry.destroy()
        self.findings_entries = []
        self._add_findings_entry(is_initial=True)
        
        # Reset file path field
        self._update_filepath_field()
        if self.type_var.get() != self.FOLDER_LOOKUP_OPTION:
            self.filepath_entry.delete(0, 'end')

        if not keep_state:
            self.is_editing = False
            self.editing_entry_id = None
            self.is_duplicate_found = False
            self.duplicate_entry = None
            
        self.update_ui_for_mode()
        self._update_remove_button_state()
        self.scrollable_frame._parent_canvas.yview_moveto(0.0)

# --- Findings Entry Sub-Frame (Updated) ---
class FindingsEntry(ctk.CTkFrame):
    def __init__(self, master, index, accent_color, type_options, verified_options, field_labels, 
                 type_options_default, verified_options_default, **kwargs): 
        super().__init__(master, **kwargs)
        self.index = index
        self.type_options = type_options
        self.verified_options = verified_options
        self.accent_color = accent_color
        self.field_labels = field_labels 
        
        self.grid_columnconfigure(0, weight=0) # Options container
        self.grid_columnconfigure(1, weight=1) # Info Textbox
        self.grid_columnconfigure(2, weight=1) # Requirements/Verification Textboxes

        ctk.CTkLabel(self, text=f"Finding #{self.index}", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=5, pady=(5, 0), sticky="w", columnspan=3)

        # LEFT Container (Type and Verified Radio Buttons)
        options_container = ctk.CTkFrame(self, fg_color="transparent")
        options_container.grid(row=1, column=0, padx=5, pady=5, sticky="nsw")
        options_container.grid_columnconfigure(0, weight=1)
        current_row = 0

        # 1. Type
        self.type_var = ctk.StringVar(value=type_options_default) 
        ctk.CTkLabel(options_container, text=self.field_labels["finding_type_radio"]).grid(row=current_row, column=0, padx=0, pady=(2, 0), sticky="w")
        current_row += 1
        for option in self.type_options:
            ctk.CTkRadioButton(options_container, text=option, variable=self.type_var, value=option, 
                               fg_color=self.accent_color, hover_color=self.accent_color).grid(row=current_row, column=0, padx=1, sticky="w")
            current_row += 1

        # 2. Verified
        self.verified_var = ctk.StringVar(value=verified_options_default) 
        ctk.CTkLabel(options_container, text=self.field_labels["finding_verified_radio"]).grid(row=current_row, column=0, padx=0, pady=(5, 0), sticky="w")
        current_row += 1
        for option in self.verified_options:
            ctk.CTkRadioButton(options_container, text=option, variable=self.verified_var, value=option, 
                               fg_color=self.accent_color, hover_color=self.accent_color).grid(row=current_row, column=0, padx=1, sticky="w")
            current_row += 1

        # CENTER Container (Info Text Box)
        info_container = ctk.CTkFrame(self, fg_color="transparent")
        info_container.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        info_container.grid_columnconfigure(0, weight=1)
        info_container.grid_rowconfigure(1, weight=1)

        # 3. Info (Required Field)
        ctk.CTkLabel(info_container, text=self.field_labels["finding_info_textbox"]).grid(row=0, column=0, padx=0, pady=(2, 0), sticky="w")
        # APPLY INPUT COLOR: Finding Info Textbox
        self.info_textbox = ctk.CTkTextbox(info_container, height=100, wrap="word", fg_color=INPUT_BG_COLOR) 
        self.info_textbox.grid(row=1, column=0, padx=0, pady=5, sticky="nsew")
        
        # RIGHT Container (Requirements and Verification Textboxes)
        req_ver_container = ctk.CTkFrame(self, fg_color="transparent")
        req_ver_container.grid(row=1, column=2, padx=10, pady=5, sticky="nsew")
        req_ver_container.grid_columnconfigure(0, weight=1)
        req_ver_container.grid_rowconfigure((1, 3), weight=1)
        
        # 4. Requirements Textbox
        ctk.CTkLabel(req_ver_container, text=self.field_labels["requirements_textbox"]).grid(row=0, column=0, padx=0, pady=(5,0), sticky="w")
        # APPLY INPUT COLOR: Requirements Textbox
        self.requirements_textbox = ctk.CTkTextbox(req_ver_container, height=60, wrap="word", fg_color=INPUT_BG_COLOR) 
        self.requirements_textbox.grid(row=1, column=0, padx=0, pady=5, sticky="nsew")
        
        # 5. Verification Info Textbox
        ctk.CTkLabel(req_ver_container, text=self.field_labels["verification_info_textbox"]).grid(row=2, column=0, padx=0, pady=(5,0), sticky="w")
        # APPLY INPUT COLOR: Verification Info Textbox
        self.verification_info_textbox = ctk.CTkTextbox(req_ver_container, height=60, wrap="word", fg_color=INPUT_BG_COLOR) 
        self.verification_info_textbox.grid(row=3, column=0, padx=0, pady=5, sticky="nsew")

    def get_data(self):
        """Returns the data collected from this finding entry, including new fields."""
        return {
            "Type": self.type_var.get(),
            "Verified": self.verified_var.get(),
            "Info": self.info_textbox.get("1.0", "end-1c").strip(),
            "Requirements": self.requirements_textbox.get("1.0", "end-1c").strip(),
            "VerificationInfo": self.verification_info_textbox.get("1.0", "end-1c").strip()
        }

    def load_data(self, data):
        """Loads data into this finding entry, including new fields."""
        
        # Handle Type Conflict
        type_saved = data.get('Type')
        if type_saved in self.type_options:
            self.type_var.set(type_saved)
        else:
            first_option = APP_CONFIG["findings"]["_DEFAULT"]
            self.type_var.set(first_option)
            messagebox.showwarning("Configuration Conflict", 
                                   f"The saved Finding Type '{type_saved}' is no longer in the configuration. It was reset to '{first_option}' for editing.")
        
        # Handle Verified Conflict
        verified_saved = data.get('Verified')
        if verified_saved in self.verified_options:
            self.verified_var.set(verified_saved)
        else:
            last_option = APP_CONFIG["findings"]["_VERIFIED_DEFAULT"]
            self.verified_var.set(last_option)
            messagebox.showwarning("Configuration Conflict", 
                                   f"The saved Verified Status '{verified_saved}' is no longer in the configuration. It was reset to '{last_option}' for editing.")

        self.info_textbox.delete("1.0", "end")
        self.info_textbox.insert("1.0", data.get('Info', ''))
        
        self.requirements_textbox.delete("1.0", "end")
        self.requirements_textbox.insert("1.0", data.get('Requirements', ''))

        self.verification_info_textbox.delete("1.0", "end")
        self.verification_info_textbox.insert("1.0", data.get('VerificationInfo', ''))


# --- View Data Frame Class (Updated with Sorting and Layout) ---
class ViewDataFrame(ctk.CTkFrame):
    def __init__(self, master, data, load_entry_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.data = data
        self.load_entry_callback = load_entry_callback 
        self._tracking_detail_frames = {} 

        # New Configuration Attributes
        # Reference the global tracking data configuration
        self.TRACKING_DATA = APP_CONFIG["tracking"]["data"] 
        self.VIEW_COLUMNS_CONFIG = APP_CONFIG["view_columns"]
        self.ROW_TEXT_COLOR = self.VIEW_COLUMNS_CONFIG["ROW_TEXT_COLOR"] 
        self.HEADER_TEXT_COLOR = self.VIEW_COLUMNS_CONFIG["HEADER_TEXT_COLOR"]
        self.DEFAULT_FONT = ctk.CTkFont(size=self.VIEW_COLUMNS_CONFIG["FONT_SIZE"])
        self.BOLD_FONT = ctk.CTkFont(size=self.VIEW_COLUMNS_CONFIG["FONT_SIZE"], weight="bold")
        self.CLICK_FONT = ctk.CTkFont(size=self.VIEW_COLUMNS_CONFIG["FONT_SIZE"], weight="bold", underline=True)

        # Sorting attributes (Reintroduced)
        self.sort_data_key = "id"  # Default sorting key
        self.sort_direction = "asc" # Default sorting direction
        self.data_key_map = {c['name']: c['data_key'] for c in self.VIEW_COLUMNS_CONFIG["COLUMNS"]}


        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # --- Top Control Frame (Simplified - no filtering) ---
        self.control_frame = ctk.CTkFrame(self)
        self.control_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.control_frame.grid_columnconfigure((0, 1), weight=1)
        
        self.title_label = ctk.CTkLabel(self.control_frame, text="View and Edit Entries", 
                                        font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        # Verification Summary
        self.summary_label = ctk.CTkLabel(self.control_frame, text="Summary: Loading...", anchor="e")
        self.summary_label.grid(row=0, column=1, padx=10, pady=5, sticky="e")
        
        # Tracking Stats Frame
        self.tracking_stats_frame = ctk.CTkFrame(self.control_frame, fg_color="transparent")
        self.tracking_stats_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(5, 0), sticky="ew")
        self.tracking_stats_frame.grid_columnconfigure(0, weight=1)

        # --- Scrollable Data Area (Updated Header Style) ---
        # The label text is now the header
        self.scrollable_data_frame = ctk.CTkScrollableFrame(self, 
                                                            label_text="Data Entries (Click to Edit)",
                                                            label_font=ctk.CTkFont(size=14, weight="bold")) # Updated font
        self.scrollable_data_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.scrollable_data_frame.grid_columnconfigure(0, weight=1)
        
        # --- Header Frame (Fixed at the top of the scrollable frame) ---
        self.header_frame = ctk.CTkFrame(self.scrollable_data_frame, fg_color=("gray70", "gray20"))

    def _get_sort_value(self, item):
        """Helper to get a sortable value, handling nested dictionary keys."""
        parts = self.sort_data_key.split('.')
        value = item
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                # Handle custom keys
                if self.sort_data_key == "custom:verification_summary":
                    # Sort by the number of successes (first finding element)
                    findings = item.get('Findings', [])
                    if findings:
                        return findings[0].get('Verified', 'Untested')
                    return 'z'
                elif self.sort_data_key == "custom:tracking_status":
                    return self._calculate_tracking_status(item)
                elif self.sort_data_key in ["custom:creation_info", "custom:last_edit_info"]:
                    # Sort by timestamp from Info log
                    log = item.get('Main', {}).get('Info', [])
                    if log:
                        if self.sort_data_key == "custom:creation_info":
                            return log[0].get('timestamp', '0')
                        if self.sort_data_key == "custom:last_edit_info":
                            return log[-1].get('timestamp', '0')
                    return '0'
                
                return value
        return value

    def _sort_data_list(self, data):
        """Sorts the data list based on current key and direction."""
        if not data:
            return []
            
        reverse = self.sort_direction == "desc"
        
        try:
            # Custom sorting key function
            sorted_data = sorted(data, key=self._get_sort_value, reverse=reverse)
            return sorted_data
        except Exception:
            # Fallback to sorting by ID if the primary sort fails (e.g., mixing types)
            return sorted(data, key=lambda x: x.get('id', 0), reverse=reverse)


    def _sort_data(self, column_name):
        """Updates sorting attributes and triggers a display refresh."""
        data_key = self.data_key_map.get(column_name)
        if data_key:
            # If clicking the currently active key, toggle direction
            if self.sort_data_key == data_key:
                self.sort_direction = "desc" if self.sort_direction == "asc" else "asc"
            # If clicking a new key, set it as active and reset to ascending
            else:
                self.sort_data_key = data_key
                self.sort_direction = "asc"
            
            # Since self.data holds a reference to the global data, pass it explicitly to update_display
            self.update_display(self.data) 

    def _calculate_verification_status(self, entry):
        """Calculates success/failure/untested counts and determines row color."""
        findings = entry.get('Findings', [])
        counts = defaultdict(int)
        
        SUCCESS = APP_CONFIG["findings"]["SUCCESS_STATUS"]
        FAILURE = APP_CONFIG["findings"]["FAILURE_STATUS"]
        UNTESTED = APP_CONFIG["findings"]["UNVERIFIED_STATUS"]

        for finding in findings:
            verified_status = finding.get('Verified', UNTESTED)
            counts[verified_status] += 1

        total = len(findings)
        num_success = counts[SUCCESS]
        num_failure = counts[FAILURE]
        num_untested = counts[UNTESTED]
        
        # --- Determine Row Color (Background Color) ---
        if total == 0 or num_untested > 0:
            row_fg_color = UNVERIFIED_COLOR_BLUE_ROW
        elif num_success > 0 and num_failure == 0:
            row_fg_color = ALL_SUCCESS_COLOR_GREEN_ROW
        else: # num_failure > 0
            row_fg_color = ALL_FAILURE_COLOR_RED_ROW
            
        return total, num_success, num_failure, num_untested, row_fg_color

    def _calculate_tracking_status(self, entry):
        """Checks if the entry's main name is in the configured tracking list."""
        entry_name = entry.get('Main', {}).get('MainName')
        entry_filepath = entry.get('Main', {}).get('Filepath')
        
        # Check against the specific filepath lists
        for tracking_item in self.TRACKING_DATA: 
            if tracking_item["filepath"] == entry_filepath and entry_name in tracking_item["entries"]:
                return "Tracked (Found)"
        
        return "Untracked (Missing)"
    
    def _create_header(self):
        """Sets up the fixed header row for the data table using the new config and styling."""
        for widget in self.header_frame.winfo_children():
            widget.destroy()
            
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        
        column_configs = self.VIEW_COLUMNS_CONFIG["COLUMNS"]
        
        for i, config in enumerate(column_configs):
            weight = config["weight"]
            
            # Use integer weight for grid_columnconfigure
            self.header_frame.grid_columnconfigure(i, weight=weight) 
            
            # Determine sorting indicator
            indicator = ""
            if self.sort_data_key == config['data_key']:
                 indicator = " ▲" if self.sort_direction == "asc" else " ▼"

            header_label = ctk.CTkLabel(self.header_frame, text=config["name"] + indicator, 
                         font=self.BOLD_FONT, 
                         fg_color=self.header_frame.cget("fg_color"),
                         text_color=self.HEADER_TEXT_COLOR, 
                         anchor="w")
                         
            header_label.grid(row=0, column=i, padx=5, pady=5, sticky="ew")
            
            # Bind click event for sorting
            header_label.bind("<Button-1>", lambda event, k=config['name']: self._sort_data(k))
            # Bind events to the header frame itself for better click area
            header_label.bind("<Enter>", lambda event, k=config['name']: header_label.configure(text_color=PURPLE_HUE))
            header_label.bind("<Leave>", lambda event, k=config['name']: header_label.configure(text_color=self.HEADER_TEXT_COLOR))


    def _on_click(self, event, entry):
        """Handle row click to load the entry for editing."""
        self.master.lift()
        self.master.focus_force()
        self.load_entry_callback(entry)

    def _on_hover(self, event, row_frame, original_color):
        """Handles mouse entering a row."""
        row_frame.configure(fg_color=HIGHLIGHT_HOVER_COLOR)
        for widget in row_frame.winfo_children():
             widget.configure(text_color=HIGHLIGHT_TEXT_COLOR)

    def _on_leave(self, event, row_frame, original_color):
        """Handles mouse leaving a row."""
        row_frame.configure(fg_color=original_color)
        for widget in row_frame.winfo_children():
             # Reset text color to white as requested
             widget.configure(text_color=self.ROW_TEXT_COLOR)

    def _update_stats(self, display_data):
        """
        Updates the tracking statistics frame.
        """
        for widget in self.tracking_stats_frame.winfo_children():
            widget.destroy()

        self._tracking_detail_frames = {} 

        tracking_data = self._get_tracking_data(display_data)

        self.tracking_stats_frame.grid_columnconfigure((0, 1, 2), weight=1) 
        ctk.CTkLabel(self.tracking_stats_frame, text="Tracking Status per Project Folder:", font=self.BOLD_FONT).grid(row=0, column=0, padx=5, pady=(5, 0), sticky="w", columnspan=3)
        
        status_row_index = 1
        for item in tracking_data:
            filepath = item["filepath"]
            missing_entries = item["missing"]
            found_entries = item["found"]
            total_required = item["total_required"]

            if total_required == 0:
                continue

            num_missing = len(missing_entries)
            
            if num_missing == 0:
                status_text = "✅ COMPLETE"
                status_color = FOUND_ENTRY_COLOR_TRACKING
            else:
                status_text = f"❌ {num_missing}/{total_required} MISSING"
                status_color = MISSING_ENTRY_COLOR
            
            ctk.CTkLabel(self.tracking_stats_frame, text=f"• {filepath}:", anchor="w").grid(row=status_row_index, column=0, padx=(10, 0), pady=2, sticky="w")

            ctk.CTkLabel(self.tracking_stats_frame, text=status_text, text_color=status_color, font=self.BOLD_FONT).grid(row=status_row_index, column=1, padx=(5, 0), pady=2, sticky="w")

            status_button = ctk.CTkButton(self.tracking_stats_frame, text="Show Details", width=100, fg_color=CLICK_INDICATOR_COLOR)
            
            status_button.configure(
                command=lambda fp=filepath, m=missing_entries, f=found_entries, btn=status_button, r_idx=status_row_index + 1: self._toggle_tracking_details(fp, m, f, btn, r_idx)
            )
            
            status_button.grid(row=status_row_index, column=2, padx=(5, 10), pady=2, sticky="e")

            status_row_index += 1
            
            details_frame = ctk.CTkFrame(self.tracking_stats_frame, fg_color="transparent")
            self._tracking_detail_frames[filepath] = (details_frame, status_button, status_row_index)
            status_row_index += 1
            
    def _get_tracking_data(self, display_data):
        """Calculates which required tracking entries are present in the display_data."""
        
        tracking_summary = []
        for tracking_item in self.TRACKING_DATA: 
            filepath = tracking_item["filepath"]
            missing_entries = []
            found_entries = []
            
            for required_entry_name in tracking_item["entries"]:
                
                is_found = any(
                    entry.get('Main', {}).get('Filepath') == filepath and 
                    entry.get('Main', {}).get('MainName') == required_entry_name
                    for entry in display_data
                )
                
                if is_found:
                    found_entries.append(required_entry_name)
                else:
                    missing_entries.append(required_entry_name)

            tracking_summary.append({
                "filepath": filepath,
                "missing": missing_entries,
                "found": found_entries,
                "total_required": len(tracking_item["entries"])
            })
            
        return tracking_summary

    def _toggle_tracking_details(self, filepath, missing_entries, found_entries, button, detail_frame_row):
        """Toggles the visibility of tracking details for a project folder."""
        details_frame, _, _ = self._tracking_detail_frames.get(filepath, (None, None, None))
        
        if not details_frame:
            return

        is_visible = details_frame.grid_info()
        
        for widget in details_frame.winfo_children():
            widget.destroy()

        if is_visible:
            details_frame.grid_remove()
            button.configure(text="Show Details")
        else:
            details_frame.grid_columnconfigure((0, 1), weight=1) 
            
            missing_text = "Missing Entries:\n" + "\n".join([f"- {e}" for e in missing_entries]) if missing_entries else "Missing Entries: None"
            found_text = "Found Entries:\n" + "\n".join([f"- {e}" for e in found_entries]) if found_entries else "Found Entries: None"
            
            # Use default white text color for all
            ctk.CTkLabel(details_frame, text=missing_text, justify="left", anchor="nw", text_color=self.ROW_TEXT_COLOR).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
            ctk.CTkLabel(details_frame, text=found_text, justify="left", anchor="nw", text_color=self.ROW_TEXT_COLOR).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            details_frame.grid(row=detail_frame_row, column=0, columnspan=3, padx=(15, 10), pady=(0, 10), sticky="ew")
            button.configure(text="Hide Details")


    def update_display(self, data):
        """Sorts data and draws the table."""
        
        # 1. Sort the data based on current criteria
        self.data = self._sort_data_list(data) 
        
        # 2. Clear all previous row frames (but not the header)
        for widget in self.scrollable_data_frame.winfo_children():
            if widget != self.header_frame:
                widget.destroy()

        # 3. Update stats based on the sorted/full data
        self._update_stats(self.data)

        # 4. Re-create header (handles sort indicators)
        self._create_header()

        total_success_entries = 0
        total_failure_entries = 0
        
        column_configs = self.VIEW_COLUMNS_CONFIG["COLUMNS"]

        for row_index, entry in enumerate(self.data):
            
            # 5. Calculate Statuses and determine row colors
            total_findings, num_success, num_failure, num_untested, row_fg_color = self._calculate_verification_status(entry)
            tracking_status = self._calculate_tracking_status(entry)
            
            # Update summary counts
            if num_success > 0 and num_failure == 0:
                total_success_entries += 1
            if num_failure > 0:
                total_failure_entries += 1

            # 6. Create the row frame (Row index starts at 1 below the header)
            row_frame = ctk.CTkFrame(self.scrollable_data_frame, fg_color=row_fg_color, corner_radius=5)
            row_frame.grid(row=row_index + 1, column=0, padx=5, pady=(2, 2), sticky="ew")
            
            # Configure row columns to match header columns (using configured weights)
            for i, config in enumerate(column_configs):
                 row_frame.grid_columnconfigure(i, weight=config['weight'])

            # Bind click/hover events to the row frame
            row_frame.bind("<Button-1>", lambda event, entry=entry: self._on_click(event, entry))
            
            def create_bound_label(parent, text, column, font=self.DEFAULT_FONT, text_color=self.ROW_TEXT_COLOR, anchor="w", justify="left"):
                """Helper to create a label and bind necessary events."""
                label = ctk.CTkLabel(parent, text=text, font=font, text_color=text_color, anchor=anchor, justify=justify)
                label.grid(row=0, column=column, padx=5, pady=5, sticky="ew")
                
                label.bind("<Button-1>", lambda event, entry=entry: self._on_click(event, entry))
                label.bind("<Enter>", lambda event, rf=row_frame, oc=row_fg_color: self._on_hover(event, rf, oc))
                label.bind("<Leave>", lambda event, rf=row_frame, oc=row_fg_color: self._on_leave(event, rf, oc))
                return label

            # Parse common entry data once
            entry_id = entry.get('id', 'N/A')
            main_data = entry.get('Main', {})
            description_data = entry.get('Description', {}) # For Description Type
            creation_ts, creation_user, last_edit_ts, last_edit_user = parse_info_log(main_data.get('Info', []))
            verification_summary = f"S:{num_success}/F:{num_failure}/U:{num_untested} (Total:{total_findings})"

            # 7. Loop through the configured columns to populate the row
            for col_index, config in enumerate(column_configs):
                data_key = config["data_key"]
                
                display_text = 'N/A'
                display_font = self.DEFAULT_FONT
                justify = "left"
                anchor = "w"

                if data_key == "id":
                    display_text = str(entry_id)
                elif data_key == "Main.MainName":
                    display_text = main_data.get('MainName', 'N/A')
                elif data_key == "Main.Filepath":
                    display_text = main_data.get('Filepath', 'N/A') 
                elif data_key == "Description.Type":
                     display_text = description_data.get('Type', 'N/A')
                
                # Custom/Calculated Fields
                elif data_key == "custom:verification_summary":
                    display_text = verification_summary
                elif data_key == "custom:tracking_status":
                    display_text = tracking_status
                    display_font = self.BOLD_FONT 
                elif data_key == "custom:creation_info":
                    display_text = f"{creation_ts}\n({creation_user})"
                    justify = "center"
                    anchor = "center"
                elif data_key == "custom:last_edit_info":
                    display_text = f"{last_edit_ts}\n({last_edit_user})"
                    justify = "center"
                    anchor = "center"
                
                # Create the label
                create_bound_label(row_frame, display_text, col_index, 
                                   font=display_font, justify=justify, anchor=anchor) 
            
        # Update Global Summary Label
        total_entries = len(data)
        summary_text = f"Total Entries: {total_entries} | Successful: {total_success_entries} | Failing: {total_failure_entries}"
        self.summary_label.configure(text=summary_text)


# --- Main Execution ---

if __name__ == "__main__":
    # Setup testing environment
    if not os.path.exists(SOURCE_FOLDER):
        os.makedirs(SOURCE_FOLDER)
    if not os.path.exists(os.path.join(SOURCE_FOLDER, DEFAULT_FOLDER_OPTION)):
        os.makedirs(os.path.join(SOURCE_FOLDER, DEFAULT_FOLDER_OPTION))
    
    # Check if a specific file path needs to be created for the tracking config
    for tracking_item in TRACKING_DATA: 
         if not os.path.exists(os.path.join(SOURCE_FOLDER, tracking_item["filepath"])):
             os.makedirs(os.path.join(SOURCE_FOLDER, tracking_item["filepath"]))
    
    if sys.version_info < (3, 7):
        messagebox.showerror("Python Version Error", "This application requires Python 3.7 or newer.")
        sys.exit(1)
        
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        error_message = f"An unexpected fatal error occurred: {e}"
        if 'App' in locals() and 'messagebox' in globals():
            messagebox.showerror("Fatal Application Error", error_message)
        else:
            print(error_message)
        sys.exit(1)