import os
import time
import datetime
import logging
import json
import sys
import re
import shlex
import importlib

# --- Library Import with Fallback ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.logging import RichHandler
    RICH_INSTALLED = True
except ImportError:
    RICH_INSTALLED = False
    print("Warning: 'rich' library not found. Falling back to basic console output.")
    print("For a better experience, please install it with 'pip install rich'.")

    class DummyConsole:
        def print(self, *args, **kwargs):
            text_to_print = []
            for arg in args:
                if hasattr(arg, 'plain'):
                    text_to_print.append(arg.plain)
                else:
                    text_to_print.append(str(arg))
            full_text = " ".join(text_to_print)
            clean_text = re.sub(r'\[.*?\]', '', full_text)
            print(clean_text)

        def input(self, prompt_text):
            clean_prompt = re.sub(r'\[.*?\]', '', prompt_text)
            return input(clean_prompt)
        
        def rule(self, *args, **kwargs):
            print("-" * 80)

    console = DummyConsole()
    class Panel:
        def __init__(self, *args, **kwargs):
            pass
        @staticmethod
        def fit(content):
            return content
    class Text:
        def __init__(self, text="", style=""):
            self.text = text
            self.plain = text
        def __add__(self, other):
            return self.text + str(other)
        def append(self, text, style=None):
            self.text += str(text)
            self.plain += str(text)

    Live = lambda *args, **kwargs: type('DummyLive', (object,), {'__enter__': lambda s: None, '__exit__': lambda s, *e: None})()


try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.document import Document
    PROMPT_TOOLKIT_INSTALLED = True
except ImportError:
    PROMPT_TOOLKIT_INSTALLED = False
    print("Warning: 'prompt_toolkit' library not found. Falling back to basic input.")
    print("For a better experience with autocompletion, please install it with 'pip install prompt_toolkit'.")
    def prompt(text, completer=None):
        return input(re.sub(r'\[.*?\]', '', text))


# --- Configuration & API Key Loading ---
API_CONFIG = {
    'openai': {
        'name': 'OpenAI',
        'module': 'openai',
        'models': {
            'gpt-4o': 'gpt-4o',
            'gpt-4o-mini': 'gpt-4o-mini',
            'gpt-3.5-turbo': 'gpt-3.5-turbo'
        },
        'api_key_env': 'OPENAI_API_KEY',
        'api_key_file': 'openai_api_key'
    },
    'gemini': {
        'name': 'Google Gemini',
        'module': 'google.generativeai',
        'models': {
            'gemini-2.5-pro': 'gemini-2.5-pro',
            'gemini-2.5-flash': 'gemini-2.5-flash',
            'gemini-1.5-pro': 'gemini-1.5-pro',
            'gemini-1.5-flash': 'gemini-1.5-flash',
        },
        'api_key_env': 'GEMINI_API_KEY',
        'api_key_file': 'gemini_api_key'
    },
    'mistral': {
        'name': 'Mistral AI',
        'module': 'mistralai',
        'models': {
            'mistral-large-latest': 'mistral-large-latest',
            'mistral-medium-latest': 'mistral-medium-latest',
            'mistral-small-latest': 'mistral-small-latest',
            'mistral-tiny': 'mistral-tiny'
        },
        'api_key_env': 'MISTRAL_API_KEY',
        'api_key_file': 'mistral_api_key'
    },
    'anthropic': {
        'name': 'Anthropic',
        'module': 'anthropic',
        'models': {
            'claude-3-opus': 'claude-3-opus-20240229',
            'claude-3-sonnet': 'claude-3-sonnet-20240229',
            'claude-3-haiku': 'claude-3-haiku-20240307'
        },
        'api_key_env': 'ANTHROPIC_API_KEY',
        'api_key_file': 'anthropic_api_key'
    }
}

def load_api_key(base_filename, env_var):
    """
    Attempts to load an API key from a file with or without a .txt extension,
    or falls back to an environment variable.
    """
    filename_txt = "{}.txt".format(base_filename)
    if os.path.exists(filename_txt):
        try:
            with open(filename_txt, 'r') as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception as e:
            print("Error reading {}: {}".format(filename_txt, e))
    
    if os.path.exists(base_filename):
        try:
            with open(base_filename, 'r') as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception as e:
            print("Error reading {}: {}".format(base_filename, e))

    return os.getenv(env_var)

# File search directory and model settings
FILE_DIRECTORY = "./documents"
MAX_FILE_SUGGESTIONS = 10
MAX_FILE_SIZE_MB = 5

# --- Logging Setup ---
log_filename = "chat_history.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_filename, mode='a', encoding='utf-8')
    ]
)
log = logging.getLogger(__name__)

if RICH_INSTALLED:
    console = Console()
else:
    console = DummyConsole()

# --- Custom Autocomplete Class ---
if PROMPT_TOOLKIT_INSTALLED:
    class ChatCompleter(Completer):
        def __init__(self, file_directory, all_files):
            self.file_directory = file_directory
            self.commands = ['/suggest', '/suggestLast', '/run_deep', 'exit']
            self.all_files = all_files

        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            words = shlex.split(text)
            
            if not text or (len(words) == 1 and text.startswith(words[0])):
                command = words[0] if words else ''
                for cmd in self.commands:
                    if cmd.startswith(command):
                        yield Completion(cmd, start_position=-len(command))
            elif len(words) >= 2 and words[0] == '/suggest':
                search_text = words[-1]
                try:
                    for relative_path in self.all_files:
                        if search_text.lower() in relative_path.lower():
                            yield Completion(relative_path, start_position=-len(search_text))
                except FileNotFoundError:
                    pass
            elif words[0] in ['/suggestLast', '/run_deep']:
                pass

# --- API Handlers ---
def get_openai_response(messages, model_name):
    try:
        response = openai.chat.completions.create(
            model=model_name,
            messages=messages
        )
        return response.choices[0].message.content
    except Exception as e:
        return "Error with OpenAI API: {}".format(e)

def get_gemini_response(messages, model_name):
    try:
        # Gemini API does not handle the "system" role well, so we adjust.
        formatted_messages = []
        for msg in messages:
            if msg["role"] == "user":
                formatted_messages.append({'role': 'user', 'parts': [msg["content"]]})
            elif msg["role"] == "assistant":
                formatted_messages.append({'role': 'model', 'parts': [msg["content"]]})
        
        gemini_model = GenerativeModel(model_name)
        
        response = gemini_model.generate_content(formatted_messages)
        return response.text
    except Exception as e:
        return "Error with Gemini API: {}".format(e)
    
def get_mistral_response(messages, model_name):
    try:
        client = MistralClient(api_key=MISTRAL_API_KEY)
        response = client.chat(
            model=model_name,
            messages=messages
        )
        return response.choices[0].message.content
    except Exception as e:
        return "Error with Mistral API: {}".format(e)

def get_anthropic_response(messages, model_name):
    try:
        client = anthropic.Anthropic()
        # Anthropic's message format is slightly different and requires a `messages` list
        # of dicts with `role` and `content` and a `system` prompt
        system_prompt = next((msg['content'] for msg in messages if msg['role'] == 'system'), None)
        user_messages = [{"role": "user", "content": msg['content']} for msg in messages if msg['role'] != 'system']

        response = client.messages.create(
            model=model_name,
            max_tokens=1024,
            messages=user_messages,
            system=system_prompt
        )
        return response.content[0].text
    except Exception as e:
        return f"Error with Anthropic API: {e}"

# --- File Handling ---
def read_file_content(filepath):
    if not os.path.exists(filepath):
        return None, "Error: File not found."
    
    if os.path.getsize(filepath) > MAX_FILE_SIZE_MB * 1024 * 1024:
        return None, "Error: File '{}' is too large.".format(os.path.basename(filepath))
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read(), None
    except Exception as e:
        return None, "Error reading file: {}".format(e)

def build_filename_index(all_files):
    """
    Builds a keyword index of filenames for fast lookups.
    """
    index = {}
    for relative_path in all_files:
        filename_only = os.path.basename(relative_path).lower()
        filename_no_ext = os.path.splitext(filename_only)[0]
        keywords = re.findall(r'[\w\.-_]+', filename_no_ext)
        
        for keyword in keywords:
            if len(keyword) > 2:
                if keyword not in index:
                    index[keyword] = set()
                index[keyword].add(relative_path)
    return index

def get_file_suggestions(keywords, all_files, search_content=False, user_initiated=False, ai_response_text=""):
    """
    Finds file suggestions based on keywords.

    Args:
        keywords (list): A list of keywords to search for.
        all_files (list): A list of all relative file paths.
        search_content (bool): True for deep search, False for filename search.
        user_initiated (bool): True for user-initiated search (substring on full path).
        ai_response_text (str): The AI's response text for exact substring matching.

    Returns:
        list: A list of tuples (file_path, snippet) for deep search, or (file_path, None) for others.
    """
    found_files = []
    keywords_set = set(k.lower().strip() for k in keywords)
    
    # Store found files to prevent duplicates
    found_paths = set()

    if search_content:
        # This is the new, strict logic for AI response matching
        ai_response_text_lower = ai_response_text.lower()
        for relative_path in all_files:
            filename_no_ext = os.path.splitext(os.path.basename(relative_path))[0].lower()
            if filename_no_ext in ai_response_text_lower:
                found_files.append((relative_path, None))
                found_paths.add(relative_path)
    elif user_initiated:
        # This is the existing logic for /suggest
        for keyword in keywords_set:
            for relative_path in all_files:
                if relative_path in found_paths:
                    continue
                if keyword in relative_path.lower():
                    found_files.append((relative_path, None))
                    found_paths.add(relative_path)
                    if len(found_files) >= MAX_FILE_SUGGESTIONS:
                        break
            if len(found_files) >= MAX_FILE_SUGGESTIONS:
                break
    else:
        # This is the fallback for other searches, not directly requested by the user
        for keyword in keywords_set:
            for relative_path in all_files:
                if relative_path in found_paths:
                    continue
                filename_full = os.path.basename(relative_path).lower()
                filename_base = os.path.splitext(filename_full)[0].lower()
                
                if keyword in filename_full or keyword in filename_base:
                    found_files.append((relative_path, None))
                    found_paths.add(relative_path)
                    if len(found_files) >= MAX_FILE_SUGGESTIONS:
                        break
            if len(found_files) >= MAX_FILE_SUGGESTIONS:
                break

    return found_files

# --- Main Logic ---
def get_ai_response(messages, api_choice, model_choice):
    if api_choice.lower() == 'openai':
        return get_openai_response(messages, model_choice)
    elif api_choice.lower() == 'gemini':
        return get_gemini_response(messages, model_choice)
    elif api_choice.lower() == 'mistral':
        return get_mistral_response(messages, model_choice)
    elif api_choice.lower() == 'anthropic':
        return get_anthropic_response(messages, model_choice)
    else:
        return "Invalid API choice."

def extract_keywords(text):
    # This regex matches words and words containing punctuation or special characters, but not standalone punctuation.
    words = re.findall(r'[a-zA-Z0-9]+[a-zA-Z0-9\.\-_]*[a-zA-Z0-9]+', text.lower())
    # A simple list of common English stopwords to exclude
    stopwords = {'a', 'an', 'and', 'are', 'as', 'at', 'be', 'but', 'by', 'for', 'if', 'in', 'into', 'is', 'it', 'no', 'not', 'of', 'on', 'or', 'such', 'that', 'the', 'their', 'then', 'there', 'these', 'they', 'this', 'to', 'was', 'will', 'with'}
    
    keywords = []
    for word in words:
        # Exclude stopwords and very short words
        if word not in stopwords and len(word) > 1:
            keywords.append(word)

    return list(set(keywords))

def display_and_select_files(suggestions, sent_files, keywords=None):
    if not suggestions:
        if RICH_INSTALLED:
            console.print(Panel(Text("No files found matching the criteria.", style="bold yellow"), border_style="yellow"))
        else:
            console.print("No files found matching the criteria.")
        return None

    new_suggestions = [s for s in suggestions if s[0] not in sent_files]
    given_suggestions = [s for s in suggestions if s[0] in sent_files]
    
    display_list = new_suggestions + given_suggestions
    unique_display_list = []
    seen_paths = set()
    for item in display_list:
        if item[0] not in seen_paths:
            unique_display_list.append(item)
            seen_paths.add(item[0])

    if RICH_INSTALLED:
        all_suggestions_text = Text()
        for i, (filename, snippet) in enumerate(unique_display_list):
            
            # Create a highlightable text object for the filename
            filename_text = Text(filename, style="cyan" if filename not in sent_files else "red")
            
            # The corrected section: iterate through keywords to apply highlighting
            if keywords:
                for keyword in keywords:
                    filename_text.highlight_regex(r'(?i)' + re.escape(keyword), style="bold magenta")
            # End of corrected section

            text = Text(f"[{i+1}] ", style="white") + filename_text
            
            if snippet:
                text.append(f"\n  Match: ", style="bold")
                
                # Create a highlightable text object for the snippet
                snippet_text = Text(snippet, style="dim white")
                for keyword in keywords:
                    snippet_text.highlight_regex(re.escape(keyword), style="bold yellow")
                text.append(snippet_text)

            all_suggestions_text.append(text)
            if i < len(unique_display_list) - 1:
                all_suggestions_text.append("\n")

        console.print(Panel(all_suggestions_text, title="I found these files that might be relevant:", style="white"))
    else:
        print("I found these files that might be relevant:")
        for i, (filename, snippet) in enumerate(unique_display_list):
            status = "(already sent)" if filename in sent_files else ""
            print(f"[{i+1}] {filename} {status}")
            if snippet:
                print(f"  Match: {snippet}")
    
    selected_files = []
    
    choice_str = console.input("Please enter file numbers separated by commas (e.g., 1,3), or press Enter to skip: ")
    
    if not choice_str:
        if RICH_INSTALLED:
            console.print("[bold yellow]Skipping file inclusion.[/bold yellow]")
        else:
            console.print("Skipping file inclusion.")
        return None

    try:
        choice_parts = [p.strip() for p in choice_str.split(',')]
        for choice_part in choice_parts:
            try:
                choice = int(choice_part)
                index = choice - 1
                if 0 <= index < len(unique_display_list):
                    selected_files.append(unique_display_list[index][0])
                else:
                    console.print(f"[bold red]Invalid input:[/bold red] File number '{choice_part}' is out of range.")
            except ValueError:
                console.print(f"[bold red]Invalid input:[/bold red] '{choice_part}' is not a valid number.")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred during selection:[/bold red] {e}")

    return selected_files


def process_and_send_files(selected_files, conversation_history, api_choice, selected_model, all_files, sent_files, keywords_to_highlight=None):
    if not selected_files:
        return conversation_history, None, sent_files
    
    full_content = ""
    for file_to_send in selected_files:
        sent_files.add(file_to_send)
        content, error = read_file_content(os.path.join(FILE_DIRECTORY, file_to_send))
        if content:
            full_content += "--- File: {} ---\n{}\n".format(file_to_send, content)
        else:
            console.print("{}".format(error))
    
    additional_prompt = console.input("Provide a prompt to go with the files (optional): ")
    user_message_content = "File Content:\n```\n{}\n```\n\nUser Query: {}".format(full_content, additional_prompt)
    
    log.info("User sent files: %s with prompt: %s", ', '.join(selected_files), additional_prompt)

    conversation_history.append({"role": "user", "content": user_message_content})
    ai_message = get_ai_response(conversation_history, api_choice, selected_model)
    
    last_ai_response = ai_message
    
    # AI response suggestions and highlighting (new logic)
    ai_suggestions = []
    keywords_to_highlight_in_response = []
    if not ai_message.startswith("Error with"):
        ai_suggestions = get_file_suggestions([], all_files, search_content=True, ai_response_text=ai_message)
        last_suggestions = ai_suggestions
        
        # Get keywords from the suggested filenames for highlighting
        for file_suggestion, _ in ai_suggestions:
            filename_no_ext = os.path.splitext(os.path.basename(file_suggestion))[0]
            keywords_to_highlight_in_response.append(filename_no_ext)
        
        if keywords_to_highlight_in_response:
            log.info("Recommended files based on AI response: %s", ', '.join([s[0] for s in ai_suggestions]))

    if RICH_INSTALLED:
        formatted_ai_message = Text(ai_message)
        for keyword in keywords_to_highlight_in_response:
            formatted_ai_message.highlight_regex(r'(?i)' + re.escape(keyword), style="bold magenta")
        
        console.print(Panel(formatted_ai_message, title="AI Response", style="white"))

    else:
        console.print("\nAI: {}".format(ai_message))
    
    log.info("AI: {}".format(ai_message))
    conversation_history.append({"role": "assistant", "content": ai_message})
    
    if ai_suggestions:
        selected_files = display_and_select_files(last_suggestions, sent_files, keywords_to_highlight_in_response)
        if selected_files:
            conversation_history, last_ai_response, sent_files = process_and_send_files(selected_files, conversation_history, api_choice, selected_model, all_files, sent_files)
    else:
        if RICH_INSTALLED:
            console.print(Panel(Text("I didn't find any relevant files automatically.", justify="center"), style="bold yellow"))
        else:
            console.print("I didn't find any relevant files automatically.")
    
    if RICH_INSTALLED:
        console.print("For a broader search, use '[bold yellow]/run_deep[/bold yellow]'.")
    else:
        console.print("For a broader search, use '/run_deep'.")

    return conversation_history, last_ai_response, sent_files


def display_api_options():
    api_providers = list(API_CONFIG.keys())
    if RICH_INSTALLED:
        console.print(Text("Choose your AI API:", style="bold white"))
        colors = ['cyan', 'magenta', 'green', 'blue']
        all_api_text = Text()
        for i, provider in enumerate(api_providers):
            color = colors[i % len(colors)]
            text = Text(f"[{i+1}] ", style="white") + Text(API_CONFIG[provider]['name'], style=color)
            all_api_text.append(text)
            if i < len(api_providers) - 1:
                all_api_text.append("\n")
        console.print(Panel(all_api_text, border_style="dim"))
    else:
        console.print("Choose your AI API:")
        for i, provider in enumerate(api_providers):
            console.print(f"[{i+1}] {API_CONFIG[provider]['name']}")
    return api_providers

def display_model_options(api_choice_name):
    models = list(API_CONFIG.get(api_choice_name, {}).get('models', {}).keys())
    if not models:
        console.print("No models available for this API.")
        return
    if RICH_INSTALLED:
        console.print(Text("Choose a model:", style="bold white"))
        all_models_text = Text()
        for i, model in enumerate(models):
            text = Text(f"[{i+1}] ", style="white") + Text(model, style="cyan")
            all_models_text.append(text)
            if i < len(models) - 1:
                all_models_text.append("\n")
        console.print(Panel(all_models_text, border_style="dim"))
    else:
        console.print("Choose a model:")
        for i, model in enumerate(models):
            console.print(f"[{i+1}] {model}")
    return models

def main():
    if RICH_INSTALLED:
        console.print(Panel("✨ [bold green]Welcome to the AI Chatbot![/bold green] ✨", style="bold blue", padding=(1, 2)))
    else:
        console.print("Welcome to the AI Chatbot!")
    
    api_providers = display_api_options()
    
    api_choice_name = None
    while not api_choice_name:
        try:
            api_choice_num = console.input("Enter number for API: ")
            api_index = int(api_choice_num) - 1
            if 0 <= api_index < len(api_providers):
                api_choice_name = api_providers[api_index]
            else:
                console.print("Invalid selection. Please choose a number from the list.")
        except (ValueError, IndexError):
            console.print("Invalid input. Please enter a number.")

    config = API_CONFIG[api_choice_name]
    try:
        module = importlib.import_module(config['module'])
        if api_choice_name == 'openai':
            globals()['openai'] = module
        elif api_choice_name == 'gemini':
            globals()['GenerativeModel'] = module.GenerativeModel
            globals()['configure'] = module.configure
        elif api_choice_name == 'mistral':
            globals()['MistralClient'] = module.MistralClient
        elif api_choice_name == 'anthropic':
            globals()['anthropic'] = module
    except ImportError:
        console.print(f"Error: The '{config['module']}' library is not installed. Please install it with 'py -m pip install {config['module']}'")
        return

    api_key = load_api_key(config['api_key_file'], config['api_key_env'])
    if not api_key:
        console.print(f"Error: No {config['name']} API key found. Please set it in a file or environment variable.")
        return
    
    if api_choice_name == 'openai':
        openai.api_key = api_key
    elif api_choice_name == 'gemini':
        configure(api_key=api_key)
    elif api_choice_name == 'mistral':
        globals()['MISTRAL_API_KEY'] = api_key
    elif api_choice_name == 'anthropic':
        globals()['ANTHROPIC_API_KEY'] = api_key

    models = display_model_options(api_choice_name)
    model_choice_name = None
    while not model_choice_name:
        try:
            model_choice_num = console.input("Enter number for Model: ")
            model_index = int(model_choice_num) - 1
            if 0 <= model_index < len(models):
                model_choice_name = models[model_index]
            else:
                console.print("Invalid selection. Please choose a number from the list.")
        except (ValueError, IndexError):
            console.print("Invalid input. Please enter a number.")
    
    selected_model = config['models'][model_choice_name]
    
    all_files = []
    if os.path.exists(FILE_DIRECTORY):
        for root, dirs, files in os.walk(FILE_DIRECTORY):
            for filename in files:
                full_path = os.path.join(root, filename)
                relative_path = os.path.relpath(full_path, FILE_DIRECTORY)
                all_files.append(relative_path)
    else:
        console.print(f"Error: The directory '{FILE_DIRECTORY}' does not exist.")
        return

    
    filename_index = build_filename_index(all_files)
    conversation_history = []
    sent_files = set()
    last_suggestions = []
    last_ai_response = ""
    
    if RICH_INSTALLED:
        console.print("\n[bold white]How to interact with the AI:[/bold white]")
        console.print("  [white]1.[/white] Type your prompt directly to the AI.")
        console.print("  [white]2.[/white] Use '[bold yellow]/suggest <keyword>[/bold yellow]' to find specific files.")
        console.print("  [white]3.[/white] To select a file from AI suggestions, use '[bold yellow]/suggestLast <number>[/bold yellow]'.")
        console.print("  [white]4.[/white] Use '[bold yellow]/run_deep[/bold yellow]' to search file content based on the last AI response.")
        console.print("  [white]5.[/white] Type '[bold red]exit[/bold red]' to quit the program.")
    else:
        console.print("\nHow to interact with the AI:")
        console.print("  1. Type your prompt directly to the AI.")
        console.print("  2. Use '/suggest <keyword>' to find specific files.")
        print("  3. To select a file from AI suggestions, use '/suggestLast <number>'.")
        print("  4. Use '/run_deep' to search file content based on the last AI response.")
        print(" 5. Type 'exit' to quit the program.")

    if PROMPT_TOOLKIT_INSTALLED:
        completer = ChatCompleter(FILE_DIRECTORY, all_files)
    else:
        completer = None

    try:
        while True:
            user_input = prompt("\n> ", completer=completer)
            
            if user_input.lower() == 'exit':
                if RICH_INSTALLED:
                    console.print(Panel("👋 Goodbye!", style="bold yellow"))
                else:
                    console.print("Goodbye!")
                break

            try:
                command_parts = shlex.split(user_input, comments=True)
            except ValueError:
                console.print("Invalid input: unmatched quotes. Please try again.")
                continue

            if not command_parts:
                continue

            command = command_parts[0]
            
            if command == '/suggest':
                if len(command_parts) < 2:
                    console.print("Please provide a keyword for /suggest. You can use quotes for multi-word phrases.")
                    continue
                keywords = command_parts[1:]
                suggestions = get_file_suggestions(keywords, all_files, user_initiated=True)
                last_suggestions = suggestions
                
                selected_files = display_and_select_files(suggestions, sent_files, keywords)
                
                if selected_files:
                    conversation_history, last_ai_response, sent_files = process_and_send_files(selected_files, conversation_history, api_choice_name, selected_model, all_files, sent_files, keywords)

            elif command == '/suggestLast':
                # --- FIX APPLIED HERE ---
                if not last_suggestions:
                    console.print("No previous suggestions to reference. Please run a search first.")
                    continue
                if len(command_parts) < 2:
                    console.print("Please provide one or more numbers for /suggestLast (e.g., /suggestLast 1,3).")
                    continue
                
                try:
                    # Correctly split the input string by commas
                    input_numbers = command_parts[1].split(',')
                    selected_numbers = [int(n.strip()) - 1 for n in input_numbers]
                    
                    selected_files = [
                        last_suggestions[i][0] for i in selected_numbers 
                        if 0 <= i < len(last_suggestions)
                    ]
                    
                    if selected_files:
                        conversation_history, last_ai_response, sent_files = process_and_send_files(selected_files, conversation_history, api_choice_name, selected_model, all_files, sent_files)
                    else:
                        console.print("Invalid selection. Please choose a number from the list.")
                except (ValueError, IndexError):
                    console.print("Invalid input. Please provide a comma-separated list of numbers.")
                # --- END OF FIX ---
                
            elif command == '/run_deep':
                if not last_ai_response:
                    console.print("No previous AI response to reference. Please chat with the AI first.")
                    continue
                keywords = extract_keywords(last_ai_response)
                # The get_file_suggestions function is also fixed to handle empty keywords gracefully.
                if keywords:
                    suggestions = get_file_suggestions(keywords, all_files, search_content=True)
                    last_suggestions = suggestions
                    
                    selected_files = display_and_select_files(suggestions, sent_files, keywords)
                    if selected_files:
                        conversation_history, last_ai_response, sent_files = process_and_send_files(selected_files, conversation_history, api_choice_name, selected_model, all_files, sent_files)
                else:
                    console.print("No relevant keywords found in the last AI response.")
                
            else:
                if not user_input.startswith('/'):
                    log.info("User: {}".format(user_input))
                conversation_history.append({"role": "user", "content": user_input})
                
                ai_message = get_ai_response(conversation_history, api_choice_name, selected_model)
                
                last_ai_response = ai_message
                
                # AI response suggestions and highlighting (new logic)
                ai_suggestions = []
                keywords_to_highlight_in_response = []
                if not ai_message.startswith("Error with"):
                    ai_suggestions = get_file_suggestions([], all_files, search_content=True, ai_response_text=ai_message)
                    last_suggestions = ai_suggestions
                    
                    # Get keywords from the suggested filenames for highlighting
                    for file_suggestion, _ in ai_suggestions:
                        filename_no_ext = os.path.splitext(os.path.basename(file_suggestion))[0]
                        keywords_to_highlight_in_response.append(filename_no_ext)
                
                log.info("AI: {}".format(ai_message))
                if ai_suggestions:
                    log.info("Recommended files based on AI response: %s", ', '.join([s[0] for s in ai_suggestions]))

                if RICH_INSTALLED:
                    formatted_ai_message = Text(ai_message)
                    for keyword in keywords_to_highlight_in_response:
                        formatted_ai_message.highlight_regex(r'(?i)' + re.escape(keyword), style="bold magenta")
                    
                    console.print(Panel(formatted_ai_message, title="AI Response", style="white"))
                else:
                    console.print("\nAI: {}".format(ai_message))
                
                conversation_history.append({"role": "assistant", "content": ai_message})
                
                if ai_suggestions:
                    selected_files = display_and_select_files(last_suggestions, sent_files, keywords_to_highlight_in_response)
                    if selected_files:
                        conversation_history, last_ai_response, sent_files = process_and_send_files(selected_files, conversation_history, api_choice_name, selected_model, all_files, sent_files)
                else:
                    if RICH_INSTALLED:
                        console.print(Panel(Text("I didn't find any relevant files automatically.", justify="center"), style="bold yellow"))
                    else:
                        console.print("I didn't find any relevant files automatically.")

    except Exception as e:
        console.print("An unexpected error occurred: {}".format(e))
        logging.error("An unexpected error occurred: {}".format(e), exc_info=True)
    finally:
        console.print("Script terminated. Check chat_history.log for full conversation.")

if __name__ == "__main__":
    if not os.path.exists(FILE_DIRECTORY):
        os.makedirs(FILE_DIRECTORY)
        console.print("Created directory: {}".format(FILE_DIRECTORY))
    
    main()