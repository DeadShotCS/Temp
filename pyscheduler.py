import time
import datetime
import subprocess
import schedule
import threading
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.live import Live
import os

console = Console()
# Global reference to the live display object
live_display = None

# --- Job Configuration ---
# Define your command-line jobs and their schedules
jobs = {
    'ping_google': {
        'command': 'ping -c 4 google.com',
        'schedule': schedule.every(10).seconds,
        'status': 'Not run yet',
        'last_run': 'N/A',
        'output': ''
    },
    'list_files': {
        'command': 'dir',  # Example: 'dir' on Windows
        'schedule': schedule.every(30).seconds,
        'status': 'Not run yet',
        'last_run': 'N/A',
        'output': ''
    },
    'show_disk_space': {
        'command': 'df -h', # Example: 'dir' on Windows
        'schedule': schedule.every(1).minutes,
        'status': 'Not run yet',
        'last_run': 'N/A',
        'output': ''
    }
}

# --- Utility Functions ---
def run_job(job_name):
    """Executes a command and updates the job status."""
    global live_display
    job = jobs[job_name]
    try:
        result = subprocess.run(
            job['command'],
            check=True,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        job['status'] = Text("Success", style="bold green")
        job['last_run'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        job['output'] = f"Success!\n{result.stdout}"
    except subprocess.CalledProcessError as e:
        job['status'] = Text("Failed", style="bold red")
        job['last_run'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        job['output'] = f"Failed!\n{e.stderr.strip()}"
    except FileNotFoundError:
        job['status'] = Text("Failed (Command not found)", style="bold red")
        job['last_run'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        job['output'] = "Failed!\nCommand not found."

def run_threaded_job(job_name):
    """Starts a scheduled job in a new thread to prevent blocking."""
    job_thread = threading.Thread(target=run_job, args=(job_name,))
    job_thread.start()

def get_next_run_time():
    """Calculates the time until the next scheduled job runs."""
    all_jobs = schedule.get_jobs()
    if not all_jobs:
        return None
    
    next_run = min(job.next_run for job in all_jobs)
    seconds_until_next = (next_run - datetime.datetime.now()).total_seconds()
    
    if seconds_until_next < 0:
        return "Now"
    
    hours = int(seconds_until_next // 3600)
    minutes = int((seconds_until_next % 3600) // 60)
    seconds = int(seconds_until_next % 60)
    
    time_str = ""
    if hours > 0:
        time_str += f"{hours}h "
    if minutes > 0:
        time_str += f"{minutes}m "
    if seconds > 0:
        time_str += f"{seconds}s"
    
    return time_str.strip() if time_str else "Now"

def generate_display():
    """Generates the Rich displayable content."""
    # --- Title Panel ---
    title_panel = Panel("[bold green]Scheduled Command-Line Utility[/bold green]")

    # --- Status Panel ---
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    status_text = Text("Current Time: ", style="white")
    status_text.append(current_time, style="bold yellow")
    
    next_run_time = get_next_run_time()
    if next_run_time:
        status_text.append("\nTime Until Next Job: ", style="white")
        status_text.append(next_run_time, style="bold cyan")
    else:
        status_text.append("\nNo jobs scheduled.")
    
    status_panel = Panel(status_text, title="[bold white]Status[/bold white]")

    # --- Job Table ---
    table = Table(title="[bold blue]Job Status[/bold blue]")
    table.add_column("Job Name", justify="left", style="cyan", no_wrap=True)
    table.add_column("Next Run", style="magenta")
    table.add_column("Last Run", style="yellow")
    table.add_column("Status", style="green")
    
    for job_name, config in jobs.items():
        job_list = schedule.get_jobs(job_name)
        job_obj = job_list[0] if job_list else None
        next_run_str = job_obj.next_run.strftime('%Y-%m-%d %H:%M:%S') if job_obj and job_obj.next_run else 'N/A'
        
        table.add_row(
            job_name,
            next_run_str,
            config['last_run'],
            config['status']
        )
    
    return Group(title_panel, status_panel, table)

# --- Threading for Display and Scheduling ---
def display_updater():
    """Updates the live display every second."""
    while True:
        if live_display:
            live_display.update(generate_display())
        time.sleep(1)

def scheduler_runner():
    """Runs the schedule loop."""
    while True:
        schedule.run_pending()
        time.sleep(1)

# --- Main Program Execution ---
def main():
    """
    Sets up the scheduled jobs and starts the main program loop.
    
    This function initializes a display thread to handle real-time UI updates
    and a scheduler thread to manage and run the jobs. The main thread then
    uses `rich.live.Live` to handle the terminal display and keeps the program
    running until a KeyboardInterrupt (e.g., Ctrl+C) is received.
    """
    global live_display
    
    # Schedule the jobs to be run in their own threads
    for job_name, config in jobs.items():
        config['schedule'].do(run_threaded_job, job_name).tag(job_name)
    
    # Start the display and scheduler threads
    display_thread = threading.Thread(target=display_updater, daemon=True)
    scheduler_thread = threading.Thread(target=scheduler_runner, daemon=True)
    display_thread.start()
    scheduler_thread.start()
    
    # Use Live to manage the display in the main thread
    with Live(generate_display(), screen=True, refresh_per_second=4) as live:
        live_display = live
        # Keep the main thread alive to prevent the program from exiting
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()