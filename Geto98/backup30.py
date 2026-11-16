
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import subprocess
import zipfile
from datetime import datetime

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table


console = Console()


# ============================================================
# PATHS
# ============================================================

BASE_BACKUP_DIR = "/sdcard/Download"
TERMUX_HOME = "/data/data/com.termux/files/home"

# Supported backup and restore extensions.
BACKUP_EXTENSIONS = (".py", ".sh", ".txt")

os.makedirs(
    BASE_BACKUP_DIR,
    exist_ok=True
)


# ============================================================
# HELPERS
# ============================================================

def is_script_file(filename):
    """
    Return True ONLY for .py, .sh and .txt files.
    """

    return filename.lower().endswith(
        BACKUP_EXTENSIONS
    )


def is_backup_dir(name):
    """
    Accept backup folders.
    """

    return (
        name == "backup"
        or name.startswith("backup_")
    )


def get_backups():
    """
    Find backup folders directly inside Download.
    Newest backup first.
    """

    backups = []

    try:
        for name in os.listdir(BASE_BACKUP_DIR):

            full_path = os.path.join(
                BASE_BACKUP_DIR,
                name
            )

            if (
                os.path.isdir(full_path)
                and is_backup_dir(name)
            ):
                backups.append(name)

    except Exception as e:
        console.print(
            "[bold red]Cannot read backup directory:[/bold red]"
        )
        console.print(f"[yellow]{e}[/yellow]")
        return []

    backups.sort(
        key=lambda name: os.path.getmtime(
            os.path.join(
                BASE_BACKUP_DIR,
                name
            )
        ),
        reverse=True
    )

    return backups


# ============================================================
# BACKUP
# ============================================================

def backup_selected():
    """
    Backup .py, .sh and .txt files directly inside TERMUX_HOME.

    Creates:
    1. A normal backup directory.
    2. A ZIP archive containing the same supported files.

    Subdirectories are not scanned.
    """

    console.print()

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    console.print(
        "[bold cyan]Enter a backup name suffix.[/bold cyan]"
    )

    console.print(
        "[yellow]Text, numbers, and emojis are supported.[/yellow]"
    )

    suffix = Prompt.ask(
        "[bold cyan]Backup name suffix[/bold cyan]",
        default=timestamp
    ).strip()

    if not suffix:
        suffix = timestamp

    # Prevent path traversal and directory separators.
    suffix = suffix.replace("/", "_").replace("\\", "_")
    suffix = suffix.replace("\0", "_")

    backup_name = f"backup_{suffix}"

    backup_dir = os.path.join(
        BASE_BACKUP_DIR,
        backup_name
    )

    zip_path = backup_dir + ".zip"

    # Prevent overwriting either existing backup.
    if (
        os.path.exists(backup_dir)
        or os.path.exists(zip_path)
    ):
        console.print()
        console.print(
            "[bold red]This backup name already exists.[/bold red]"
        )
        console.print(
            "[yellow]Choose another name.[/yellow]"
        )
        return

    # ========================================================
    # READ TERMUX HOME
    # ========================================================

    try:
        entries = os.listdir(TERMUX_HOME)

    except Exception as e:
        console.print(
            "[bold red]Cannot read Termux HOME.[/bold red]"
        )
        console.print(f"[yellow]{e}[/yellow]")
        return

    # ========================================================
    # CREATE BACKUP DIRECTORY
    # ========================================================

    try:
        os.makedirs(
            backup_dir,
            exist_ok=False
        )

    except Exception as e:
        console.print(
            "[bold red]Cannot create backup directory.[/bold red]"
        )
        console.print(f"[yellow]{e}[/yellow]")
        return

    count = 0
    failed = 0

    console.print()
    console.print(
        "[bold cyan]Starting backup...[/bold cyan]"
    )

    # ========================================================
    # COPY SUPPORTED FILES
    # ========================================================

    for filename in entries:

        src = os.path.join(
            TERMUX_HOME,
            filename
        )

        # Ignore directories and non-regular files.
        if not os.path.isfile(src):
            continue

        # Only .py, .sh and .txt files.
        if not is_script_file(filename):
            continue

        dst = os.path.join(
            backup_dir,
            filename
        )

        try:
            shutil.copy2(
                src,
                dst
            )

            count += 1

        except Exception as e:
            failed += 1

            console.print(
                f"[red]Failed:[/red] {filename}"
            )

            console.print(
                f"[yellow]{e}[/yellow]"
            )

    # ========================================================
    # CREATE ZIP ARCHIVE
    # ========================================================

    zip_failed = False

    try:
        with zipfile.ZipFile(
            zip_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED
        ) as zip_file:

            for filename in os.listdir(backup_dir):

                file_path = os.path.join(
                    backup_dir,
                    filename
                )

                if (
                    os.path.isfile(file_path)
                    and is_script_file(filename)
                ):
                    zip_file.write(
                        file_path,
                        arcname=filename
                    )

    except Exception as e:
        zip_failed = True

        console.print()
        console.print(
            "[bold red]ZIP backup failed.[/bold red]"
        )
        console.print(
            f"[yellow]{e}[/yellow]"
        )

        # Remove an incomplete ZIP file.
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
        except OSError:
            pass

    # ========================================================
    # RESULT
    # ========================================================

    console.print()

    console.print(
        "[bold green]Backup process finished.[/bold green]"
    )

    console.print(
        f"[cyan]Backup name:[/cyan] {backup_name}"
    )

    console.print(
        f"[cyan]Folder:[/cyan] {backup_dir}"
    )

    console.print(
        f"[cyan]Files copied:[/cyan] {count}"
    )

    if failed:
        console.print(
            f"[bold red]Copy failures:[/bold red] {failed}"
        )

    if not zip_failed:
        console.print(
            f"[green]ZIP archive:[/green] {zip_path}"
        )

        console.print(
            "[green]ZIP creation successful.[/green]"
        )

    else:
        console.print(
            "[bold red]ZIP archive was not created successfully.[/bold red]"
        )

    console.print()
    console.print(
        "[cyan]Included extensions:[/cyan] .py, .sh, .txt"
    )
    console.print(
        "[cyan]Subdirectories:[/cyan] ignored"
    )


# ============================================================
# RESTORE
# ============================================================

def restore_files():
    """
    Restore .py, .sh and .txt files from a selected backup folder.

    Existing destination files are replaced.
    Subdirectories are not restored.
    """

    backups = get_backups()

    # ========================================================
    # NO BACKUPS
    # ========================================================

    if not backups:
        console.print()
        console.print(
            "[bold red]No backup folders found.[/bold red]"
        )
        console.print(
            f"[yellow]Checked:[/yellow] {BASE_BACKUP_DIR}"
        )
        return

    # ========================================================
    # SHOW BACKUPS
    # ========================================================

    table = Table(
        title="Available Backups"
    )

    table.add_column(
        "No",
        style="cyan",
        justify="center"
    )

    table.add_column(
        "Backup Folder",
        style="green"
    )

    table.add_column(
        "Location",
        style="white"
    )

    for index, backup_name in enumerate(
        backups,
        start=1
    ):

        backup_path = os.path.join(
            BASE_BACKUP_DIR,
            backup_name
        )

        table.add_row(
            str(index),
            backup_name,
            backup_path
        )

    console.print()
    console.print(table)
    console.print()

    # ========================================================
    # SELECT BACKUP
    # ========================================================

    choice = Prompt.ask(
        "[bold cyan]Select backup number[/bold cyan] "
        "[yellow](0 = cancel)[/yellow]",
        default="0"
    ).strip()

    if choice == "0":
        console.print(
            "[yellow]Cancelled.[/yellow]"
        )
        return

    # ========================================================
    # VALIDATE SELECTION
    # ========================================================

    try:
        index = int(choice) - 1

        if index < 0 or index >= len(backups):
            raise ValueError

        backup_name = backups[index]

    except (ValueError, TypeError):
        console.print(
            "[bold red]Invalid selection.[/bold red]"
        )
        return

    backup_dir = os.path.join(
        BASE_BACKUP_DIR,
        backup_name
    )

    if not os.path.isdir(backup_dir):
        console.print(
            "[bold red]Backup folder does not exist.[/bold red]"
        )
        return

    # ========================================================
    # READ BACKUP
    # ========================================================

    try:
        entries = os.listdir(backup_dir)

    except Exception as e:
        console.print(
            "[bold red]Cannot read backup.[/bold red]"
        )
        console.print(f"[yellow]{e}[/yellow]")
        return

    # ========================================================
    # RESTORE FILES
    # ========================================================

    restored = 0
    failed = 0

    console.print()
    console.print(
        f"[bold cyan]Restoring:[/bold cyan] {backup_name}"
    )
    console.print()

    for filename in entries:

        src = os.path.join(
            backup_dir,
            filename
        )

        # Ignore directories and non-regular files.
        if not os.path.isfile(src):
            continue

        # Only restore .py, .sh and .txt files.
        if not is_script_file(filename):
            continue

        dst = os.path.join(
            TERMUX_HOME,
            filename
        )

        try:
            shutil.copy2(
                src,
                dst
            )

            restored += 1

        except Exception as e:
            failed += 1

            console.print(
                f"[red]Failed:[/red] {filename}"
            )

            console.print(
                f"[yellow]{e}[/yellow]"
            )

    # ========================================================
    # RESTORE RESULT
    # ========================================================

    console.print()

    console.print(
        "[bold green]Restore complete.[/bold green]"
    )

    console.print(
        f"[cyan]Files restored:[/cyan] {restored}"
    )

    if failed:
        console.print(
            f"[bold red]Failed:[/bold red] {failed}"
        )

    console.print(
        f"[cyan]Restore destination:[/cyan] {TERMUX_HOME}"
    )

    # ========================================================
    # EXECUTE PERMISSIONS
    # ========================================================

    try:
        result = subprocess.run(
            "chmod +x ~/*.py ~/*.sh 2>/dev/null",
            shell=True,
            executable="/system/bin/sh"
        )

        console.print()

        if result.returncode == 0:
            console.print(
                "[bold green]Execute permissions applied.[/bold green]"
            )

            console.print(
                "[cyan]Command:[/cyan] "
                "chmod +x ~/*.py ~/*.sh 2>/dev/null"
            )

        else:
            console.print(
                "[yellow]No matching .py/.sh files "
                "or no changes needed.[/yellow]"
            )

    except Exception as e:
        console.print()
        console.print(
            "[bold red]Failed to apply execute permissions.[/bold red]"
        )
        console.print(f"[yellow]{e}[/yellow]")


# ============================================================
# MAIN MENU
# ============================================================

def main():

    while True:

        console.print()

        console.print(
            "[bold yellow]"
            "══════════════════════════════════════"
            "[/bold yellow]"
        )

        console.print(
            "[bold cyan]"
            "        TERMUX BACKUP MANAGER"
            "[/bold cyan]"
        )

        console.print(
            "[bold yellow]"
            "══════════════════════════════════════"
            "[/bold yellow]"
        )

        console.print(
            "[green]1[/green]  Backup .py + .sh + .txt (Folder + ZIP)"
        )

        console.print(
            "[green]2[/green]  Restore"
        )

        console.print(
            "[red]0[/red]  Exit"
        )

        console.print()

        choice = Prompt.ask(
            "[bold cyan]Select[/bold cyan]",
            default="0"
        ).strip()

        # ====================================================
        # BACKUP
        # ====================================================

        if choice == "1":
            backup_selected()

        # ====================================================
        # RESTORE
        # ====================================================

        elif choice == "2":
            restore_files()

        # ====================================================
        # EXIT
        # ====================================================

        elif choice == "0":
            console.print(
                "[bold yellow]Exit.[/bold yellow]"
            )
            break

        # ====================================================
        # INVALID
        # ====================================================

        else:
            console.print(
                "[bold red]Invalid option.[/bold red]"
            )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
