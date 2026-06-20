"""
Netwatch Textual TUI

Displays widgets for:
- Raw syscall log stream
- Aggregated metrics
- Active processes details in a DataTable
- Parent-child process lineage tree
- Detailed IO history of selected processes
- MITRE ATT&CK behavioral mapping
- Modal overlay alerts for FSM trigger events
"""
from .state import SyscallState
from .models import ThreatAlert, ProcessDetails, IOHistory
from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal, Grid, VerticalScroll
from textual.widgets import Header, Footer, Label, RichLog, Digits, DataTable, Tree, TabbedContent, TabPane, Button
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.reactive import reactive
from textual import on


class MetricWidget(Widget):
    """ Custom widget to display a single metric card """
    value = reactive(0)

    def __init__(self, label: str, initial_value: int = 0, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.label = label
        self.value = initial_value

    def compose(self) -> ComposeResult:
        yield Label(self.label, classes="metric-title")
        yield Digits(str(self.value), id="metric-digits", classes="bold-text")

    def watch_value(self, old_val: int, new_val: int) -> None:
        """ Watch value changes and update the UI digits """
        try:
            digits = self.query_one("#metric-digits", Digits)
            digits.update(str(new_val))
        except Exception:
            pass


class AlertModal(ModalScreen):
    """ Modal overlay displaying threat detection alerts """

    def __init__(self, alert: ThreatAlert, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.alert = alert

    def compose(self) -> ComposeResult:
        with Vertical(id="alert-box"):
            yield Label(f"THREAT LEVEL: {self.alert.severity.value.upper()}", id="alert-title")
            yield Label(f"[bold]Rule Name:[/bold] {self.alert.rule_name}", id="alert-field-rule")
            yield Label(f"[bold]PID:[/bold] {self.alert.pid}", id="alert-field-pid")
            yield Label(f"[bold]Details:[/bold] {self.alert.message}", id="alert-field-msg")
            yield Button("Acknowledge", id="alert-ack-btn", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "alert-ack-btn":
            self.dismiss()


class LogDisplay(Vertical):
    """ Displays raw syscall logs """

    def compose(self) -> ComposeResult:
        yield Label("Syscall Log Feed", classes="section-header")
        yield RichLog(
            id="log-feed-box",
            highlight=True,
            markup=True,
            max_lines=1000,
            wrap=True
        )

    def add_log(self, log_line: str) -> None:
        try:
            self.query_one("#log-feed-box", RichLog).write(log_line)
        except Exception:
            pass


class IOHistoryWidget(Vertical):
    """ Displays process IO access and executed trace history """

    def compose(self) -> ComposeResult:
        yield Label("Select a process to view IO History", id="io-history-title", classes="section-header")
        with VerticalScroll(classes="io-scroll"):
            yield Label("No process selected", id="io-history-content", markup=True)

    def update_history(self, pid: int | None, history: IOHistory | None) -> None:
        title = self.query_one("#io-history-title", Label)
        content = self.query_one("#io-history-content", Label)
        
        if pid is None or history is None:
            title.update("Select a process to view IO History")
            content.update("No process selected")
            return

        title.update(f"IO History for PID {pid}")
        lines = []
        if history.paths_accessed:
            lines.append("[bold cyan]Paths Accessed:[/bold cyan]")
            for p in sorted(history.paths_accessed):
                lines.append(f"  - {p}")
        if history.paths_executed:
            lines.append("\n[bold green]Paths Executed:[/bold green]")
            for p in sorted(history.paths_executed):
                lines.append(f"  - {p}")
        if history.active_fds:
            lines.append("\n[bold yellow]Active FDs:[/bold yellow]")
            for fd in sorted(history.active_fds):
                lines.append(f"  - FD {fd}")
        if history.active_sockfds:
            lines.append("\n[bold magenta]Active Sockets (FDs):[/bold magenta]")
            for fd in sorted(history.active_sockfds):
                lines.append(f"  - Socket FD {fd}")
        if history.trace_executed:
            lines.append("\n[bold red]Traced Syscalls/Events:[/bold red]")
            for t in sorted(history.trace_executed, key=lambda x: str(x)):
                lines.append(f"  - {t}")
                
        content.update("\n".join(lines) if lines else "No IO History recorded for this process.")


class ProcessTable(Vertical):
    """ Displays details for active processes """

    def compose(self) -> ComposeResult:
        yield Label("Process List", classes="section-header")
        yield DataTable(id="proc-table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("PID", "Binary Path", "Parent PID", "Child PIDs", "Open FDs")
        table.cursor_type = "row"


class LineageTree(Vertical):
    """ Renders the process lineage tree hierarchy """

    def compose(self) -> ComposeResult:
        yield Label("Process Lineage Hierarchy", classes="section-header")
        yield Tree("Process Tree Root", id="lineage-tree")

    def on_mount(self) -> None:
        tree = self.query_one(Tree)
        tree.show_root = False

    def update_tree(self, processes: dict[int, ProcessDetails], selected_pid: int | None = None) -> None:
        tree = self.query_one("#lineage-tree", Tree)
        tree.clear()
        
        roots = [p for p in processes.values() if p.parent_pid is None or p.parent_pid not in processes]
        
        def add_nodes(parent_node, proc: ProcessDetails):
            label = f"{proc.pid}: {proc.binary_path or 'Unknown'}"
            if selected_pid == proc.pid:
                label = f"[reverse]{label}[/reverse]"
            node = parent_node.add(label, data=proc.pid)
            node.expand()
            for child_pid in proc.child_pids:
                if child_pid in processes:
                    add_nodes(node, processes[child_pid])
                    
        for root in roots:
            add_nodes(tree.root, root)
        tree.root.expand()


class MitreTree(Vertical):
    """ Maps system call behavior and detected anomalies to MITRE ATT&CK """

    def compose(self) -> ComposeResult:
        yield Label("MITRE ATT&CK Mapping Tree", classes="section-header")
        yield Tree("Tactics & Techniques", id="mitre-tree")

    def on_mount(self) -> None:
        tree = self.query_one(Tree)
        tree.show_root = False

    def update_mitre(self, raw_logs: list[str], histories: dict[int, IOHistory]) -> None:
        tree = self.query_one("#mitre-tree", Tree)
        tree.clear()

        # execution tactic
        exec_node = tree.root.add("[bold red]Tactic: Execution[/bold red]")
        exec_node.expand()
        
        # Unix Shell (T1059.004)
        shell_pids = []
        for pid, history in histories.items():
            for path in history.paths_executed:
                if path.endswith(("sh", "bash", "zsh", "dash")):
                    shell_pids.append((pid, path))
        if shell_pids:
            t1059 = exec_node.add("Command and Scripting Interpreter: Unix Shell (T1059.004)")
            t1059.expand()
            for pid, path in shell_pids:
                t1059.add(f"[bold]PID {pid}[/bold] executed shell: [yellow]{path}[/yellow]")

        # Client Execution (T1203)
        client_exec_pids = []
        for pid, history in histories.items():
            for path in history.paths_executed:
                if path in history.paths_accessed and not path.endswith(("sh", "bash", "zsh", "dash")):
                    client_exec_pids.append((pid, path))
        if client_exec_pids:
            t1203 = exec_node.add("Exploitation for Client Execution (T1203)")
            t1203.expand()
            for pid, path in client_exec_pids:
                t1203.add(f"[bold]PID {pid}[/bold] executed dropped payload: [yellow]{path}[/yellow]")

        # defense evasion tactic
        evasion_node = tree.root.add("[bold yellow]Tactic: Defense Evasion[/bold yellow]")
        evasion_node.expand()
        
        # Linux Permissions modification (T1222.002)
        fchmod_lines = []
        for line in raw_logs:
            if "fchmod" in line or "chmod" in line:
                if "pid" in line:
                    parts = line.split("]")
                    pid_part = parts[0].replace("[pid", "").strip()
                    if pid_part.isdigit():
                        fchmod_lines.append((int(pid_part), line.strip()))
        if fchmod_lines:
            t1222 = evasion_node.add("File and Directory Permissions Modification: Linux (T1222.002)")
            t1222.expand()
            seen = set()
            for pid, desc in fchmod_lines:
                if desc not in seen:
                    t1222.add(f"[bold]PID {pid}[/bold] modified permissions: [yellow]{desc}[/yellow]")
                    seen.add(desc)

        # command and control tactic
        c2_node = tree.root.add("[bold green]Tactic: Command and Control[/bold green]")
        c2_node.expand()
        
        # Non-Standard Port / Proxy (T1043/T1090)
        c2_lines = []
        for line in raw_logs:
            if any(op in line for op in ["bind", "listen", "accept", "accept4"]):
                if "pid" in line:
                    parts = line.split("]")
                    pid_part = parts[0].replace("[pid", "").strip()
                    if pid_part.isdigit():
                        c2_lines.append((int(pid_part), line.strip()))
        if c2_lines:
            t1043 = c2_node.add("Non-Standard Port / Inbound Connection Listener (T1043/T1090)")
            t1043.expand()
            seen = set()
            for pid, desc in c2_lines:
                if desc not in seen:
                    t1043.add(f"[bold]PID {pid}[/bold] created inbound listener: [yellow]{desc}[/yellow]")
                    seen.add(desc)
                    
        tree.root.expand()


class NetwatchApp(App):
    """ Netwatch Textual TUI app """

    CSS_PATH = "tui.tcss"

    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("ctrl+c", "quit_app", "Quit application")
    ]

    def __init__(self, state: SyscallState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.last_log_index = 0
        self.last_alert_index = 0
        self.selected_pid = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Monitor & Metrics", id="tab-monitor"):
                with VerticalScroll():
                    with Grid(id="metrics-grid"):
                        yield MetricWidget("Total Logs Ingested", id="m-total-logs")
                        yield MetricWidget("Total Paths Accessed", id="m-paths-accessed")
                        yield MetricWidget("Total Open FDs", id="m-open-fds")
                        yield MetricWidget("Total Active PIDs", id="m-active-pids")
                    yield LogDisplay(id="log-display-section")
            with TabPane("Process Analysis & Lineage", id="tab-lineage"):
                with VerticalScroll():
                    with Horizontal(id="details-container"):
                        yield ProcessTable(id="table-section")
                        yield LineageTree(id="tree-section")
                    yield IOHistoryWidget(id="io-section")
            with TabPane("MITRE ATT&CK Map", id="tab-mitre"):
                yield MitreTree(id="mitre-section")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.2, self.poll_state)

    def poll_state(self) -> None:
        with self.state.lock:
            # 1. Update Metrics
            total_logs = len(self.state.raw_logs)
            
            paths_accessed_set = set()
            for h in self.state.history.values():
                paths_accessed_set.update(h.paths_accessed)
            paths_accessed = len(paths_accessed_set)
            
            open_fds = sum(len(fds) for fds in self.state.active_fds.values())
            active_pids = len(self.state.processes)

            # 2. Get new logs
            new_logs = self.state.raw_logs[self.last_log_index:]
            self.last_log_index = total_logs

            # 3. Get new alerts
            new_alerts = self.state.alerts[self.last_alert_index:]
            self.last_alert_index = len(self.state.alerts)

            # Copy data for UI updates under lock
            processes_copy = {pid: proc for pid, proc in self.state.processes.items()}
            fds_copy = {pid: len(fds) for pid, fds in self.state.active_fds.items()}
            history_copy = {pid: hist for pid, hist in self.state.history.items()}
            raw_logs_copy = list(self.state.raw_logs)

        # Update metrics widgets
        self.query_one("#m-total-logs", MetricWidget).value = total_logs
        self.query_one("#m-paths-accessed", MetricWidget).value = paths_accessed
        self.query_one("#m-open-fds", MetricWidget).value = open_fds
        self.query_one("#m-active-pids", MetricWidget).value = active_pids

        # Append raw logs
        if new_logs:
            log_display = self.query_one(LogDisplay)
            for log in new_logs:
                log_display.add_log(log)

        # Trigger modals for new alerts
        for alert in new_alerts:
            self.push_screen(AlertModal(alert))

        # Update tables and trees
        self.update_process_table(processes_copy, fds_copy)
        self.update_lineage_tree(processes_copy)
        self.update_io_history(history_copy)
        self.update_mitre_tree(raw_logs_copy, history_copy)

    def update_process_table(self, processes: dict[int, ProcessDetails], fds_count: dict[int, int]) -> None:
        table = self.query_one("#proc-table", DataTable)
        cursor_coordinate = table.cursor_coordinate
        
        table.clear()
        for pid, proc in sorted(processes.items()):
            child_str = ",".join(str(c) for c in proc.child_pids) if proc.child_pids else "None"
            open_fds = fds_count.get(pid, 0)
            table.add_row(
                str(pid),
                proc.binary_path or "Unknown",
                str(proc.parent_pid) if proc.parent_pid is not None else "None",
                child_str,
                str(open_fds),
                key=str(pid)
            )
            
        if cursor_coordinate and cursor_coordinate.row < len(table.rows):
            table.cursor_coordinate = cursor_coordinate

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key and event.row_key.value:
            try:
                self.selected_pid = int(event.row_key.value)
            except ValueError:
                self.selected_pid = None

    @on(Tree.NodeSelected)
    def on_node_selected(self, event: Tree.NodeSelected) -> None:
        if event.node.data is not None:
            self.selected_pid = event.node.data

    def update_lineage_tree(self, processes: dict[int, ProcessDetails]) -> None:
        self.query_one("#tree-section", LineageTree).update_tree(processes, self.selected_pid)

    def update_io_history(self, histories: dict[int, IOHistory]) -> None:
        io_widget = self.query_one(IOHistoryWidget)
        if self.selected_pid is not None and self.selected_pid in histories:
            io_widget.update_history(self.selected_pid, histories[self.selected_pid])
        else:
            io_widget.update_history(None, None)

    def update_mitre_tree(self, raw_logs: list[str], histories: dict[int, IOHistory]) -> None:
        self.query_one("#mitre-section", MitreTree).update_mitre(raw_logs, histories)

    def action_toggle_dark(self) -> None:
        self.theme = "textual-dark" if self.theme == "textual-light" else "textual-light"

    def action_quit_app(self) -> None:
        self.exit()
