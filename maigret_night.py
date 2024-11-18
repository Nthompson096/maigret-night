import sys
import subprocess
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, 
                             QGroupBox, QFormLayout, QSpinBox, QComboBox, QTabWidget, QToolButton)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Worker class that handles executing the Maigret command in a separate thread
class MaigretWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()  # Add this signal to indicate completion

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.process = None

    def run(self):
        self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=True)
        for line in self.process.stdout:
            self.output_signal.emit(line.strip())
        self.process.wait()

        self.finished_signal.emit()  # Emit when the process finishes

    def terminate(self):
        if self.process:
            self.process.terminate()
            self.process.wait()

# Main GUI class for the Maigret OSINT tool
class MaigretGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Maigret Night")
        self.setGeometry(100, 100, 1000, 600)  # Reduced window size
        self.worker = None

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        # Create tabs for different sections
        self.create_input_tab(tab_widget)
        self.create_options_tab(tab_widget)
        self.create_proxy_tab(tab_widget)
        self.create_output_tab(tab_widget)

        # Buttons and output area
        self.create_buttons(layout)

    def create_input_tab(self, tab_widget):
        input_group = QWidget()
        input_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        input_layout.addRow("Username:", self.username_input)
        
        input_group.setLayout(input_layout)
        tab_widget.addTab(input_group, "Input")

    def create_options_tab(self, tab_widget):
        options_group = QWidget()
        options_layout = QVBoxLayout()

        # Timeout input
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (seconds):"))
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(1, 300)
        timeout_layout.addWidget(self.timeout_spinbox)
        options_layout.addLayout(timeout_layout)

        # Retries input
        retries_layout = QHBoxLayout()
        retries_layout.addWidget(QLabel("Retries:"))
        self.retries_spinbox = QSpinBox()
        self.retries_spinbox.setRange(1, 10)
        self.retries_spinbox.setValue(3)  # Default retries is 3
        retries_layout.addWidget(self.retries_spinbox)
        options_layout.addLayout(retries_layout)

        # Max connections input
        max_connections_layout = QHBoxLayout()
        max_connections_layout.addWidget(QLabel("Max Connections:"))
        self.max_connections_spinbox = QSpinBox()
        self.max_connections_spinbox.setRange(1, 50) # Max connections, up to 50
        self.max_connections_spinbox.setValue(10)  # Default max connections is 10 now
        max_connections_layout.addWidget(self.max_connections_spinbox)
        options_layout.addLayout(max_connections_layout)

        # Other checkboxes
        self.no_recursion_checkbox = QCheckBox("No Recursion")
        options_layout.addWidget(self.no_recursion_checkbox)

        self.no_extracting_checkbox = QCheckBox("No Extracting")
        options_layout.addWidget(self.no_extracting_checkbox)

        self.permute_checkbox = QCheckBox("Permute")
        options_layout.addWidget(self.permute_checkbox)

        self.all_sites_checkbox = QCheckBox("All Sites")
        options_layout.addWidget(self.all_sites_checkbox)

        # ID type combobox
        self.id_type_combobox = QComboBox()
        self.id_type_combobox.addItems(["username", "email", "phone", "profile", "location"])
        options_layout.addWidget(QLabel("ID Type:"))
        options_layout.addWidget(self.id_type_combobox)

        # Add Top Sites checkbox
        self.top_sites_checkbox = QCheckBox("Enable Top Sites")
        options_layout.addWidget(self.top_sites_checkbox)

        # Top sites input (only enabled if Top Sites checkbox is checked)
        self.top_sites_input = QSpinBox()
        self.top_sites_input.setRange(1, 100)
        self.top_sites_input.setValue(10)  # Default to 10 top sites
        self.top_sites_input.setEnabled(False)  # Disable initially
        options_layout.addWidget(QLabel("Top Sites Count:"))
        options_layout.addWidget(self.top_sites_input)

        # Enable/Disable top sites count input based on checkbox state
        self.top_sites_checkbox.toggled.connect(self.toggle_top_sites_input)

        # Tags input
        self.tags_input = QLineEdit()
        options_layout.addWidget(QLabel("Tags (comma-separated):"))
        options_layout.addWidget(self.tags_input)

        # Site input
        self.site_input = QLineEdit()
        options_layout.addWidget(QLabel("Site URL:"))
        options_layout.addWidget(self.site_input)

        # Disabled sites checkbox
        self.use_disabled_sites_checkbox = QCheckBox("Use Disabled Sites")
        options_layout.addWidget(self.use_disabled_sites_checkbox)

        # Parse URL input
        self.parse_url_input = QLineEdit()
        options_layout.addWidget(QLabel("Parse URL:"))
        options_layout.addWidget(self.parse_url_input)

        # Submit URL input
        self.submit_url_input = QLineEdit()
        options_layout.addWidget(QLabel("Submit URL:"))
        options_layout.addWidget(self.submit_url_input)

        options_group.setLayout(options_layout)
        tab_widget.addTab(options_group, "Options")

        # Add missing checkboxes
        self.self_check_checkbox = QCheckBox("Self Check")
        options_layout.addWidget(self.self_check_checkbox)

        self.stats_checkbox = QCheckBox("Stats")
        options_layout.addWidget(self.stats_checkbox)

        # Add Report Sorting checkbox
        self.report_sorting_checkbox = QCheckBox("Enable Report Sorting")
        options_layout.addWidget(self.report_sorting_checkbox)

        # Report Sorting input (only enabled if checkbox is checked)
        self.report_sorting_combobox = QComboBox()
        self.report_sorting_combobox.addItems(["default", "data"])
        self.report_sorting_combobox.setEnabled(False)  # Disable initially
        options_layout.addWidget(QLabel("Report Sort:"))
        options_layout.addWidget(self.report_sorting_combobox)

        # Enable/Disable report sorting input based on checkbox state
        self.report_sorting_checkbox.toggled.connect(self.toggle_report_sorting_input)

        options_group.setLayout(options_layout)
        tab_widget.addTab(options_group, "Options")

    def toggle_top_sites_input(self):
        # Enable or disable the top sites input based on checkbox
        self.top_sites_input.setEnabled(self.top_sites_checkbox.isChecked())

    def toggle_report_sorting_input(self):
        # Enable or disable the report sorting input based on checkbox
        self.report_sorting_combobox.setEnabled(self.report_sorting_checkbox.isChecked())

    def create_proxy_tab(self, tab_widget):
        proxy_group = QWidget()
        proxy_layout = QVBoxLayout()

        self.proxy_input = QLineEdit()
        proxy_layout.addWidget(QLabel("Proxy URL (e.g., socks5://127.0.0.1:1080):"))
        proxy_layout.addWidget(self.proxy_input)

        self.tor_proxy_input = QLineEdit()
        proxy_layout.addWidget(QLabel("Tor Proxy URL:"))
        proxy_layout.addWidget(self.tor_proxy_input)

        self.i2p_proxy_input = QLineEdit()
        proxy_layout.addWidget(QLabel("I2P Proxy URL:"))
        proxy_layout.addWidget(self.i2p_proxy_input)

        proxy_group.setLayout(proxy_layout)
        tab_widget.addTab(proxy_group, "Proxy")

    def create_output_tab(self, tab_widget):
        output_group = QWidget()
        output_layout = QHBoxLayout()

        self.csv_checkbox = QCheckBox("CSV")
        self.pdf_checkbox = QCheckBox("PDF")
        self.txt_checkbox = QCheckBox("TXT")
        self.html_checkbox = QCheckBox("HTML")
        output_layout.addWidget(self.csv_checkbox)
        output_layout.addWidget(self.pdf_checkbox)
        output_layout.addWidget(self.txt_checkbox)
        output_layout.addWidget(self.html_checkbox)

        output_group.setLayout(output_layout)
        tab_widget.addTab(output_group, "Output")

    def create_buttons(self, layout):
        button_layout = QHBoxLayout()
        self.run_button = QPushButton("Run Maigret")
        self.run_button.clicked.connect(self.run_maigret)
        button_layout.addWidget(self.run_button)

        self.stop_button = QPushButton("Stop Maigret")
        self.stop_button.clicked.connect(self.stop_maigret)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)

        layout.addLayout(button_layout)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

    def run_maigret(self):
        # Construct the command for running Maigret
        command = f"maigret {self.username_input.text()}"

        # Add additional flags for settings
        command += f" --timeout {self.timeout_spinbox.value()}"
        command += f" --retries {self.retries_spinbox.value()}"
        command += f" --max-connections {self.max_connections_spinbox.value()}"
        if self.no_recursion_checkbox.isChecked():
            command += " --no-recursion"
        if self.no_extracting_checkbox.isChecked():
            command += " --no-extracting"
        command += f" --id-type {self.id_type_combobox.currentText()}"
        if self.permute_checkbox.isChecked():
            command += " --permute"
        if self.proxy_input.text():
            command += f" --proxy {self.proxy_input.text()}"
        if self.tor_proxy_input.text():
            command += f" --tor-proxy {self.tor_proxy_input.text()}"
        if self.i2p_proxy_input.text():
            command += f" --i2p-proxy {self.i2p_proxy_input.text()}"
        if self.all_sites_checkbox.isChecked():
            command += " --all-sites"
        if self.top_sites_checkbox.isChecked():
            command += f" --top-sites {self.top_sites_input.value()}"
        if self.tags_input.text():
            command += f" --tags {self.tags_input.text()}"
        if self.site_input.text():
            command += f" --site {self.site_input.text()}"
        if self.use_disabled_sites_checkbox.isChecked():
            command += " --use-disabled-sites"
        
        # Add more specific URLs
        if self.parse_url_input.text():
            command += f" --parse {self.parse_url_input.text()}"
        if self.submit_url_input.text():
            command += f" --submit {self.submit_url_input.text()}"
        if self.self_check_checkbox.isChecked():
            command += " --self-check"
        if self.stats_checkbox.isChecked():
            command += " --stats"
        
        # Output file options
        if self.csv_checkbox.isChecked():
            command += " --csv"
        if self.pdf_checkbox.isChecked():
            command += " --pdf"
        if self.txt_checkbox.isChecked():
            command += " --txt"
        if self.html_checkbox.isChecked():
            command += " --html"
        
        # Add report sorting if checkbox is checked
        if self.report_sorting_checkbox.isChecked():
            command += f" --reports-sorting {self.report_sorting_combobox.currentText()}"

        self.output_area.append(f"Running command: {command}")

        # Run the Maigret command in a separate thread
        self.worker = MaigretWorker(command)
        self.worker.output_signal.connect(self.append_output)
        self.worker.finished_signal.connect(self.on_maigret_finished)  # Connect to the finished signal
        self.worker.start()

        self.run_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def on_maigret_finished(self):
        # Disable the stop button when Maigret finishes
        self.stop_button.setEnabled(False)
        self.run_button.setEnabled(True)  # Re-enable the run button

    def stop_maigret(self):
        if self.worker:
            self.worker.terminate()
            self.worker = None
            self.output_area.append("Maigret process terminated.")

        self.run_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def append_output(self, text):
        self.output_area.append(text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MaigretGUI()
    window.show()
    sys.exit(app.exec())
