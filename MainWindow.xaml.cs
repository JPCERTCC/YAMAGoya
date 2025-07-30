using System;
using System.IO;
using System.Windows;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using System.Windows.Forms;
using System.Globalization;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Windows.Navigation;
using System.Windows.Automation.Peers;
using System.Windows.Automation;
using YAMAGoya.Core;
using MessageBox = System.Windows.MessageBox;
using System.Windows.Interop;

namespace YAMAGoya
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml.
    /// Provides a GUI for session management, detection, log viewing, and process termination.
    /// </summary>
    [SuppressMessage("Design", "CA1515:Type can be made internal", Justification = "MainWindow must be public for XAML binding to work properly.")]
    [SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "Controls dispose resources on unload")]
    [SuppressMessage("Performance", "CA1863:Use 'CompositeFormat'", Justification = "Not available in current .NET version")]
    public partial class MainWindow : Window
    {
        private Thread? _staDetectionThread;
        private CancellationTokenSource? _detectionCts;
        private NotifyIcon? _notifyIcon;

        private static readonly string s_logFileNameFormat = Config.logFileNameFormat;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();
            InitializeNotifyIcon();
            InitializeAccessibility();
            
            // Window status handle
            this.StateChanged += MainWindow_StateChanged;
            
            // Window close handle
            this.Closing += MainWindow_Closing;
            
            // Check session status when window loads
            this.Loaded += Window_Loaded;
        }
        
        /// <summary>
        /// Initializes the system tray notify icon.
        /// </summary>
        private void InitializeNotifyIcon()
        {
            _notifyIcon = new NotifyIcon
            {
                Icon = System.Drawing.Icon.ExtractAssociatedIcon(
                    Path.Combine(AppContext.BaseDirectory, "YAMAGoya.exe")),
                Visible = true,
                Text = "YAMAGoya"
            };
            
            var contextMenu = new ContextMenuStrip();
            
            var openItem = new ToolStripMenuItem("Open");
            openItem.Click += (s, e) => 
            {
                this.Show();
                this.WindowState = WindowState.Normal;
                this.Activate();
            };
            
            var exitItem = new ToolStripMenuItem("Exit");
            exitItem.Click += (s, e) => 
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
                System.Windows.Application.Current.Shutdown();
            };
            
            contextMenu.Items.Add(openItem);
            contextMenu.Items.Add(new ToolStripSeparator());
            contextMenu.Items.Add(exitItem);
            
            _notifyIcon.ContextMenuStrip = contextMenu;
            
            _notifyIcon.DoubleClick += (s, e) => 
            {
                this.Show();
                this.WindowState = WindowState.Normal;
                this.Activate();
            };
        }
        
        /// <summary>
        /// Initializes accessibility features for the application.
        /// </summary>
        private void InitializeAccessibility()
        {
            // Set up keyboard shortcuts
            KeyDown += MainWindow_KeyDown;
            
            // Ensure proper focus management
            Loaded += (s, e) => txtRulesFolder.Focus();
        }
        
        /// <summary>
        /// Handles keyboard shortcuts for accessibility.
        /// </summary>
        private void MainWindow_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            // Ctrl+1-4 for tab navigation
            if (e.Key >= System.Windows.Input.Key.D1 && e.Key <= System.Windows.Input.Key.D4 && 
                (System.Windows.Input.Keyboard.Modifiers & System.Windows.Input.ModifierKeys.Control) == System.Windows.Input.ModifierKeys.Control)
            {
                var tabControl = FindName("TabControl") as System.Windows.Controls.TabControl;
                if (tabControl != null)
                {
                    int tabIndex = e.Key - System.Windows.Input.Key.D1;
                    if (tabIndex < tabControl.Items.Count)
                    {
                        tabControl.SelectedIndex = tabIndex;
                        e.Handled = true;
                    }
                }
            }
            
            // F1 for help
            if (e.Key == System.Windows.Input.Key.F1)
            {
                var tabControl = FindName("TabControl") as System.Windows.Controls.TabControl;
                if (tabControl != null)
                {
                    tabControl.SelectedIndex = 3; // Help tab
                    e.Handled = true;
                }
            }
        }
        
        /// <summary>
        /// Handles window state changes to minimize to system tray.
        /// </summary>
        private void MainWindow_StateChanged(object? sender, EventArgs e)
        {
            if (this.WindowState == WindowState.Minimized)
            {
                this.Hide();
                if (_notifyIcon != null)
                {
                    _notifyIcon.ShowBalloonTip(
                        2000, 
                        "YAMAGoya", 
                        "Application is running in the system tray.", 
                        ToolTipIcon.Info);
                }
            }
        }
        
        /// <summary>
        /// Handles window closing to minimize to tray instead of closing the application.
        /// </summary>
        private void MainWindow_Closing(object? sender, CancelEventArgs e)
        {
            e.Cancel = true;
            this.WindowState = WindowState.Minimized;
        }

        /// <summary>
        /// Checks the ETW session status when the window loads and updates the UI.
        /// </summary>
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // Try to start the session to check if it's already running
                EtwSession.StartEtwSession(Config.sessionName);
                // If no exception, then the session wasn't running, but now it is
                if (IsSessionRunning(Config.sessionName))
                {
                    ChangeStatus_sessionRunning();
                    AppendAlert("Application started - ETW session started.");
                }
                else
                {
                    ChangeStatus_sessionNotRunning();
                    AppendAlert("Application started - Failed to start ETW session.");
                }
            }
            catch (InvalidOperationException)
            {
                // Session is already running
                if (IsSessionRunning(Config.sessionName))
                {
                    ChangeStatus_sessionRunning();
                    AppendAlert("Application started - ETW session is already running.");
                }
                else
                {
                    ChangeStatus_sessionNotRunning();
                    AppendAlert("Application started - ETW session status check failed.");
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                ChangeStatus_sessionNotRunning();
                AppendAlert($"Error accessing ETW session: {ex.Message}");
                MessageBox.Show($"Access denied when starting ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (IOException ex)
            {
                ChangeStatus_sessionNotRunning();
                AppendAlert($"I/O error when checking ETW session: {ex.Message}");
                MessageBox.Show($"I/O error when starting ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Appends a status message with a timestamp to the alert monitoring ListBox.
        /// Enhanced with accessibility announcements.
        /// </summary>
        /// <param name="message">The status message to append.</param>
        public void AppendAlert(string message)
        {
            // Validate input parameter
            ArgumentNullException.ThrowIfNull(message);

            // If we're not on the UI thread, re-invoke this method on the UI thread.
            if (!this.Dispatcher.CheckAccess())
            {
                this.Dispatcher.Invoke(() => AppendAlert(message));
                return;
            }

            // Format the timestamp using invariant culture.
            string timeStamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            string fullMessage = $"{timeStamp}: {message}";
            
            // Create alert item with appropriate color
            var alertItem = new AlertItem
            {
                Message = fullMessage,
                Foreground = message.Contains("DETECTED", StringComparison.Ordinal) ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Black
            };
            
            lstAlerts.Items.Add(alertItem);
            
            // Announce important alerts to screen readers
            if (message.Contains("started", StringComparison.OrdinalIgnoreCase) || 
                message.Contains("stopped", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("DETECTED", StringComparison.Ordinal))
            {
                AutomationPeer peer = UIElementAutomationPeer.FromElement(lstAlerts);
                if (peer != null)
                {
                    peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
                }
            }
        }

        /// <summary>
        /// Starts the ETW session.
        /// </summary>
        private void BtnStartSession_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                EtwSession.StartEtwSession(Config.sessionName);
                if (IsSessionRunning(Config.sessionName))
                {
                    ChangeStatus_sessionRunning();
                    AppendAlert("ETW session started.");
                }
                else
                {
                    ChangeStatus_sessionNotRunning();
                    AppendAlert("Failed to start ETW session.");
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                ChangeStatus_sessionNotRunning();
                MessageBox.Show($"Error starting ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (InvalidOperationException ex)
            {
                if (IsSessionRunning(Config.sessionName))
                {
                    ChangeStatus_sessionRunning();
                    AppendAlert("ETW session is already running.");
                }
                else
                {
                    ChangeStatus_sessionNotRunning();
                    MessageBox.Show($"Error starting ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        /// <summary>
        /// Stops the ETW session.
        /// </summary>
        private void BtnStopSession_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                EtwSession.StopEtwSession(Config.sessionName);
                ChangeStatus_sessionNotRunning();
                AppendAlert("ETW session stopped.");
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show($"Error stopping ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (InvalidOperationException ex)
            {
                MessageBox.Show($"Error stopping ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Opens a FolderBrowserDialog for selecting the rules folder.
        /// </summary>
        private void BtnBrowseRules_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new FolderBrowserDialog())
            {
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    txtRulesFolder.Text = dialog.SelectedPath;
                }
            }
        }

        /// <summary>
        /// Opens a FileDialog for selecting the log folder.
        /// </summary>
        private void BtnBrowseLogs_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new FolderBrowserDialog())
            {
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    txtLogFolder.Text = dialog.SelectedPath;
                }
            }
        }

        /// <summary>
        /// Starts the detection process asynchronously.
        /// </summary>
        private async void BtnStartDetection_Click(object sender, RoutedEventArgs e)
        {
            string folder = txtRulesFolder.Text;
            bool killOption = tgbKillProcess.IsChecked == true;
            bool sigmaOption = tgbUseSigma.IsChecked == true;
            bool yaraOption = tgbUseYara.IsChecked == true;
            bool eventLogOption = tgbEventLog.IsChecked == true;
            bool textLogOption = tgbTextLog.IsChecked == true;
            bool sessionNameOption = tgbSessionName.IsChecked == true;

            if (string.IsNullOrWhiteSpace(folder))
            {
                MessageBox.Show("Please specify a rules folder.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (sessionNameOption)
            {
                Dispatcher.Invoke(() => {
                    Config.sessionName = txtSessionName.Text;
                });
            }

            if (yaraOption)
            {
                Dispatcher.Invoke(() => {
                    if (int.TryParse(txtMemoryScanInterval.Text, out int interval))
                    {
                        Config.memoryScanInterval = interval;
                    }
                    else
                    {
                        MessageBox.Show("Invalid memory scan interval. Please enter a valid number.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                });
            }

            try
            {
                EtwSession.StartEtwSession(Config.sessionName);
                if (IsSessionRunning(Config.sessionName))
                {
                    ChangeStatus_sessionRunning();
                    AppendAlert("ETW session started.");
                }
                else
                {
                    ChangeStatus_sessionNotRunning();
                    AppendAlert("Failed to start ETW session. Cannot proceed with detection.");
                    return;
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                ChangeStatus_sessionNotRunning();
                MessageBox.Show($"Error starting ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            catch (InvalidOperationException ex)
            {
                if (IsSessionRunning(Config.sessionName))
                {
                    ChangeStatus_sessionRunning();
                    AppendAlert("ETW session is already running.");
                }
                else
                {
                    ChangeStatus_sessionNotRunning();
                    MessageBox.Show($"Error starting ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }
            catch (IOException ex)
            {
                ChangeStatus_sessionNotRunning();
                MessageBox.Show($"I/O error when starting ETW session: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _detectionCts = new CancellationTokenSource();
            CancellationToken token = _detectionCts.Token;

            AppendAlert("Starting detection...");

            ChangeStatus_detectionRunning();

            await Task.Run(() =>
            {
                _staDetectionThread = new Thread(() =>
                {
                    try
                    {
                        using (var detect = new Detect())
                        {
                            var options = new List<string> {"--all"};
                            if (killOption)
                            {
                                options.Add("--kill");
                            }
                            if (sigmaOption)
                            {
                                options.Add("--sigma");
                            } else
                            {
                                options.Add("--detect");
                            }
                            if (yaraOption)
                            {
                                options.Add("--yara");
                            }
                            if (eventLogOption)
                            {
                                options.Add("--no_event_log");
                            }
                            if (textLogOption)
                            {
                                options.Add("--no_text_log");
                            }

                            Dispatcher.Invoke(() => {
                                Config.logDirectory = txtLogFolder.Text;
                            });
                            detect.StartEtwDetection(folder, options.ToArray(), Config.sessionName, token);
                        }
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            ChangeStatus_sessionRunning();
                            MessageBox.Show($"UnauthorizedAccessException during detection: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                    }
                    catch (InvalidOperationException ex)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            ChangeStatus_sessionRunning();
                            MessageBox.Show($"InvalidOperationException during detection: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                    }
                    catch (IOException ex)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            ChangeStatus_sessionRunning();
                            MessageBox.Show($"IOException during detection: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                    }
                });
                _staDetectionThread.SetApartmentState(ApartmentState.STA);
                _staDetectionThread.Start();
                _staDetectionThread.Join();
            }, token).ConfigureAwait(false);

            AppendAlert("Detection stopped.");
        }

        /// <summary>
        /// Stops the detection process and restarts the ETW session.
        /// </summary>
        private void BtnStopDetection_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _detectionCts?.Cancel();
                _detectionCts?.Dispose();
                _detectionCts = null;

                AppendAlert("Detection stopped.");
                if (IsSessionRunning(Config.sessionName))
                {
                    ChangeStatus_sessionRunning();
                }
                else
                {
                    ChangeStatus_sessionNotRunning();
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show($"Access denied error: {ex.Message}");
            }
            catch (InvalidOperationException ex)
            {
                MessageBox.Show($"Invalid operation error: {ex.Message}");
            }
            catch (IOException ex)
            {
                MessageBox.Show($"I/O error: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates the status of the ETW session running.
        /// Enhanced with accessibility announcements.
        /// </summary>
        private void ChangeStatus_sessionRunning()
        {
            txtSessionStatus.Text = "Status: Ready to Detect";
            txtSessionStatus.Foreground = new SolidColorBrush(Colors.White);
            txtSessionStatusBackground.Background = new SolidColorBrush(Colors.LightSkyBlue);
            sessionStatusIcon.Kind = MaterialDesignThemes.Wpf.PackIconKind.Check;
            
            // Announce status change to screen readers
            AutomationPeer peer = UIElementAutomationPeer.FromElement(txtSessionStatus);
            if (peer != null)
            {
                peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
            }
        }

        /// <summary>
        /// Updates the status of the ETW session not running.
        /// Enhanced with accessibility announcements.
        /// </summary>
        private void ChangeStatus_sessionNotRunning()
        {
            txtSessionStatus.Text = "Status: ETW Session Not Running\r\n(Please run as Administrator)";
            txtSessionStatus.Foreground = new SolidColorBrush(Colors.White);
            txtSessionStatusBackground.Background = new SolidColorBrush(Colors.LightCoral);
            sessionStatusIcon.Kind = MaterialDesignThemes.Wpf.PackIconKind.Information;
            
            // Announce status change to screen readers
            AutomationPeer peer = UIElementAutomationPeer.FromElement(txtSessionStatus);
            if (peer != null)
            {
                peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
            }
        }

        /// <summary>
        /// Updates the status of the detection running.
        /// Enhanced with accessibility announcements.
        /// </summary>
        private void ChangeStatus_detectionRunning()
        {
            txtSessionStatus.Text = "Status: Detection Running";
            txtSessionStatus.Foreground = new SolidColorBrush(Colors.White);
            txtSessionStatusBackground.Background = new SolidColorBrush(Colors.LightGreen);
            sessionStatusIcon.Kind = MaterialDesignThemes.Wpf.PackIconKind.Check;
            
            // Announce status change to screen readers
            AutomationPeer peer = UIElementAutomationPeer.FromElement(txtSessionStatus);
            if (peer != null)
            {
                peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
            }
        }

        /// <summary>
        /// Checks if the ETW session is currently running.
        /// </summary>
        /// <param name="sessionName">The name of the ETW session to check.</param>
        /// <returns>True if the session is running, false otherwise.</returns>
        [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Method is designed to never throw and always return a boolean result")]
        private static bool IsSessionRunning(string sessionName)
        {
            try
            {
                EtwSession.StopEtwSession(sessionName);
                EtwSession.StartEtwSession(sessionName);
                return true;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }

        /// <summary>
        /// Opens the log file using the default associated application.
        /// If using date-based log files, opens the most recent log file.
        /// </summary>
        private void BtnOpenLog_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string logDirectory = Config.logDirectory;
                if (Directory.Exists(logDirectory))
                {
                    string todayLogFile = Path.Combine(
                        logDirectory, 
                        string.Format(
                            CultureInfo.InvariantCulture, 
                            s_logFileNameFormat, 
                            DateTime.Today.ToString(Config.logDateFormat, CultureInfo.InvariantCulture))
                    );

                    // if the log file for today exists, open it
                    if (File.Exists(todayLogFile))
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = todayLogFile,
                            UseShellExecute = true
                        });
                    }
                    else
                    {
                        // if the log file for today does not exist, open the most recent log file
                        var logFiles = Directory.GetFiles(logDirectory, "*.log")
                            .OrderByDescending(f => new FileInfo(f).LastWriteTime)
                            .ToArray();

                        if (logFiles.Length > 0)
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = logFiles[0],
                                UseShellExecute = true
                            });
                        }
                        else
                        {
                            MessageBox.Show("No log files found in the log directory.", 
                                "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                }
                else
                {
                    MessageBox.Show($"Log directory '{logDirectory}' does not exist.", 
                        "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show($"Error opening log file: {ex.Message}", 
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (IOException ex)
            {
                MessageBox.Show($"Error opening log file: {ex.Message}", 
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Opens the GitHub URL in the default browser when the GitHub icon is clicked.
        /// </summary>
        private void BtnGitHub_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/JPCERTCC/YAMAGoya",
                    UseShellExecute = true
                });
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show($"Failed to open GitHub page: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Opens the URL when a hyperlink is clicked.
        /// </summary>
        private void Hyperlink_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = e.Uri.AbsoluteUri,
                    UseShellExecute = true
                });
                e.Handled = true;
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show($"Failed to open link: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Tab selection change event to reset scroll position when Help tab is selected.
        /// </summary>
        private void TabControl_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (helpTabItem.IsSelected && helpScrollViewer != null)
            {
                Dispatcher.BeginInvoke(new Action(() => {
                    helpScrollViewer.ScrollToHome();
                }), System.Windows.Threading.DispatcherPriority.ContextIdle);
            }
        }

        /// <summary>
        /// Represents an alert item with color information for the GUI list.
        /// </summary>
        internal sealed class AlertItem
        {
            /// <summary>
            /// Gets or sets the alert message text.
            /// </summary>
            public string Message { get; set; } = string.Empty;
            
            /// <summary>
            /// Gets or sets the foreground brush for text color.
            /// </summary>
            public System.Windows.Media.Brush Foreground { get; set; } = System.Windows.Media.Brushes.Black;
            
            /// <summary>
            /// Gets the display text for the alert item.
            /// </summary>
            public string DisplayText => Message;
        }
    }
}
