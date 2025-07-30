using System;
using System.Windows;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;

namespace YAMAGoya
{
    /// <summary>
    /// Interaction logic for App.xaml.
    /// This class serves as the entry point of the application.
    /// It determines whether to run in GUI mode or command-line mode based on startup arguments.
    /// </summary>
    [SuppressMessage("Design", "CA1515:Type can be made internal", Justification = "App must be public for XAML binding to work properly.")]
    public partial class App : Application
    {
        /// <summary>
        /// Gets or sets a value indicating whether the application is running in GUI mode.
        /// When command-line arguments are provided, this property remains false.
        /// </summary>
        public static bool IsGuiMode { get; set; }

        /// <summary>
        /// Attaches the calling process to the console of an existing process.
        /// Pass -1 to attach to the parent process's console.
        /// </summary>
        /// <param name="processId">The process ID to attach to.</param>
        /// <returns>True if successful; otherwise, false.</returns>
        [DllImport("Kernel32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool AttachConsole(int processId);

        /// <summary>
        /// Static constructor. Attempts to attach the process to the parent's console.
        /// </summary>
        static App()
        {
            AttachConsole(-1);
        }

        /// <summary>
        /// Called when the application starts.
        /// If command-line arguments are provided, the application runs in command-line mode.
        /// Otherwise, it launches the GUI.
        /// </summary>
        /// <param name="e">Startup event arguments.</param>
        protected override void OnStartup(StartupEventArgs e)
        {
            // Ensure that the StartupEventArgs is not null.
            ArgumentNullException.ThrowIfNull(e);

            base.OnStartup(e);

            // If command-line arguments are provided, run in command-line mode.
            if (e.Args != null && e.Args.Length > 0)
            {
                Console.WriteLine("Running in command-line mode...");
                try
                {
                    CommandLineProcessor.Process(e.Args);
                }
                catch (ArgumentException ex)
                {
                    MessageBox.Show($"Argument error: {ex.Message}", "YAMAGoya Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (InvalidOperationException ex)
                {
                    MessageBox.Show($"Operation error: {ex.Message}", "YAMAGoya Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                // Rethrow any other exceptions.
                catch
                {
                    MessageBox.Show("An unexpected error occurred. Please check the logs for more details.", "YAMAGoya Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    throw;
                }
                Shutdown();
            }
            else
            {
                IsGuiMode = true;
                MainWindow mainWindow = new MainWindow();
                mainWindow.Show();
            }
        }
    }
}
