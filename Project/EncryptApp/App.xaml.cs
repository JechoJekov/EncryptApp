using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace EncryptApp
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private void Application_Startup(object sender, StartupEventArgs e)
        {
            // All paths should be considered relative to the directory in which the program resides
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            // Set the default culture
            Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
            Thread.CurrentThread.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");

            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        }

        private void Application_Exit(object sender, ExitEventArgs e)
        {

        }

        private void Application_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            ShowError(e.Exception);
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            ShowError((Exception)e.ExceptionObject);
        }

        void ShowError(Exception exc)
        {
            if (CheckAccess())
            {
                MessageBox.Show(
                    $"An unexpected application error occurred:\n{exc}",
                    "Application Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error,
                    MessageBoxResult.OK,
                    MessageBoxOptions.None
                    );
            }
            else
            {
                Dispatcher.Invoke(new Action<Exception>(ShowError), exc);
            }
        }
    }
}
