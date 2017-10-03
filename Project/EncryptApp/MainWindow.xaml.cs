using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using WPFFolderBrowser;

namespace EncryptApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        static string ApplicationName = Assembly.GetExecutingAssembly().GetName().Name;

        const string LoaderFileName = "Loader.exe";

        WPFFolderBrowserDialog _applicationPathDialog;

        public MainWindow()
        {
            InitializeComponent();
        }

        private async void buttonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            var applicationPath = textBoxApplicationPath.Text.Trim();
            var password = textBoxPassword.Password;
            var confirmPassword = textBoxPassword_Confirm.Password;

            #region Validate parameters

            if (applicationPath.Length == 0)
            {
                textBoxApplicationPath.Focus();
                return;
            }

            if (password.Length == 0)
            {
                textBoxPassword.Focus();
                return;
            }

            if (password != confirmPassword)
            {
                MessageBox.Show(
                    "Passwords do not match.",
                    "Encrypt",
                    MessageBoxButton.OK,
                    MessageBoxImage.Stop,
                    MessageBoxResult.OK
                    );

                textBoxPassword_Confirm.Focus();
                return;
            }

            #endregion

            var loaderPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LoaderFileName);

            if (false == File.Exists(loaderPath))
            {
                MessageBox.Show(
                    $"'{LoaderFileName}' not found. The file must be located in {ApplicationName}'s folder.",
                    "Encrypt",
                    MessageBoxButton.OK,
                    MessageBoxImage.Stop,
                    MessageBoxResult.OK
                    );
            }
            else if (false == Directory.Exists(applicationPath))
            {
                MessageBox.Show(
                    $"Application directory '{applicationPath}' not found.",
                    "Encrypt",
                    MessageBoxButton.OK,
                    MessageBoxImage.Stop,
                    MessageBoxResult.OK
                    );
            }
            else if (false == Encryptor.IsApplication(applicationPath))
            {
                MessageBox.Show(
                    "The specified path does not contain an application.",
                    "Encrypt",
                    MessageBoxButton.OK,
                    MessageBoxImage.Stop,
                    MessageBoxResult.OK
                    );
            }
            else if (Encryptor.IsEncryptedApplication(applicationPath))
            {
                MessageBox.Show(
                    "The specified application is already encrypted.",
                    "Encrypt",
                    MessageBoxButton.OK,
                    MessageBoxImage.Stop,
                    MessageBoxResult.OK
                    );
            }
            else
            {
                panelOverlay.Visibility = Visibility.Visible;

                try
                {
                    var encryptedFilesList = await Task.Run(() => Encryptor.Encrypt(applicationPath, loaderPath, password));

                    if (encryptedFilesList.Count == 0)
                    {
                        MessageBox.Show(
                            "The specified path does not contain a .NET application.",
                            "Encrypt",
                            MessageBoxButton.OK,
                            MessageBoxImage.Stop,
                            MessageBoxResult.OK
                            );
                    }
                    else
                    {
                        MessageBox.Show(
                            "Encryption complete.",
                            "Encrypt",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information,
                            MessageBoxResult.OK
                            );

                        textBoxApplicationPath.Text = null;
                        textBoxPassword.Password = null;
                        textBoxPassword_Confirm.Password = null;

                        textBoxApplicationPath.Focus();
                    }
                }
                catch (Exception exc)
                {
                    MessageBox.Show(
                        $"An error occurred during the encryption:\n\n{exc}.",
                        "Encrypt",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error,
                        MessageBoxResult.OK
                        );
                }
                finally
                {
                    panelOverlay.Visibility = Visibility.Hidden;
                }
            }
        }

        private void buttonApplicationPath_Browse_Click(object sender, RoutedEventArgs e)
        {
            if (_applicationPathDialog == null)
            {
                _applicationPathDialog = new WPFFolderBrowserDialog("Path to application directory");
            }

            if (_applicationPathDialog.ShowDialog() == true)
            {
                textBoxApplicationPath.Text = _applicationPathDialog.FileName;
            }
        }

        private void Window_Closed(object sender, EventArgs e)
        {
            if (_applicationPathDialog != null)
            {
                // The dispose method is not implemented by the library
                //_applicationPathDialog.Dispose();
                _applicationPathDialog = null;
            }
        }
    }
}
