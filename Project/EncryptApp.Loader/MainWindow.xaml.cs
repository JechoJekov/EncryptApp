using System;
using System.Collections.Generic;
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

namespace EncryptApp.Loader
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
        }

        private void Window_Closed(object sender, EventArgs e)
        {

        }

        private void buttonOK_Click(object sender, RoutedEventArgs e)
        {
            var password = textBoxPassword.Password;
            
            if (password.Length == 0)
            {
                textBoxPassword.Focus();
                return;
            }

            panelOverlay.Visibility = Visibility.Visible;

            Task.Factory.StartNew(() => ApplicationLoader.Load(password)).ContinueWith(task =>
            {
                panelOverlay.Visibility = Visibility.Hidden;

                if (task.Exception != null)
                {
                    if (task.Exception.InnerExceptions[0] is ApplicationLoaderException exc)
                    {
#if DEBUG
                        MessageBox.Show(
                            $"Error:\n\n{exc}",
                            "Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error,
                            MessageBoxResult.OK
                            );
#else
                        MessageBox.Show(
                            $"Error!",
                            "Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error,
                            MessageBoxResult.OK
                            );
#endif
                    }
                    else
                    {
                        // Rethrow the exception
                        throw task.Exception;
                    }
                }
                else
                {
                    // Exit the loader
                    Close();
                }
            }, TaskScheduler.FromCurrentSynchronizationContext());

#if DEPRECATED // Requires .NET 4.5

            try
            {
                

                // Exit the loader
                Close();
            }
            catch (ApplicationLoaderException exc)
            {
#if DEBUG
                MessageBox.Show(
                    $"Error:\n\n{exc}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error,
                    MessageBoxResult.OK
                    );
#else
                MessageBox.Show(
                    $"Error!",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error,
                    MessageBoxResult.OK
                    );
#endif
            }
            finally
            {
                panelOverlay.Visibility = Visibility.Hidden;
            }

#endif
        }

        private void buttonCancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                Close();
            }
        }
    }
}
