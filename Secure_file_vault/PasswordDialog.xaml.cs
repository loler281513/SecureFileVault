using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;

namespace Secure_file_vault
{
    public partial class PasswordDialog : Window
    {
        public SecureString Password { get; private set; }
        private bool _confirmPassword;

        public PasswordDialog(string title, string message, bool confirmPassword = false)
        {
            InitializeComponent();
            this.Title = title;
            MessageText.Text = message;
            _confirmPassword = confirmPassword;

            if (confirmPassword)
            {
                ConfirmLabel.Visibility = Visibility.Visible;
                ConfirmPasswordBox.Visibility = Visibility.Visible;
                this.Height = 250;
            }
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (_confirmPassword)
            {
                if (!PasswordsMatch())
                {
                    MessageBox.Show("Пароли не совпадают!", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    PasswordBox.Clear();
                    ConfirmPasswordBox.Clear();
                    PasswordBox.Focus();
                    return;
                }

                if (PasswordBox.SecurePassword.Length == 0)
                {
                    MessageBox.Show("Пароль не может быть пустым!", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }

            Password = PasswordBox.SecurePassword;
            DialogResult = true;
            Close();
        }

        private bool PasswordsMatch()
        {
            if (PasswordBox.SecurePassword.Length != ConfirmPasswordBox.SecurePassword.Length)
                return false;

            IntPtr pwdPtr = IntPtr.Zero;
            IntPtr confirmPtr = IntPtr.Zero;

            try
            {
                pwdPtr = Marshal.SecureStringToBSTR(PasswordBox.SecurePassword);
                confirmPtr = Marshal.SecureStringToBSTR(ConfirmPasswordBox.SecurePassword);

                int length = PasswordBox.SecurePassword.Length;

                // Сравниваем посимвольно (каждый символ в UTF-16 занимает 2 байта)
                for (int i = 0; i < length; i++)
                {
                    char c1 = (char)Marshal.ReadInt16(pwdPtr, i * 2);
                    char c2 = (char)Marshal.ReadInt16(confirmPtr, i * 2);

                    if (c1 != c2)
                        return false;
                }

                return true;
            }
            finally
            {
                if (pwdPtr != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(pwdPtr);
                if (confirmPtr != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(confirmPtr);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        protected override void OnClosed(EventArgs e)
        {
            // Очищаем чувствительные данные
            PasswordBox.Clear();
            ConfirmPasswordBox.Clear();
            base.OnClosed(e);
        }
    }
}