using Microsoft.Win32;
using Secure_file_vault.Models;
using Secure_file_vault.Services;
using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace Secure_file_vault
{
    public partial class MainWindow : Window
    {
        private string _currentVaultPath;
        private VaultMetadata _currentMetadata;
        private CryptoService _cryptoService;
        private SecureDeleteService _deleteService;
        private byte[] _currentKey;
        private SecureString _currentPassword;

        public MainWindow()
        {
            InitializeComponent();
            _cryptoService = new CryptoService();
            _deleteService = new SecureDeleteService();
        }

        private async void CreateVaultButton_Click(object sender, RoutedEventArgs e)
        {
            string vaultPath = VaultPathTextBox.Text;

            if (string.IsNullOrWhiteSpace(vaultPath))
            {
                ShowError("Укажите путь для хранилища");
                return;
            }

            try
            {
                // Проверка
                if (Directory.Exists(vaultPath) && File.Exists(Path.Combine(vaultPath, "vault.meta")))
                {
                    if (MessageBox.Show("В этой папке уже существует хранилище. Перезаписать?",
                        "Предупреждение", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                        return;
                }

                Directory.CreateDirectory(vaultPath);
                string dataPath = Path.Combine(vaultPath, "Data");
                Directory.CreateDirectory(dataPath);

                var password = await GetPasswordFromUser("Создание хранилища",
                    "Введите мастер-пароль для нового хранилища:", true);

                if (password == null)
                    return;

                byte[] salt = _cryptoService.GenerateRandomSalt();

                _currentPassword = password;
                _currentKey = _cryptoService.DeriveKeyFromSecureString(_currentPassword, salt, 100000);

                byte[] verifier = _cryptoService.CreateMasterKeyVerifier(_currentKey);

                _currentMetadata = new VaultMetadata
                {
                    MasterKeySalt = salt,
                    MasterKeyVerifier = verifier,
                    Pbkdf2Iterations = 100000
                };

                string metadataPath = Path.Combine(vaultPath, "vault.meta");
                await SaveMetadataAsync(metadataPath);

                _currentVaultPath = vaultPath;

                UpdateUIState(true);
                ShowStatus("Хранилище успешно создано", true);
                RefreshFileList();
            }
            catch (Exception ex)
            {
                ShowError($"Ошибка при создании хранилища: {ex.Message}");
            }
        }

        private async void OpenVaultButton_Click(object sender, RoutedEventArgs e)
        {
            string vaultPath = VaultPathTextBox.Text;

            if (!Directory.Exists(vaultPath))
            {
                ShowError("Указанная папка не существует");
                return;
            }

            string metadataPath = Path.Combine(vaultPath, "vault.meta");
            if (!File.Exists(metadataPath))
            {
                ShowError("В указанной папке нет хранилища (файл vault.meta не найден)");
                return;
            }

            try
            {
                var password = await GetPasswordFromUser("Открытие хранилища",
                    "Введите мастер-пароль для открытия хранилища:", false);

                if (password == null)
                    return;

                _currentMetadata = await LoadMetadataAsync(metadataPath);

                byte[] testKey = _cryptoService.DeriveKeyFromSecureString(
                    password, _currentMetadata.MasterKeySalt, _currentMetadata.Pbkdf2Iterations);

                if (!_cryptoService.VerifyMasterKey(testKey, _currentMetadata.MasterKeyVerifier))
                {
                    ShowError("Неверный мастер-пароль!");
                    return;
                }

                _currentVaultPath = vaultPath;
                _currentPassword = password;
                _currentKey = testKey;

                UpdateUIState(true);
                ShowStatus("Хранилище успешно открыто", true);
                RefreshFileList();
            }
            catch (Exception ex)
            {
                ShowError($"Ошибка при открытии хранилища: {ex.Message}");
                UpdateUIState(false);
            }
        }

        private async void AddFileButton_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog();
            openDialog.Title = "Выберите файл для добавления";
            openDialog.Multiselect = false;

            if (openDialog.ShowDialog() == true)
            {
                try
                {
                    string fileName = openDialog.FileName;
                    string fileId = Guid.NewGuid().ToString();
                    string encryptedFileName = $"{fileId}.enc";
                    string encryptedPath = Path.Combine(_currentVaultPath, "Data", encryptedFileName);

                    byte[] iv = _cryptoService.GenerateRandomIv();

                    byte[] tag = await _cryptoService.EncryptFileToFileAsync(fileName, encryptedPath, _currentKey, iv);

                    var fileInfo = new FileInfo(fileName);
                    var metadata = new FileMetadata
                    {
                        Id = fileId,
                        OriginalFileName = Path.GetFileName(fileName),
                        EncryptedFileName = encryptedFileName,
                        Iv = iv,
                        Tag = tag,
                        OriginalFileSize = fileInfo.Length,
                        AddedDate = DateTime.Now
                    };

                    _currentMetadata.Files.Add(metadata);
                    await SaveMetadataAsync(Path.Combine(_currentVaultPath, "vault.meta"));

                    RefreshFileList();
                    ShowStatus($"Файл {metadata.OriginalFileName} успешно добавлен", true);
                }
                catch (Exception ex)
                {
                    ShowError($"Ошибка при добавлении файла: {ex.Message}");
                }
            }
        }

        private async void ExtractFileButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedFile = FilesListView.SelectedItem as FileMetadata;
            if (selectedFile == null)
            {
                ShowError("Выберите файл для извлечения");
                return;
            }


            var password = await GetPasswordFromUser("Подтверждение пароля", $"Введите мастер-пароль для извлечения файла '{selectedFile.OriginalFileName}':", false);

            if (password == null)
                return;

            byte[] testKey;
            try
            {
                testKey = _cryptoService.DeriveKeyFromSecureString(
                    password, _currentMetadata.MasterKeySalt, _currentMetadata.Pbkdf2Iterations);

                if (!_cryptoService.VerifyMasterKey(testKey, _currentMetadata.MasterKeyVerifier))
                {
                    ShowError("Неверный мастер-пароль! Доступ к файлу запрещен.");
                    return;
                }
            }
            catch (Exception ex)
            {
                ShowError($"Ошибка при проверке пароля: {ex.Message}");
                return;
            }



            var saveDialog = new SaveFileDialog();
            saveDialog.Title = "Сохранить расшифрованный файл как";
            saveDialog.FileName = selectedFile.OriginalFileName;

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    string encryptedPath = Path.Combine(_currentVaultPath, "Data", selectedFile.EncryptedFileName);

                    byte[] decryptedData = await _cryptoService.DecryptFileAsync(
                        encryptedPath, _currentKey, selectedFile.Iv, selectedFile.Tag);

                    await File.WriteAllBytesAsync(saveDialog.FileName, decryptedData);
                    ShowStatus($"Файл {selectedFile.OriginalFileName} успешно извлечен", true);
                }
                catch (Exception ex)
                {
                    ShowError($"Ошибка при извлечении файла: {ex.Message}");
                }
            }
        }

        private async void SecureDeleteButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedFile = FilesListView.SelectedItem as FileMetadata;
            if (selectedFile == null)
            {
                ShowError("Выберите файл для безопасного удаления");
                return;
            }

            if (MessageBox.Show($"Вы действительно хотите безопасно удалить файл {selectedFile.OriginalFileName}?\n" +
                "Это действие необратимо!", "Подтверждение удаления",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
            {
                try
                {
                    string encryptedPath = Path.Combine(_currentVaultPath, "Data", selectedFile.EncryptedFileName);
                    await _deleteService.SecureDeleteAsync(encryptedPath);

                    _currentMetadata.Files.Remove(selectedFile);
                    await SaveMetadataAsync(Path.Combine(_currentVaultPath, "vault.meta"));

                    RefreshFileList();
                    ShowStatus($"Файл {selectedFile.OriginalFileName} безопасно удален", true);
                }
                catch (Exception ex)
                {
                    ShowError($"Ошибка при удалении: {ex.Message}");
                }
            }
        }

        private async void VerifyIntegrityButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedFile = FilesListView.SelectedItem as FileMetadata;
            if (selectedFile == null)
            {
                ShowError("Выберите файл для проверки");
                return;
            }

            try
            {
                string encryptedPath = Path.Combine(_currentVaultPath, "Data", selectedFile.EncryptedFileName);

                bool isValid = await _cryptoService.VerifyIntegrity(
                    encryptedPath, _currentKey, selectedFile.Iv, selectedFile.Tag);

                if (isValid)
                {
                    MessageBox.Show($"Файл {selectedFile.OriginalFileName} целостен и не поврежден",
                        "Проверка целостности", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show($"Файл {selectedFile.OriginalFileName} поврежден или был изменен!",
                        "Ошибка целостности", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                ShowError($"Файл {selectedFile.OriginalFileName} поврежден! {ex.Message}");
            }
        }

        private async Task<SecureString> GetPasswordFromUser(string title, string message, bool confirmPassword)
        {
            var dialog = new PasswordDialog(title, message, confirmPassword);
            if (dialog.ShowDialog() == true)
            {
                return dialog.Password;
            }
            return null;
        }

        private async Task SaveMetadataAsync(string path)
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            string json = JsonSerializer.Serialize(_currentMetadata, options);
            await File.WriteAllTextAsync(path, json);
        }

        private async Task<VaultMetadata> LoadMetadataAsync(string path)
        {
            string json = await File.ReadAllTextAsync(path);
            return JsonSerializer.Deserialize<VaultMetadata>(json);
        }

        private void RefreshFileList()
        {
            FilesListView.ItemsSource = null;
            FilesListView.ItemsSource = _currentMetadata.Files;
        }

        private void UpdateUIState(bool isVaultOpen)
        {
            AddFileButton.IsEnabled = isVaultOpen;

            if (!isVaultOpen)
            {
                ExtractFileButton.IsEnabled = false;
                SecureDeleteButton.IsEnabled = false;
                VerifyIntegrityButton.IsEnabled = false;
                FilesListView.ItemsSource = null;
            }
        }

        private void FilesListView_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            bool hasSelection = FilesListView.SelectedItem != null;
            ExtractFileButton.IsEnabled = hasSelection && _currentVaultPath != null;
            SecureDeleteButton.IsEnabled = hasSelection && _currentVaultPath != null;
            VerifyIntegrityButton.IsEnabled = hasSelection && _currentVaultPath != null;
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog();
            dialog.Title = "Выберите папку для хранилища";

            if (dialog.ShowDialog() == true)
            {
                VaultPathTextBox.Text = dialog.FolderName;
            }
        }

        private void ShowError(string message)
        {
            MessageBox.Show(message, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            ShowStatus(message, false);
        }

        private void ShowStatus(string message, bool isSuccess)
        {
            StatusText.Text = message;
            StatusText.Foreground = isSuccess ?
                System.Windows.Media.Brushes.Green : System.Windows.Media.Brushes.Red;
        }

        protected override void OnClosed(EventArgs e)
        {
            _cryptoService?.Dispose();

            if (_currentKey != null)
            {
                Array.Clear(_currentKey, 0, _currentKey.Length);
                _currentKey = null;
            }

            _currentPassword?.Dispose();

            base.OnClosed(e);
        }
    }
}