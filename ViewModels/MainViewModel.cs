using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using CertDecipher.Models;

namespace CertDecipher.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private string _certificateContent = string.Empty;
        private string _statusMessage = string.Empty;

        public MainViewModel()
        {
            Properties = new ObservableCollection<CertificateProperty>();
            SelectFileCommand = new RelayCommand(_ => SelectFile());
            CopyCommand = new RelayCommand(_ => CopyCertificateContent(), _ => !string.IsNullOrEmpty(CertificateContent));
            ExportCommand = new RelayCommand(_ => ExportToFile(), _ => Properties.Count > 0);
            StatusMessage = "Ready. Select a certificate file (PEM, DER, PFX, or PKCS#12) to view its details.";
        }

        public ICommand SelectFileCommand { get; }
        public ICommand CopyCommand { get; }
        public ICommand ExportCommand { get; }

        public string CertificateContent
        {
            get => _certificateContent;
            set
            {
                if (_certificateContent != value)
                {
                    _certificateContent = value;
                    OnPropertyChanged(nameof(CertificateContent));
                    OnPropertyChanged(nameof(HasCertificateContent));
                }
            }
        }

        public bool HasCertificateContent => !string.IsNullOrEmpty(CertificateContent);

        public ObservableCollection<CertificateProperty> Properties { get; }

        public string StatusMessage
        {
            get => _statusMessage;
            set
            {
                if (_statusMessage != value)
                {
                    _statusMessage = value;
                    OnPropertyChanged(nameof(StatusMessage));
                }
            }
        }

        private void SelectFile()
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "Certificate Files (*.pem;*.cer;*.crt;*.pfx;*.p12;*.der;*.p7b;*.p7c;*.p8;*.p10;*.csr)|*.pem;*.cer;*.crt;*.pfx;*.p12;*.der;*.p7b;*.p7c;*.p8;*.p10;*.csr|PEM/DER Files (*.pem;*.cer;*.crt;*.der)|*.pem;*.cer;*.crt;*.der|PFX/PKCS#12 Files (*.pfx;*.p12)|*.pfx;*.p12|PKCS#7 Files (*.p7b;*.p7c)|*.p7b;*.p7c|PKCS#8 Private Keys (*.p8)|*.p8|CSR Files (*.p10;*.csr)|*.p10;*.csr|All Files (*.*)|*.*",
                Title = "Open Certificate File (PEM, DER, PFX, PKCS#12, PKCS#7, PKCS#8, CSR)"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                LoadCertificate(openFileDialog.FileName);
            }
        }

        private void LoadCertificate(string filePath)
        {
            try
            {
                string extension = Path.GetExtension(filePath).ToLowerInvariant();

                if (extension == ".pfx" || extension == ".p12")
                {
                    LoadPfxCertificate(filePath);
                }
                else if (extension == ".p7b" || extension == ".p7c")
                {
                    LoadPkcs7Certificate(filePath);
                }
                else if (extension == ".p8")
                {
                    LoadPkcs8PrivateKey(filePath);
                }
                else if (extension == ".p10" || extension == ".csr")
                {
                    LoadCsr(filePath);
                }
                else
                {
                    LoadPemCertificate(filePath);
                }
            }
            catch (Exception ex) when (ex is not CryptographicException)
            {
                StatusMessage = $"Error: {ex.Message}";
            }
        }

        private void LoadPemCertificate(string filePath)
        {
            try
            {
                string extension = Path.GetExtension(filePath).ToLowerInvariant();
                X509Certificate2? certificate = null;
                string displayContent = string.Empty;
                bool isDerFormat = false;
                X509Certificate2Collection? collection = null;

                // First, try to load as PEM (text format)
                try
                {
                    string pemContent = File.ReadAllText(filePath);
                    var certBase64List = ExtractAllCertsFromPem(pemContent);

                    if (certBase64List.Count == 1)
                    {
                        // Single certificate - existing logic
                        byte[] certBytes = Convert.FromBase64String(certBase64List[0]);
                        certificate = new X509Certificate2(certBytes);
                        displayContent = pemContent;
                        isDerFormat = false;
                    }
                    else if (certBase64List.Count > 1)
                    {
                        // Multiple certificates - chain handling
                        collection = new X509Certificate2Collection();
                        foreach (string base64 in certBase64List)
                        {
                            collection.Add(new X509Certificate2(Convert.FromBase64String(base64)));
                        }

                        certificate = collection[0];
                        displayContent = FormatPemChainContent(collection);
                        isDerFormat = false;

                        string chainInfo = collection.Count > 1 ? $" ({collection.Count} certificates)" : "";
                        StatusMessage = $"PEM chain loaded{chainInfo}: {certificate.Subject}";

                        CertificateContent = displayContent;
                        PopulateProperties(certificate, collection, isPfx: false);
                        return; // Early return for multi-cert case
                    }
                }
                catch
                {
                    // Not a certificate PEM file, check for private key or CSR
                }

                // If no certificate found, check for private key in PEM format
                if (certificate == null)
                {
                    try
                    {
                        string pemContent = File.ReadAllText(filePath);
                        var (hasPrivateKey, isEncrypted, keyType) = DetectPrivateKeyInPem(pemContent);

                        if (hasPrivateKey)
                        {
                            // Handle as PEM private key file
                            LoadPemPrivateKey(filePath, pemContent, isEncrypted);
                            return;
                        }

                        // Check for CSR
                        if (pemContent.Contains("-----BEGIN CERTIFICATE REQUEST-----") ||
                            pemContent.Contains("-----BEGIN NEW CERTIFICATE REQUEST-----"))
                        {
                            LoadCsr(filePath);
                            return;
                        }
                    }
                    catch
                    {
                        // Not a PEM private key or CSR, try DER format
                    }
                }

                // If PEM failed, try DER (binary format)
                if (certificate == null)
                {
                    try
                    {
                        byte[] derBytes = File.ReadAllBytes(filePath);
                        certificate = new X509Certificate2(derBytes);
                        displayContent = FormatDerAsPem(derBytes);
                        isDerFormat = true;
                    }
                    catch (CryptographicException)
                    {
                        ClearCertificateData();
                        StatusMessage = "Error: Unable to parse certificate file. The file may be corrupted or in an unsupported format.";
                        return;
                    }
                }

                if (certificate != null)
                {
                    // Set the certificate content for display
                    CertificateContent = displayContent;
                    string encodingFormat = isDerFormat ? "DER encoding" : "PEM encoding";
                    StatusMessage = $"Certificate loaded successfully ({encodingFormat}): {certificate.Subject}";

                    // Populate properties
                    PopulateProperties(certificate, isPfx: false);
                }
                else
                {
                    ClearCertificateData();
                    StatusMessage = "Error: No valid certificate content found in the file.";
                }
            }
            catch (FormatException)
            {
                ClearCertificateData();
                StatusMessage = "Error: The file does not contain valid certificate data.";
            }
            catch (CryptographicException ex)
            {
                ClearCertificateData();
                StatusMessage = $"Error: Unable to parse certificate. {ex.Message}";
            }
        }

        private (bool HasPrivateKey, bool IsEncrypted, string KeyType) DetectPrivateKeyInPem(string pemContent)
        {
            // Check for various private key PEM headers
            bool hasPrivateKey = pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
                                 pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
                                 pemContent.Contains("-----BEGIN EC PRIVATE KEY-----") ||
                                 pemContent.Contains("-----BEGIN DSA PRIVATE KEY-----") ||
                                 pemContent.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
                                 pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") && pemContent.Contains("Proc-Type: 4,ENCRYPTED");

            bool isEncrypted = pemContent.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
                              pemContent.Contains("Proc-Type: 4,ENCRYPTED");

            string keyType = "Unknown";
            if (pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") || pemContent.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
                keyType = "RSA";
            else if (pemContent.Contains("-----BEGIN EC PRIVATE KEY-----"))
                keyType = "EC";
            else if (pemContent.Contains("-----BEGIN DSA PRIVATE KEY-----"))
                keyType = "DSA";
            else if (pemContent.Contains("-----BEGIN PRIVATE KEY-----"))
                keyType = "PKCS#8";

            return (hasPrivateKey, isEncrypted, keyType);
        }

        private void LoadPemPrivateKey(string filePath, string pemContent, bool isEncrypted)
        {
            string? password = null;

            if (isEncrypted)
            {
                password = PromptForPrivateKeyPassword(filePath);
                if (password == null) // User cancelled
                {
                    ClearCertificateData();
                    StatusMessage = "Private key loading cancelled.";
                    return;
                }
            }

            // Extract the base64 content from the PEM file
            string base64Content = ExtractBase64FromPrivateKey(pemContent);
            if (string.IsNullOrEmpty(base64Content))
            {
                ClearCertificateData();
                StatusMessage = "Error: Unable to extract private key from PEM file.";
                return;
            }

            byte[] keyBytes = Convert.FromBase64String(base64Content);
            string keyType = "Unknown";

            // Try RSA first
            try
            {
                using var rsa = RSA.Create();
                if (password != null)
                {
                    rsa.ImportEncryptedPkcs8PrivateKey(password, keyBytes, out _);
                }
                else
                {
                    // Try different import methods for RSA
                    try
                    {
                        rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                    }
                    catch
                    {
                        rsa.ImportRSAPrivateKey(keyBytes, out _);
                    }
                }
                keyType = "RSA";
                CertificateContent = FormatPkcs8PrivateKeyContent(rsa, keyType, isEncrypted, isPemFormat: true);
                StatusMessage = $"PEM Private Key loaded: {keyType}, {rsa.KeySize} bits";
                PopulatePrivateKeyProperties(rsa, keyType, isEncrypted, isPemFormat: true);
                return;
            }
            catch { }

            // Try ECC/ECDSA
            try
            {
                using var ecdsa = ECDsa.Create();
                if (password != null)
                {
                    ecdsa.ImportEncryptedPkcs8PrivateKey(password, keyBytes, out _);
                }
                else
                {
                    try
                    {
                        ecdsa.ImportPkcs8PrivateKey(keyBytes, out _);
                    }
                    catch
                    {
                        ecdsa.ImportECPrivateKey(keyBytes, out _);
                    }
                }
                keyType = "ECC/ECDSA";
                CertificateContent = FormatPkcs8PrivateKeyContent(ecdsa, keyType, isEncrypted, isPemFormat: true);
                StatusMessage = $"PEM Private Key loaded: {keyType}, {ecdsa.KeySize} bits";
                PopulatePrivateKeyProperties(ecdsa, keyType, isEncrypted, isPemFormat: true);
                return;
            }
            catch { }

            // Try DSA
            try
            {
                using var dsa = DSA.Create();
                if (password != null)
                {
                    dsa.ImportEncryptedPkcs8PrivateKey(password, keyBytes, out _);
                }
                else
                {
                    dsa.ImportPkcs8PrivateKey(keyBytes, out _);
                }
                keyType = "DSA";
                CertificateContent = FormatPkcs8PrivateKeyContent(dsa, keyType, isEncrypted, isPemFormat: true);
                StatusMessage = $"PEM Private Key loaded: {keyType}, {dsa.KeySize} bits";
                PopulatePrivateKeyProperties(dsa, keyType, isEncrypted, isPemFormat: true);
                return;
            }
            catch { }

            ClearCertificateData();
            if (password != null)
            {
                StatusMessage = "Error: Unable to decrypt private key. The password may be incorrect.";
            }
            else
            {
                StatusMessage = "Error: Unable to parse private key file. The file may be corrupted or in an unsupported format.";
            }
        }

        private string ExtractBase64FromPrivateKey(string pemContent)
        {
            // List of possible PEM markers for private keys
            var beginMarkers = new[]
            {
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
                "-----BEGIN DSA PRIVATE KEY-----",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            };

            var endMarkers = new[]
            {
                "-----END PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
                "-----END EC PRIVATE KEY-----",
                "-----END DSA PRIVATE KEY-----",
                "-----END ENCRYPTED PRIVATE KEY-----"
            };

            for (int i = 0; i < beginMarkers.Length; i++)
            {
                int startIndex = pemContent.IndexOf(beginMarkers[i]);
                if (startIndex != -1)
                {
                    startIndex += beginMarkers[i].Length;
                    int endIndex = pemContent.IndexOf(endMarkers[i], startIndex);
                    if (endIndex != -1)
                    {
                        string base64Part = pemContent.Substring(startIndex, endIndex - startIndex);
                        return base64Part.Replace("\r", "").Replace("\n", "").Replace(" ", "");
                    }
                }
            }

            return string.Empty;
        }

        private void LoadPfxCertificate(string filePath)
        {
            string? password = PromptForPassword(filePath);
            byte[] pfxBytes = File.ReadAllBytes(filePath);
            X509Certificate2? certificate = null;
            X509Certificate2Collection? collection = null;

            try
            {
                // Try to load with password (or empty if user cancelled)
                if (password != null)
                {
                    // Try with password
                    try
                    {
                        certificate = new X509Certificate2(pfxBytes, password,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                    }
                    catch (CryptographicException)
                    {
                        // Password might be wrong, try with empty password
                        try
                        {
                            certificate = new X509Certificate2(pfxBytes, string.Empty,
                                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                        }
                        catch
                        {
                            ClearCertificateData();
                            StatusMessage = "Error: Incorrect password or corrupted PFX file.";
                            return;
                        }
                    }
                }
                else
                {
                    // Try without password
                    try
                    {
                        certificate = new X509Certificate2(pfxBytes, string.Empty,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                    }
                    catch (CryptographicException)
                    {
                        ClearCertificateData();
                        StatusMessage = "Error: PFX file requires a password.";
                        return;
                    }
                }

                // Check if this is a certificate collection (multiple certs)
                collection = new X509Certificate2Collection();
                try
                {
                    // Import as collection to get all certificates
                    if (password != null)
                    {
                        collection.Import(pfxBytes, password, X509KeyStorageFlags.Exportable);
                    }
                    else
                    {
                        collection.Import(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
                    }
                }
                catch
                {
                    // If collection import fails, just use the single certificate
                    collection.Add(certificate);
                }

                // Format certificate content for display
                CertificateContent = FormatPfxContent(certificate, collection);

                StatusMessage = collection.Count > 1
                    ? $"PFX loaded: {collection.Count} certificates, Primary: {certificate.Subject}"
                    : $"PFX loaded successfully: {certificate.Subject}";

                // Populate properties
                PopulateProperties(certificate, collection, isPfx: true);
            }
            finally
            {
                // Clean up the private key from the system store
                if (certificate != null && certificate.HasPrivateKey)
                {
                    // Reset the certificate to remove from system store
                    try
                    {
                        var temp = new X509Certificate2(certificate.RawData);
                        certificate.Reset();
                        certificate = temp;
                    }
                    catch { }
                }
            }
        }

        private void LoadPkcs7Certificate(string filePath)
        {
            byte[] pkcs7Bytes = File.ReadAllBytes(filePath);
            var collection = new X509Certificate2Collection();

            try
            {
                // Import PKCS#7 as certificate collection
                collection.Import(pkcs7Bytes, "", X509KeyStorageFlags.Exportable);

                if (collection.Count > 0)
                {
                    // Use first certificate as primary
                    X509Certificate2 primaryCert = collection[0];

                    CertificateContent = FormatPkcs7Content(primaryCert, collection);
                    StatusMessage = $"PKCS#7 loaded: {collection.Count} certificate(s), Primary: {primaryCert.Subject}";

                    PopulateProperties(primaryCert, collection, isPfx: false);
                }
                else
                {
                    ClearCertificateData();
                    StatusMessage = "Error: No certificates found in PKCS#7 file.";
                }
            }
            catch (CryptographicException ex)
            {
                ClearCertificateData();
                StatusMessage = $"Error: Unable to parse PKCS#7 file. {ex.Message}";
            }
        }

        private void LoadPkcs8PrivateKey(string filePath)
        {
            try
            {
                byte[] keyBytes = File.ReadAllBytes(filePath);
                bool isEncrypted = false;

                // First, try to determine if this is encrypted by checking PEM headers
                bool isPemFormat = false;
                string? password = null;

                try
                {
                    string pemContent = File.ReadAllText(filePath);
                    if (pemContent.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
                        pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
                        pemContent.Contains("-----BEGIN EC PRIVATE KEY-----") ||
                        pemContent.Contains("-----BEGIN DSA PRIVATE KEY-----") ||
                        pemContent.Contains("-----BEGIN PRIVATE KEY-----"))
                    {
                        isPemFormat = true;
                        isEncrypted = pemContent.Contains("ENCRYPTED") ||
                                      pemContent.Contains("RSA PRIVATE KEY") && pemContent.Contains("Proc-Type");

                        if (isEncrypted)
                        {
                            password = PromptForPrivateKeyPassword(filePath);
                            if (password == null) // User cancelled
                            {
                                ClearCertificateData();
                                StatusMessage = "PKCS#8 key loading cancelled.";
                                return;
                            }
                        }
                    }
                }
                catch { }

                // If binary, try to detect encrypted format
                if (!isPemFormat)
                {
                    // PKCS#8 encrypted keys start with different ASN.1 sequence
                    // Encrypted: 30 82 ... 06 09 2A 86 48 86 F7 0D 01 07 01 (PBES2 OID)
                    // Unencrypted: 30 82 ... 06 09 2A 86 48 86 F7 0D 01 01 01 (RSA OID) or similar
                    if (keyBytes.Length > 20)
                    {
                        // Look for PBES2 OID: 2.16.840.1.113549.1.9.16.3.18 or similar encryption OID
                        byte[] pbes2Oid = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
                        string hexString = BitConverter.ToString(keyBytes);
                        if (hexString.Contains("2A-86-48-86-F7-0D-01-07-01") || // PBES1
                            hexString.Contains("2A-86-48-86-F7-0D-01-07-02"))   // PBES2
                        {
                            isEncrypted = true;
                        }
                    }

                    if (isEncrypted)
                    {
                        password = PromptForPrivateKeyPassword(filePath);
                        if (password == null) // User cancelled
                        {
                            ClearCertificateData();
                            StatusMessage = "PKCS#8 key loading cancelled.";
                            return;
                        }
                    }
                }

                // Try to import and identify the key type
                string keyType = "Unknown";

                // Try RSA first
                try
                {
                    using var rsa = RSA.Create();
                    if (password != null)
                    {
                        rsa.ImportEncryptedPkcs8PrivateKey(password, keyBytes, out _);
                    }
                    else
                    {
                        rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                    }
                    keyType = "RSA";
                    CertificateContent = FormatPkcs8PrivateKeyContent(rsa, keyType, isEncrypted, isPemFormat);
                    StatusMessage = $"PKCS#8 Private Key loaded: {keyType}, {rsa.KeySize} bits";
                    PopulatePrivateKeyProperties(rsa, keyType, isEncrypted, isPemFormat);
                    return;
                }
                catch { }

                // Try ECC/ECDSA
                try
                {
                    using var ecdsa = ECDsa.Create();
                    if (password != null)
                    {
                        ecdsa.ImportEncryptedPkcs8PrivateKey(password, keyBytes, out _);
                    }
                    else
                    {
                        ecdsa.ImportPkcs8PrivateKey(keyBytes, out _);
                    }
                    keyType = "ECC/ECDSA";
                    CertificateContent = FormatPkcs8PrivateKeyContent(ecdsa, keyType, isEncrypted, isPemFormat);
                    StatusMessage = $"PKCS#8 Private Key loaded: {keyType}, {ecdsa.KeySize} bits";
                    PopulatePrivateKeyProperties(ecdsa, keyType, isEncrypted, isPemFormat);
                    return;
                }
                catch { }

                // Try DSA
                try
                {
                    using var dsa = DSA.Create();
                    if (password != null)
                    {
                        dsa.ImportEncryptedPkcs8PrivateKey(password, keyBytes, out _);
                    }
                    else
                    {
                        dsa.ImportPkcs8PrivateKey(keyBytes, out _);
                    }
                    keyType = "DSA";
                    CertificateContent = FormatPkcs8PrivateKeyContent(dsa, keyType, isEncrypted, isPemFormat);
                    StatusMessage = $"PKCS#8 Private Key loaded: {keyType}, {dsa.KeySize} bits";
                    PopulatePrivateKeyProperties(dsa, keyType, isEncrypted, isPemFormat);
                    return;
                }
                catch { }

                // If we get here, the key couldn't be imported
                ClearCertificateData();
                if (password != null)
                {
                    StatusMessage = "Error: Unable to decrypt PKCS#8 key. The password may be incorrect.";
                }
                else
                {
                    StatusMessage = "Error: Unable to parse PKCS#8 key file. The file may be corrupted or in an unsupported format.";
                }
            }
            catch (CryptographicException ex)
            {
                ClearCertificateData();
                StatusMessage = $"Error: Unable to parse PKCS#8 file. {ex.Message}";
            }
        }

        private void LoadCsr(string filePath)
        {
            try
            {
                byte[] csrBytes = File.ReadAllBytes(filePath);
                string? pemContent = null;

                // Try to read as PEM first
                try
                {
                    string fileContent = File.ReadAllText(filePath);
                    if (fileContent.Contains("-----BEGIN CERTIFICATE REQUEST-----") ||
                        fileContent.Contains("-----BEGIN NEW CERTIFICATE REQUEST-----"))
                    {
                        pemContent = fileContent;
                        csrBytes = Convert.FromBase64String(ExtractBase64FromCsr(fileContent));
                    }
                }
                catch { }

                // Parse CSR (PKCS#10)
                var csrInfo = ParseCsr(csrBytes);

                if (csrInfo != null)
                {
                    CertificateContent = pemContent ?? FormatCsrAsPem(csrBytes);
                    StatusMessage = $"CSR loaded: {csrInfo.Subject}";
                    PopulateCsrProperties(csrInfo);
                }
                else
                {
                    ClearCertificateData();
                    StatusMessage = "Error: Unable to parse CSR file. The file may be corrupted or in an unsupported format.";
                }
            }
            catch (CryptographicException ex)
            {
                ClearCertificateData();
                StatusMessage = $"Error: Unable to parse CSR file. {ex.Message}";
            }
        }

        private string? PromptForPrivateKeyPassword(string filePath)
        {
            // Create a simple password prompt dialog
            var window = new Window
            {
                Title = "Certificate Password",
                Width = 400,
                Height = 180,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Application.Current.MainWindow,
                ResizeMode = ResizeMode.NoResize,
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 30, 30))
            };

            var grid = new System.Windows.Controls.Grid();
            var stackPanel = new System.Windows.Controls.StackPanel
            {
                Margin = new Thickness(20)
            };

            var fileNameLabel = new System.Windows.Controls.TextBlock
            {
                Text = $"Enter password for:{Environment.NewLine}{Path.GetFileName(filePath)}",
                Margin = new Thickness(0, 0, 0, 10),
                FontWeight = FontWeights.SemiBold,
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255))
            };

            var passwordBox = new System.Windows.Controls.PasswordBox
            {
                Margin = new Thickness(0, 0, 0, 15),
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(45, 45, 48)),
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(204, 204, 204)),
                BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(62, 62, 66)),
                BorderThickness = new Thickness(1)
            };

            var buttonPanel = new System.Windows.Controls.StackPanel
            {
                Orientation = System.Windows.Controls.Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var okButton = new System.Windows.Controls.Button
            {
                Content = "OK",
                Width = 80,
                Margin = new Thickness(0, 0, 10, 0),
                IsDefault = true,
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 122, 204)),
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255)),
                BorderThickness = new Thickness(0)
            };

            var cancelButton = new System.Windows.Controls.Button
            {
                Content = "Cancel",
                Width = 80,
                IsCancel = true,
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(62, 62, 66)),
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(204, 204, 204)),
                BorderThickness = new Thickness(0)
            };

            string? password = null;

            okButton.Click += (s, e) =>
            {
                password = passwordBox.Password;
                window.DialogResult = true;
                window.Close();
            };

            cancelButton.Click += (s, e) =>
            {
                window.DialogResult = false;
                window.Close();
            };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);

            stackPanel.Children.Add(fileNameLabel);
            stackPanel.Children.Add(passwordBox);
            stackPanel.Children.Add(buttonPanel);

            grid.Children.Add(stackPanel);
            window.Content = grid;

            if (window.ShowDialog() == true)
            {
                return password;
            }

            // User cancelled - return null to indicate cancellation
            return null;
        }

        private string? PromptForPassword(string filePath)
        {
            // Create a simple password prompt dialog
            var window = new Window
            {
                Title = "Certificate Password",
                Width = 400,
                Height = 180,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Application.Current.MainWindow,
                ResizeMode = ResizeMode.NoResize,
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 30, 30))
            };

            var grid = new System.Windows.Controls.Grid();
            var stackPanel = new System.Windows.Controls.StackPanel
            {
                Margin = new Thickness(20)
            };

            var fileNameLabel = new System.Windows.Controls.TextBlock
            {
                Text = $"Enter password for:{Environment.NewLine}{Path.GetFileName(filePath)}",
                Margin = new Thickness(0, 0, 0, 10),
                FontWeight = FontWeights.SemiBold,
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255))
            };

            var passwordBox = new System.Windows.Controls.PasswordBox
            {
                Margin = new Thickness(0, 0, 0, 15),
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(45, 45, 48)),
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(204, 204, 204)),
                BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(62, 62, 66)),
                BorderThickness = new Thickness(1)
            };

            var buttonPanel = new System.Windows.Controls.StackPanel
            {
                Orientation = System.Windows.Controls.Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var okButton = new System.Windows.Controls.Button
            {
                Content = "OK",
                Width = 80,
                Margin = new Thickness(0, 0, 10, 0),
                IsDefault = true,
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 122, 204)),
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255)),
                BorderThickness = new Thickness(0)
            };

            var cancelButton = new System.Windows.Controls.Button
            {
                Content = "Cancel",
                Width = 80,
                IsCancel = true,
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(62, 62, 66)),
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(204, 204, 204)),
                BorderThickness = new Thickness(0)
            };

            string? password = null;

            okButton.Click += (s, e) =>
            {
                password = passwordBox.Password;
                window.DialogResult = true;
                window.Close();
            };

            cancelButton.Click += (s, e) =>
            {
                window.DialogResult = false;
                window.Close();
            };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);

            stackPanel.Children.Add(fileNameLabel);
            stackPanel.Children.Add(passwordBox);
            stackPanel.Children.Add(buttonPanel);

            grid.Children.Add(stackPanel);
            window.Content = grid;

            if (window.ShowDialog() == true)
            {
                return password;
            }

            // User cancelled - return empty string to try without password
            return string.Empty;
        }

        private string FormatPfxContent(X509Certificate2 primaryCert, X509Certificate2Collection collection)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PFX CERTIFICATE-----");
            sb.AppendLine($"Format: PKCS#12 (.pfx/.p12)");
            sb.AppendLine($"Subject: {primaryCert.Subject}");
            sb.AppendLine($"Issuer: {primaryCert.Issuer}");
            sb.AppendLine($"Contains Private Key: {(primaryCert.HasPrivateKey ? "Yes" : "No")}");
            sb.AppendLine($"Total Certificates in Chain: {collection.Count}");

            if (collection.Count > 1)
            {
                sb.AppendLine();
                sb.AppendLine("Certificate Chain:");
                for (int i = 0; i < collection.Count; i++)
                {
                    var cert = collection[i];
                    sb.AppendLine($"  [{i}] {cert.SubjectName.Name}");
                }
            }

            sb.AppendLine("-----END PFX CERTIFICATE-----");
            return sb.ToString();
        }

        private string FormatPkcs7Content(X509Certificate2 primaryCert, X509Certificate2Collection collection)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PKCS#7 CERTIFICATE-----");
            sb.AppendLine("Format: PKCS#7 / Cryptographic Message Syntax (.p7b/.p7c)");
            sb.AppendLine($"Subject: {primaryCert.Subject}");
            sb.AppendLine($"Issuer: {primaryCert.Issuer}");
            sb.AppendLine($"Total Certificates: {collection.Count}");

            if (collection.Count > 1)
            {
                sb.AppendLine();
                sb.AppendLine("Certificate Chain:");
                for (int i = 0; i < collection.Count; i++)
                {
                    var cert = collection[i];
                    sb.AppendLine($"  [{i}] {cert.SubjectName.Name}");
                }
            }

            sb.AppendLine("-----END PKCS#7 CERTIFICATE-----");
            return sb.ToString();
        }

        private string ExtractBase64FromPem(string pemContent)
        {
            const string beginMarker = "-----BEGIN CERTIFICATE-----";
            const string endMarker = "-----END CERTIFICATE-----";

            int startIndex = pemContent.IndexOf(beginMarker);
            if (startIndex == -1)
                return string.Empty;

            startIndex += beginMarker.Length;
            int endIndex = pemContent.IndexOf(endMarker, startIndex);
            if (endIndex == -1)
                return string.Empty;

            string base64Part = pemContent.Substring(startIndex, endIndex - startIndex);
            return base64Part.Replace("\r", "").Replace("\n", "").Replace(" ", "");
        }

        private List<string> ExtractAllCertsFromPem(string pemContent)
        {
            var certificates = new List<string>();
            const string beginMarker = "-----BEGIN CERTIFICATE-----";
            const string endMarker = "-----END CERTIFICATE-----";

            int startIndex = 0;
            while (true)
            {
                startIndex = pemContent.IndexOf(beginMarker, startIndex);
                if (startIndex == -1)
                    break;

                startIndex += beginMarker.Length;
                int endIndex = pemContent.IndexOf(endMarker, startIndex);
                if (endIndex == -1)
                    break;

                string base64Part = pemContent.Substring(startIndex, endIndex - startIndex);
                string cleanedBase64 = base64Part.Replace("\r", "").Replace("\n", "").Replace(" ", "");
                certificates.Add(cleanedBase64);

                startIndex = endIndex + endMarker.Length;
            }

            return certificates;
        }

        private string FormatDerAsPem(byte[] derBytes)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN CERTIFICATE-----");

            // Convert binary to base64
            string base64 = Convert.ToBase64String(derBytes);

            // Wrap at 64 characters per line (PEM standard)
            for (int i = 0; i < base64.Length; i += 64)
            {
                int length = Math.Min(64, base64.Length - i);
                sb.AppendLine(base64.Substring(i, length));
            }

            sb.AppendLine("-----END CERTIFICATE-----");
            sb.AppendLine();
            sb.AppendLine("(Note: Original file was in DER/binary format, displayed above as PEM)");
            return sb.ToString();
        }

        private string FormatPemChainContent(X509Certificate2Collection collection)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < collection.Count; i++)
            {
                var cert = collection[i];
                byte[] derBytes = cert.RawData;
                string base64 = Convert.ToBase64String(derBytes);

                sb.AppendLine("-----BEGIN CERTIFICATE-----");
                for (int j = 0; j < base64.Length; j += 64)
                {
                    int length = Math.Min(64, base64.Length - j);
                    sb.AppendLine(base64.Substring(j, length));
                }
                sb.AppendLine("-----END CERTIFICATE-----");

                if (i < collection.Count - 1)
                    sb.AppendLine();
            }

            return sb.ToString();
        }

        private string FormatPkcs8PrivateKeyContent(AsymmetricAlgorithm key, string keyType, bool isEncrypted, bool isPemFormat)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PKCS#8 PRIVATE KEY-----");
            sb.AppendLine($"Format: PKCS#8 (.p8)");
            sb.AppendLine($"Key Type: {keyType}");
            sb.AppendLine($"Encrypted: {(isEncrypted ? "Yes" : "No")}");
            sb.AppendLine($"File Format: {(isPemFormat ? "PEM (text)" : "DER (binary)")}");

            int keySize = 0;
            if (key is RSA rsa)
                keySize = rsa.KeySize;
            else if (key is ECDsa ecdsa)
                keySize = ecdsa.KeySize;
            else if (key is DSA dsa)
                keySize = dsa.KeySize;

            if (keySize > 0)
                sb.AppendLine($"Key Size: {keySize} bits");

            sb.AppendLine("-----END PKCS#8 PRIVATE KEY-----");
            return sb.ToString();
        }

        private string FormatCsrAsPem(byte[] csrBytes)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");

            string base64 = Convert.ToBase64String(csrBytes);
            for (int i = 0; i < base64.Length; i += 64)
            {
                int length = Math.Min(64, base64.Length - i);
                sb.AppendLine(base64.Substring(i, length));
            }

            sb.AppendLine("-----END CERTIFICATE REQUEST-----");
            return sb.ToString();
        }

        private string ExtractBase64FromCsr(string pemContent)
        {
            const string beginMarker1 = "-----BEGIN CERTIFICATE REQUEST-----";
            const string beginMarker2 = "-----BEGIN NEW CERTIFICATE REQUEST-----";
            const string endMarker = "-----END CERTIFICATE REQUEST-----";

            int startIndex = pemContent.IndexOf(beginMarker1);
            if (startIndex == -1)
                startIndex = pemContent.IndexOf(beginMarker2);

            if (startIndex == -1)
                return string.Empty;

            startIndex += pemContent.IndexOf(beginMarker1) != -1 ? beginMarker1.Length : beginMarker2.Length;
            int endIndex = pemContent.IndexOf(endMarker, startIndex);
            if (endIndex == -1)
                return string.Empty;

            string base64Part = pemContent.Substring(startIndex, endIndex - startIndex);
            return base64Part.Replace("\r", "").Replace("\n", "").Replace(" ", "");
        }

        private CsrInfo? ParseCsr(byte[] csrBytes)
        {
            try
            {
                var info = new CsrInfo();

                // Parse ASN.1 structure of CSR (PKCS#10)
                // CSR structure: SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature }
                int pos = 0;

                // Skip outer sequence tag
                if (csrBytes[0] != 0x30) return null;
                pos = SkipLength(csrBytes, 1);

                // Parse CertificationRequestInfo (SEQUENCE)
                if (csrBytes[pos] != 0x30) return null;
                pos = SkipLength(csrBytes, pos + 1);

                // Version (INTEGER)
                if (csrBytes[pos] == 0x02)
                {
                    pos = SkipLength(csrBytes, pos + 1);
                    pos++; // Skip version value
                }

                // Subject (SEQUENCE of RDNs)
                if (csrBytes[pos] != 0x30) return null;
                int subjectSeqLen = GetLength(csrBytes, pos + 1, out int subjectLenBytes);
                pos = SkipLength(csrBytes, pos);

                // Extract subject bytes
                byte[] subjectBytes = new byte[subjectSeqLen];
                Array.Copy(csrBytes, pos, subjectBytes, 0, subjectSeqLen);
                info.Subject = ParseDistinguishedName(subjectBytes);
                pos += subjectSeqLen;

                // SubjectPublicKeyInfo (SEQUENCE)
                if (csrBytes[pos] != 0x30) return null;
                int pkSeqLen = GetLength(csrBytes, pos + 1, out int pkLenBytes);
                pos = SkipLength(csrBytes, pos);

                // Parse algorithm OID
                if (csrBytes[pos + 1] == 0x06)
                {
                    int oidLen = csrBytes[pos + 2];
                    byte[] oidBytes = new byte[oidLen];
                    Array.Copy(csrBytes, pos + 3, oidBytes, 0, oidLen);
                    string oid = DecodeOid(oidBytes);
                    info.PublicKeyAlgorithm = GetKeyAlgorithmName(oid);
                }

                // Try to get public key info
                info.PublicKeyInfo = $"Algorithm: {info.PublicKeyAlgorithm}";

                // Look for attributes (Extensions) - optional
                // [0] IMPLICIT Attributes
                pos += pkSeqLen;
                if (pos < csrBytes.Length && csrBytes[pos] == 0xA0)
                {
                    pos = SkipLength(csrBytes, pos);

                    // Parse extensions if present
                    while (pos < csrBytes.Length - 20)
                    {
                        if (csrBytes[pos] == 0x30) // SEQUENCE (attribute)
                        {
                            pos = SkipLength(csrBytes, pos);

                            if (csrBytes[pos] == 0x06) // OID
                            {
                                int oidLen = csrBytes[pos + 1];
                                byte[] oidBytes = new byte[oidLen];
                                Array.Copy(csrBytes, pos + 2, oidBytes, 0, oidLen);
                                string oid = DecodeOid(oidBytes);

                                // Check for extension request (1.2.840.113549.1.9.14)
                                if (oid == "1.2.840.113549.1.9.14" || oid == "2.5.29.17")
                                {
                                    pos += 2 + oidLen;

                                    if (csrBytes[pos] == 0x31) // SET
                                    {
                                        pos = SkipLength(csrBytes, pos);
                                        if (csrBytes[pos] == 0x04) // OCTET STRING
                                        {
                                            pos = SkipLength(csrBytes, pos);
                                            if (csrBytes[pos] == 0x30) // SEQUENCE of extensions
                                            {
                                                pos = SkipLength(csrBytes, pos);
                                                info.Extensions = ParseExtensions(csrBytes, ref pos);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    pos += 2 + oidLen;
                                }
                            }
                            else
                            {
                                pos++;
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                // Parse signature algorithm
                while (pos < csrBytes.Length - 10 && csrBytes[pos] != 0x30)
                    pos++;

                if (pos < csrBytes.Length - 10 && csrBytes[pos] == 0x30)
                {
                    pos = SkipLength(csrBytes, pos);
                    if (csrBytes[pos] == 0x06) // OID
                    {
                        int oidLen = csrBytes[pos + 1];
                        byte[] oidBytes = new byte[oidLen];
                        Array.Copy(csrBytes, pos + 2, oidBytes, 0, oidLen);
                        string oid = DecodeOid(oidBytes);
                        info.SignatureAlgorithm = GetSignatureAlgorithmName(oid);
                    }
                }

                info.Signature = "(Signature not displayed for security)";
                info.IsValid = true;

                return info;
            }
            catch
            {
                return null;
            }
        }

        private List<CsrExtension> ParseExtensions(byte[] data, ref int pos)
        {
            var extensions = new List<CsrExtension>();

            while (pos < data.Length - 10)
            {
                if (data[pos] != 0x30) break; // Not a SEQUENCE

                int seqLen = GetLength(data, pos + 1, out int lenBytes);
                pos += 1 + lenBytes;

                int extStartPos = pos;

                // Parse extension: SEQUENCE { OID, critical[BOOLEAN], value }
                if (data[pos] == 0x06) // OID
                {
                    int oidLen = data[pos + 1];
                    byte[] oidBytes = new byte[oidLen];
                    Array.Copy(data, pos + 2, oidBytes, 0, oidLen);
                    string oid = DecodeOid(oidBytes);
                    pos += 2 + oidLen;

                    bool critical = false;
                    if (pos < data.Length && data[pos] == 0x01) // BOOLEAN (critical)
                    {
                        pos += 2; // Skip tag and length (always 1)
                        critical = data[pos] != 0x00;
                        pos++;
                    }

                    if (pos < data.Length && data[pos] == 0x04) // OCTET STRING (value)
                    {
                        int valueLen = GetLength(data, pos + 1, out int valueLenBytes);
                        pos += 1 + valueLenBytes;

                        byte[] valueBytes = new byte[valueLen];
                        Array.Copy(data, pos, valueBytes, 0, valueLen);

                        var ext = new CsrExtension
                        {
                            Oid = oid,
                            FriendlyName = GetExtensionFriendlyName(oid),
                            Critical = critical,
                            Value = FormatExtensionValue(oid, valueBytes)
                        };

                        extensions.Add(ext);
                        pos += valueLen;
                    }
                }

                if (pos >= extStartPos + seqLen) break;
            }

            return extensions;
        }

        private string ParseDistinguishedName(byte[] dnBytes)
        {
            try
            {
                var parts = new List<string>();
                int pos = 0;

                while (pos < dnBytes.Length - 4)
                {
                    // Each RDN is a SET containing one or more SEQUENCEs
                    if (dnBytes[pos] == 0x31) // SET
                    {
                        pos = SkipLength(dnBytes, pos);

                        if (dnBytes[pos] == 0x30) // SEQUENCE
                        {
                            int seqStart = pos;
                            pos = SkipLength(dnBytes, pos);

                            if (dnBytes[pos] == 0x06) // OID
                            {
                                int oidLen = dnBytes[pos + 1];
                                byte[] oidBytes = new byte[oidLen];
                                Array.Copy(dnBytes, pos + 2, oidBytes, 0, oidLen);
                                string oid = DecodeOid(oidBytes);
                                string attrName = GetDnAttributeName(oid);
                                pos += 2 + oidLen;

                                // Get value (could be various types)
                                if (pos < dnBytes.Length)
                                {
                                    byte tag = dnBytes[pos];
                                    int valueLen = GetLength(dnBytes, pos + 1, out int valueLenBytes);
                                    pos += 1 + valueLenBytes;

                                    string value = string.Empty;
                                    if (tag == 0x13 || tag == 0x14) // PrintableString or T61String
                                    {
                                        value = Encoding.ASCII.GetString(dnBytes, pos, valueLen);
                                    }
                                    else if (tag == 0x0C) // UTF8String
                                    {
                                        value = Encoding.UTF8.GetString(dnBytes, pos, valueLen);
                                    }
                                    else if (tag == 0x16) // IA5String
                                    {
                                        value = Encoding.ASCII.GetString(dnBytes, pos, valueLen);
                                    }

                                    if (!string.IsNullOrEmpty(value))
                                    {
                                        parts.Add($"{attrName}={value}");
                                    }

                                    pos += valueLen;
                                }
                            }
                        }
                    }
                    else
                    {
                        pos++;
                    }
                }

                return parts.Count > 0 ? string.Join(", ", parts) : "Unable to parse";
            }
            catch
            {
                return "Parse error";
            }
        }

        private string GetDnAttributeName(string oid)
        {
            return oid switch
            {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.8" => "ST",
                "2.5.4.7" => "L",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.12" => "T",
                "2.5.4.42" => "GN",
                "2.5.4.43" => "I",
                "2.5.4.4" => "SN",
                "1.2.840.113549.1.9.1" => "E",
                "0.9.2342.19200300.100.1.1" => "UID",
                "2.5.4.46" => "DNQ",
                "2.5.4.44" => "GenerationQualifier",
                "2.5.4.5" => "SerialNumber",
                _ => oid
            };
        }

        private string GetKeyAlgorithmName(string oid)
        {
            return oid switch
            {
                "1.2.840.113549.1.1.1" => "RSA",
                "1.2.840.10045.2.1" => "ECC/ECDSA",
                "1.2.840.10040.4.1" => "DSA",
                "1.3.101.112" => "Ed25519",
                "1.3.101.113" => "Ed448",
                _ => $"Unknown ({oid})"
            };
        }

        private string GetSignatureAlgorithmName(string oid)
        {
            return oid switch
            {
                "1.2.840.113549.1.1.1" => "sha1WithRSA",
                "1.2.840.113549.1.1.5" => "sha1WithRSA",
                "1.2.840.113549.1.1.11" => "sha256WithRSA",
                "1.2.840.113549.1.1.12" => "sha384WithRSA",
                "1.2.840.113549.1.1.13" => "sha512WithRSA",
                "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
                "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
                "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
                "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
                "1.3.14.3.2.29" => "sha1WithRSA",
                "2.16.840.1.101.3.4.3.1" => "dsa-with-sha256",
                _ => $"Unknown ({oid})"
            };
        }

        private string GetExtensionFriendlyName(string oid)
        {
            return oid switch
            {
                "2.5.29.17" => "Subject Alternative Name",
                "2.5.29.15" => "Key Usage",
                "2.5.29.37" => "Extended Key Usage",
                "2.5.29.19" => "Basic Constraints",
                "2.5.29.14" => "Subject Key Identifier",
                "2.5.29.35" => "Authority Key Identifier",
                "2.5.29.32" => "Certificate Policies",
                "1.3.6.1.5.5.7.1.1" => "Authority Information Access",
                "2.5.29.31" => "CRL Distribution Points",
                _ => oid
            };
        }

        private string FormatExtensionValue(string oid, byte[] valueBytes)
        {
            try
            {
                // For SAN, try to extract names
                if (oid == "2.5.29.17")
                {
                    var names = new List<string>();
                    int pos = 2; // Skip OCTET STRING header if present

                    while (pos < valueBytes.Length - 2)
                    {
                        byte tag = valueBytes[pos];
                        int len = valueBytes[pos + 1];

                        if (tag == 0x82 && pos + 2 + len <= valueBytes.Length) // DNS name
                        {
                            string dns = Encoding.ASCII.GetString(valueBytes, pos + 2, len);
                            names.Add($"DNS:{dns}");
                        }
                        else if (tag == 0x87 && pos + 2 + len <= valueBytes.Length) // IP address
                        {
                            if (len == 4)
                                names.Add($"IP:{valueBytes[pos + 2]}.{valueBytes[pos + 3]}.{valueBytes[pos + 4]}.{valueBytes[pos + 5]}");
                        }

                        pos += 2 + len;
                        if (len > 127) pos++; // Handle long form length
                    }

                    return names.Count > 0 ? string.Join(", ", names) : FormatRawValue(valueBytes);
                }

                return FormatRawValue(valueBytes);
            }
            catch
            {
                return FormatRawValue(valueBytes);
            }
        }

        private string FormatRawValue(byte[] valueBytes)
        {
            int maxLen = Math.Min(50, valueBytes.Length);
            string hex = BitConverter.ToString(valueBytes, 0, maxLen).Replace("-", " ");
            return valueBytes.Length > 50 ? hex + "..." : hex;
        }

        private int SkipLength(byte[] data, int pos)
        {
            if (pos >= data.Length) return pos;

            byte lenByte = data[pos];
            if ((lenByte & 0x80) == 0)
            {
                return pos + 1;
            }
            else
            {
                int numBytes = lenByte & 0x7F;
                return pos + 1 + numBytes;
            }
        }

        private int GetLength(byte[] data, int pos, out int lengthBytes)
        {
            lengthBytes = 1;
            if (pos >= data.Length) return 0;

            byte lenByte = data[pos];
            if ((lenByte & 0x80) == 0)
            {
                return lenByte;
            }
            else
            {
                int numBytes = lenByte & 0x7F;
                lengthBytes = 1 + numBytes;

                int length = 0;
                for (int i = 1; i <= numBytes && pos + i < data.Length; i++)
                {
                    length = (length << 8) | data[pos + i];
                }
                return length;
            }
        }

        private void PopulatePrivateKeyProperties(AsymmetricAlgorithm key, string keyType, bool isEncrypted, bool isPemFormat)
        {
            Properties.Clear();

            AddHeader("PKCS#8 PRIVATE KEY INFORMATION");
            AddProperty("File Format", "PKCS#8 (.p8)");
            AddProperty("Key Type", keyType);
            AddProperty("Encrypted", isEncrypted ? "Yes" : "No");
            AddProperty("File Encoding", isPemFormat ? "PEM (text)" : "DER (binary)");

            int keySize = 0;
            if (key is RSA rsa)
            {
                keySize = rsa.KeySize;
                AddProperty("Key Size", $"{keySize} bits");

                try
                {
                    var parameters = rsa.ExportParameters(false);
                    if (parameters.Exponent != null && parameters.Exponent.Length > 0)
                    {
                        uint exponent = parameters.Exponent[0];
                        for (int i = 1; i < parameters.Exponent.Length; i++)
                        {
                            exponent = (exponent << 8) + parameters.Exponent[i];
                        }
                        AddProperty("Public Exponent", $"0x{exponent:X} ({exponent})");
                    }
                }
                catch { }
            }
            else if (key is ECDsa ecdsa)
            {
                keySize = ecdsa.KeySize;
                AddProperty("Key Size", $"{keySize} bits");

                try
                {
                    var parameters = ecdsa.ExportParameters(false);
                    if (!string.IsNullOrEmpty(ecdsa.KeyExchangeAlgorithm))
                    {
                        AddProperty("Curve", ecdsa.KeyExchangeAlgorithm);
                    }
                }
                catch { }
            }
            else if (key is DSA dsa)
            {
                keySize = dsa.KeySize;
                AddProperty("Key Size", $"{keySize} bits");
            }
        }

        private void PopulateCsrProperties(CsrInfo csrInfo)
        {
            Properties.Clear();

            AddHeader("CSR (PKCS#10) INFORMATION");
            AddProperty("File Format", "Certificate Signing Request (.p10/.csr)");
            AddProperty("Subject", csrInfo.Subject);
            AddProperty("Signature Algorithm", csrInfo.SignatureAlgorithm);
            AddProperty("Public Key", csrInfo.PublicKeyInfo);

            if (csrInfo.Extensions.Count > 0)
            {
                AddHeader("");
                AddHeader("REQUESTED EXTENSIONS");

                foreach (var ext in csrInfo.Extensions)
                {
                    string critical = ext.Critical ? "Critical" : "Non-critical";
                    AddProperty($"{ext.FriendlyName}", $"{critical}, OID: {ext.Oid}");
                    AddProperty("  Value", ext.Value);
                }
            }

            AddHeader("");
            AddHeader("SIGNATURE");
            AddProperty("Status", csrInfo.IsValid ? "Valid CSR structure" : "Invalid CSR structure");
        }

        private class CsrInfo
        {
            public string Subject { get; set; } = string.Empty;
            public string PublicKeyAlgorithm { get; set; } = "Unknown";
            public string PublicKeyInfo { get; set; } = string.Empty;
            public string SignatureAlgorithm { get; set; } = "Unknown";
            public string Signature { get; set; } = string.Empty;
            public List<CsrExtension> Extensions { get; set; } = new List<CsrExtension>();
            public bool IsValid { get; set; }
        }

        private class CsrExtension
        {
            public string Oid { get; set; } = string.Empty;
            public string FriendlyName { get; set; } = string.Empty;
            public bool Critical { get; set; }
            public string Value { get; set; } = string.Empty;
        }

        private void PopulateProperties(X509Certificate2 certificate, bool isPfx = false)
        {
            PopulateProperties(certificate, null, isPfx);
        }

        private void PopulateProperties(X509Certificate2 certificate, X509Certificate2Collection? collection, bool isPfx)
        {
            Properties.Clear();

            // PFX/PKCS#12 Information
            if (isPfx)
            {
                AddHeader("PFX / PKCS#12 INFORMATION");
                AddProperty("File Format", "PKCS#12 (.pfx/.p12)");
                AddProperty("Has Private Key", certificate.HasPrivateKey ? "Yes" : "No");

                if (certificate.HasPrivateKey)
                {
                    AddPrivateKeyDetails(certificate);
                }

                if (collection != null && collection.Count > 1)
                {
                    AddProperty("Certificates in Chain", collection.Count.ToString());
                    AddProperty("", "");

                    for (int i = 0; i < collection.Count; i++)
                    {
                        var cert = collection[i];
                        string role = i == 0 ? "End Entity" : $"Chain Certificate #{i}";
                        AddProperty($"  [{i}] {role}", $"{cert.SubjectName.Name}");
                        AddProperty($"     Thumbprint", FormatThumbprint(cert.Thumbprint));
                        if (i < collection.Count - 1)
                            AddProperty("", "");
                    }
                }

                AddHeader("");
            }

            // PKCS#7 / Certificate Chain Information (for multi-cert non-PFX files)
            if (!isPfx && collection != null && collection.Count > 1)
            {
                AddHeader("PKCS#7 / CERTIFICATE CHAIN INFORMATION");
                AddProperty("File Format", "Multi-Certificate File");
                AddProperty("Total Certificates", collection.Count.ToString());
                AddProperty("", "");

                for (int i = 0; i < collection.Count; i++)
                {
                    var cert = collection[i];
                    string role = i == 0 ? "End Entity" : $"Chain Certificate #{i}";
                    AddProperty($"  [{i}] {role}", $"{cert.SubjectName.Name}");
                    AddProperty($"     Thumbprint", FormatThumbprint(cert.Thumbprint));
                    if (i < collection.Count - 1)
                        AddProperty("", "");
                }

                AddHeader("");
            }

            // Basic Information
            AddHeader("BASIC INFORMATION");
            AddProperty("Version", $"V{certificate.Version}");
            AddProperty("Serial Number", FormatSerialNumber(certificate.SerialNumber));
            AddProperty("Serial Number (hex)", $"0x{certificate.SerialNumber}");
            AddProperty("Signature Algorithm", certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "Unknown");

            // Validity
            AddHeader("VALIDITY");
            AddProperty("Valid From", certificate.NotBefore.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") + $" ({certificate.NotBefore:MMM dd HH:mm:ss yyyy GMT})");
            AddProperty("Valid To", certificate.NotAfter.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") + $" ({certificate.NotAfter:MMM dd HH:mm:ss yyyy GMT})");

            // Calculate days until expiry
            TimeSpan timeUntilExpiry = certificate.NotAfter - DateTime.Now;
            int daysUntilExpiry = (int)timeUntilExpiry.TotalDays;
            if (daysUntilExpiry < 0)
                AddProperty("Days Until Expiry", $"EXPIRED ({Math.Abs(daysUntilExpiry)} days ago)");
            else if (daysUntilExpiry == 0)
                AddProperty("Days Until Expiry", "Expires today!");
            else if (daysUntilExpiry == 1)
                AddProperty("Days Until Expiry", "1 day");
            else
                AddProperty("Days Until Expiry", $"{daysUntilExpiry:N0} days");

            // Check if expired
            bool isExpired = DateTime.Now > certificate.NotAfter;
            bool isNotYetValid = DateTime.Now < certificate.NotBefore;
            if (isExpired)
                AddProperty("Status", "EXPIRED");
            else if (isNotYetValid)
                AddProperty("Status", "NOT YET VALID");
            else
                AddProperty("Status", "Valid");

            // Subject
            AddHeader("SUBJECT");
            AddProperty("Subject DN", certificate.Subject ?? "N/A");
            AddDistinguishedNameProperties("Subject", certificate.SubjectName);

            // Issuer
            AddHeader("ISSUER");
            AddProperty("Issuer DN", certificate.Issuer ?? "N/A");
            AddDistinguishedNameProperties("Issuer", certificate.IssuerName);

            // Check if self-signed
            bool isSelfSigned = certificate.Subject == certificate.Issuer;
            if (isSelfSigned)
                AddProperty("Self-Signed", "Yes (Subject equals Issuer)");
            else
                AddProperty("Self-Signed", "No");

            // Public Key
            AddHeader("PUBLIC KEY INFORMATION");
            AddProperty("Algorithm", certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "Unknown");
            AddPublicKeyDetails(certificate);

            // Thumbprint
            AddHeader("FINGERPRINTS");
            AddProperty("SHA-256 Thumbprint", FormatThumbprint(certificate.Thumbprint));

            // Calculate and add SHA-1 thumbprint
            string sha1Thumbprint = GetSha1Thumbprint(certificate);
            AddProperty("SHA-1 Thumbprint", sha1Thumbprint);

            // Extensions
            AddHeader("EXTENSIONS");
            AddParsedExtensions(certificate);
        }

        private void AddPrivateKeyDetails(X509Certificate2 certificate)
        {
            try
            {
                // Try to get more details about the private key
                var rsa = certificate.GetRSAPrivateKey();
                if (rsa != null)
                {
                    AddProperty("Private Key Type", "RSA");
                    AddProperty("  Key Size", $"{rsa.KeySize} bits");
                    rsa.Dispose();
                }
                else
                {
                    var ecdsa = certificate.GetECDsaPrivateKey();
                    if (ecdsa != null)
                    {
                        AddProperty("Private Key Type", "ECDsa");
                        AddProperty("  Key Size", $"{ecdsa.KeySize} bits");
                        ecdsa.Dispose();
                    }
                    else
                    {
                        var dsa = certificate.GetDSAPrivateKey();
                        if (dsa != null)
                        {
                            AddProperty("Private Key Type", "DSA");
                            AddProperty("  Key Size", $"{dsa.KeySize} bits");
                            dsa.Dispose();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AddProperty("Private Key Info", $"Unable to retrieve details: {ex.Message}");
            }
        }

        private void AddDistinguishedNameProperties(string prefix, X500DistinguishedName dn)
        {
            try
            {
                // Parse the DN using the decoded name
                byte[] decoded = dn.RawData;
                string dnString = dn.Name ?? string.Empty;

                // Parse common attributes manually from the raw format
                // The format is typically: CN=Common Name, O=Organization, OU=Org Unit, C=Country, etc.
                var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string[] parts = dnString.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string part in parts)
                {
                    string[] keyValue = part.Split(new[] { '=' }, 2);
                    if (keyValue.Length == 2)
                    {
                        string key = keyValue[0].Trim();
                        string value = keyValue[1].Trim();
                        if (!attributes.ContainsKey(key))
                        {
                            attributes[key] = value;
                        }
                    }
                }

                // Add common attributes if present
                if (attributes.TryGetValue("CN", out string? cn))
                    AddProperty($"  Common Name (CN)", cn);
                if (attributes.TryGetValue("O", out string? o))
                    AddProperty($"  Organization (O)", o);
                if (attributes.TryGetValue("OU", out string? ou))
                    AddProperty($"  Organizational Unit (OU)", ou);
                if (attributes.TryGetValue("C", out string? c))
                    AddProperty($"  Country (C)", c);
                if (attributes.TryGetValue("ST", out string? st))
                    AddProperty($"  State/Province (ST)", st);
                if (attributes.TryGetValue("L", out string? l))
                    AddProperty($"  Locality (L)", l);
                if (attributes.TryGetValue("E", out string? e) || attributes.TryGetValue("EMAILADDRESS", out e))
                    AddProperty($"  Email (E)", e);
                if (attributes.TryGetValue("DC", out string? dc))
                    AddProperty($"  Domain Component (DC)", dc);
                if (attributes.TryGetValue("CN", out string? cn2) && !string.IsNullOrWhiteSpace(cn2))
                {
                    // Try to extract domain from CN for certs
                    if (cn2.Contains('.') && !cn2.StartsWith('*'))
                        AddProperty($"  Domain", cn2);
                }
            }
            catch (Exception)
            {
                // If parsing fails, skip the detailed DN breakdown
            }
        }

        private void AddPublicKeyDetails(X509Certificate2 certificate)
        {
            try
            {
                var rsa = certificate.GetRSAPublicKey();
                if (rsa != null)
                {
                    AddProperty("Key Size", $"{rsa.KeySize} bits");
                    AddProperty("Key Type", "RSA");

                    // Try to get RSA parameters
                    try
                    {
                        var parameters = rsa.ExportParameters(false);
                        if (parameters.Modulus != null)
                        {
                            string modulusHex = BitConverter.ToString(parameters.Modulus).Replace("-", ":");
                            AddProperty("  Modulus (first 40 bytes)", TruncateString(modulusHex, 120) + "...");
                        }
                        if (parameters.Exponent != null && parameters.Exponent.Length > 0)
                        {
                            uint exponent = parameters.Exponent[0];
                            for (int i = 1; i < parameters.Exponent.Length; i++)
                            {
                                exponent = (exponent << 8) + parameters.Exponent[i];
                            }
                            AddProperty("  Exponent", $"0x{exponent:X} ({exponent})");
                        }
                    }
                    catch
                    {
                        AddProperty("  Note", "RSA parameters not exportable (key may be in HSM)");
                    }

                    rsa.Dispose();
                    return;
                }
            }
            catch { }

            try
            {
                var ecdsa = certificate.GetECDsaPublicKey();
                if (ecdsa != null)
                {
                    AddProperty("Key Size", $"{ecdsa.KeySize} bits");
                    AddProperty("Key Type", "ECC/ECDSA");

                    // Get curve name
                    try
                    {
                        var parameters = ecdsa.ExportParameters(false);
                        if (!string.IsNullOrEmpty(ecdsa.KeyExchangeAlgorithm))
                        {
                            AddProperty("  Curve", ecdsa.KeyExchangeAlgorithm);
                        }
                    }
                    catch
                    {
                        AddProperty("  Note", "Curve information not available");
                    }

                    ecdsa.Dispose();
                    return;
                }
            }
            catch { }

            try
            {
                var dsa = certificate.GetDSAPublicKey();
                if (dsa != null)
                {
                    AddProperty("Key Size", $"{dsa.KeySize} bits");
                    AddProperty("Key Type", "DSA");
                    dsa.Dispose();
                    return;
                }
            }
            catch { }

            AddProperty("Key Size", "N/A (Unknown key type)");
        }

        private void AddParsedExtensions(X509Certificate2 certificate)
        {
            // Group extensions by category for better organization
            AddProperty("Extension Count", certificate.Extensions.Count.ToString());

#pragma warning disable CS8602
            foreach (X509Extension extension in certificate.Extensions)
            {
                string oid = extension.Oid.Value ?? "Unknown";
                string friendlyName = extension.Oid.FriendlyName ?? oid;
                bool critical = extension.Critical;

                try
                {
                    switch (oid)
                    {
                        case "2.5.29.9": // Subject Directory Attributes
                            AddProperty(friendlyName, $"{(critical ? "Critical" : "Non-critical")} - Not parsed");
                            break;

                        case "2.5.29.14": // Subject Key Identifier
                            AddSubjectKeyIdentifier(extension, critical);
                            break;

                        case "2.5.29.15": // Key Usage
                            AddKeyUsage(extension, critical);
                            break;

                        case "2.5.29.17": // Subject Alternative Name
                            AddSubjectAlternativeName(extension, critical);
                            break;

                        case "2.5.29.19": // Basic Constraints
                            AddBasicConstraints(extension, critical);
                            break;

                        case "2.5.29.31": // CRL Distribution Points
                            AddCRLDistributionPoints(extension, critical);
                            break;

                        case "2.5.29.35": // Authority Key Identifier
                            AddAuthorityKeyIdentifier(extension, critical);
                            break;

                        case "2.5.29.37": // Extended Key Usage
                            AddExtendedKeyUsage(extension, critical);
                            break;

                        case "2.5.29.32": // Certificate Policies
                            AddCertificatePolicies(extension, critical);
                            break;

                        case "1.3.6.1.5.5.7.1.1": // Authority Information Access
                            AddAuthorityInfoAccess(extension, critical);
                            break;

                        case "1.3.6.1.5.5.7.1.3": // CRL Distribution Points (another OID)
                            AddCRLDistributionPoints(extension, critical);
                            break;

                        case "2.5.29.18": // Issuer Alternative Name
                            AddIssuerAlternativeName(extension, critical);
                            break;

                        case "2.5.29.30": // Name Constraints
                            AddNameConstraints(extension, critical);
                            break;

                        case "2.5.29.36": // Policy Constraints
                            AddPolicyConstraints(extension, critical);
                            break;

                        case "2.5.29.46": // Freshest CRL
                            AddProperty(friendlyName, $"{(critical ? "Critical" : "Non-critical")} - Not parsed");
                            break;

                        case "2.5.29.54": // Inhibit anyPolicy
                            AddInhibitAnyPolicy(extension, critical);
                            break;

                        case "1.3.6.1.4.1.311.21.10": // Application Policies (Microsoft specific)
                            AddApplicationPolicies(extension, critical);
                            break;

                        default:
                            // Generic extension display
                            string rawValue = FormatRawExtensionData(extension.RawData);
                            AddProperty($"{friendlyName}", $"{(critical ? "Critical" : "Non-critical")}{Environment.NewLine}  OID: {oid}{Environment.NewLine}  Value: {rawValue}");
                            break;
                    }
                }
                catch (Exception)
                {
                    AddProperty($"{friendlyName}", $"{(critical ? "Critical" : "Non-critical")} - Parsing failed");
                }
            }
#pragma warning restore CS8602
        }

        private void AddSubjectKeyIdentifier(X509Extension extension, bool critical)
        {
            try
            {
                if (extension.RawData.Length > 4)
                {
                    // Skip header bytes and get the key identifier
                    byte[] ski = new byte[extension.RawData.Length - 4];
                    Array.Copy(extension.RawData, 4, ski, 0, ski.Length);
                    string skiHex = BitConverter.ToString(ski).Replace("-", ":");
                    AddProperty("Subject Key Identifier", $"{(critical ? "Critical" : "Non-critical")}{Environment.NewLine}  Key ID: {skiHex}");
                }
                else
                {
                    AddProperty("Subject Key Identifier", $"{(critical ? "Critical" : "Non-critical")} - Invalid format");
                }
            }
            catch
            {
                AddProperty("Subject Key Identifier", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddAuthorityKeyIdentifier(X509Extension extension, bool critical)
        {
            try
            {
                // Parse ASN.1 structure for Authority Key Identifier
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                if (extension.RawData.Length > 4)
                {
                    // The AKI contains [Key Identifier][Issuer][Serial Number]
                    // Try to extract key identifier (first octet string after sequence header)
                    byte[] data = extension.RawData;
                    int pos = 2; // Skip sequence tag and length

                    // Look for key identifier (tag 0x80)
                    if (pos < data.Length && data[pos] == 0x80)
                    {
                        pos++; // Skip tag
                        int len = data[pos++]; // Get length
                        if (pos + len <= data.Length)
                        {
                            byte[] keyId = new byte[len];
                            Array.Copy(data, pos, keyId, 0, len);
                            string keyIdHex = BitConverter.ToString(keyId).Replace("-", ":");
                            sb.AppendLine();
                            sb.Append($"  Key ID: {keyIdHex}");
                            pos += len;
                        }
                    }

                    // Look for serial number (tag 0x82)
                    if (pos < data.Length && data[pos] == 0x82)
                    {
                        pos++; // Skip tag
                        int len = data[pos++]; // Get length
                        if (pos + len <= data.Length && len <= 20) // Serial numbers are small
                        {
                            byte[] serial = new byte[len];
                            Array.Copy(data, pos, serial, 0, len);
                            string serialHex = BitConverter.ToString(serial).Replace("-", ":");
                            sb.AppendLine();
                            sb.Append($"  Serial Number: {serialHex}");
                        }
                    }
                }

                AddProperty("Authority Key Identifier", sb.ToString());
            }
            catch
            {
                AddProperty("Authority Key Identifier", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddKeyUsage(X509Extension extension, bool critical)
        {
            try
            {
                // Key Usage is a bit string
                // Format: SEQUENCE { BIT STRING ... }
                StringBuilder usages = new StringBuilder();
                usages.Append(critical ? "Critical" : "Non-critical");

                if (extension.RawData.Length >= 4)
                {
                    // The bit string starts after the sequence header
                    // Format: 30 03 03 01 XX
                    if (extension.RawData.Length >= 4 && extension.RawData[2] == 0x03) // BIT STRING tag
                    {
                        byte flags = extension.RawData[extension.RawData.Length - 1];

                        var usageNames = new List<string>();

                        // X509KeyUsageFlags enum values
                        if ((flags & 0x80) != 0) usageNames.Add("Decipher Only");
                        if ((flags & 0x40) != 0) usageNames.Add("Encipher Only");
                        if ((flags & 0x20) != 0) usageNames.Add("CRL Sign");
                        if ((flags & 0x10) != 0) usageNames.Add("Key Cert Sign");
                        if ((flags & 0x08) != 0) usageNames.Add("Key Agreement");
                        if ((flags & 0x04) != 0) usageNames.Add("Data Encipherment");
                        if ((flags & 0x02) != 0) usageNames.Add("Key Encipherment");
                        if ((flags & 0x01) != 0) usageNames.Add("Digital Signature");

                        if (usageNames.Count > 0)
                        {
                            usages.AppendLine();
                            usages.Append($"  {string.Join(", ", usageNames)}");
                        }
                    }
                }

                AddProperty("Key Usage", usages.ToString());
            }
            catch
            {
                AddProperty("Key Usage", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddExtendedKeyUsage(X509Extension extension, bool critical)
        {
            try
            {
                // Extended Key Usage contains a list of OIDs
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Parse the raw ASN.1 data
                // Format: SEQUENCE { OID1, OID2, ... }
                int pos = 2; // Skip SEQUENCE tag and length

                var ekuOids = new Dictionary<string, string>
                {
                    { "1.3.6.1.5.5.7.3.1", "Server Authentication" },
                    { "1.3.6.1.5.5.7.3.2", "Client Authentication" },
                    { "1.3.6.1.5.5.7.3.3", "Code Signing" },
                    { "1.3.6.1.5.5.7.3.4", "Email Protection" },
                    { "1.3.6.1.5.5.7.3.8", "Time Stamping" },
                    { "1.3.6.1.5.5.7.3.9", "OCSP Signing" },
                    { "1.3.6.1.4.1.311.10.3.3", "Microsoft Server Gated Crypto" },
                    { "1.3.6.1.4.1.311.10.3.4", "Microsoft SGC Netscape" },
                    { "1.3.6.1.5.5.7.3.5", "IPSec End System" },
                    { "1.3.6.1.5.5.7.3.6", "IPSec Tunnel" },
                    { "1.3.6.1.5.5.7.3.7", "IPSec User" },
                    { "1.3.6.1.5.2.3.5", "Kerberos Authentication" },
                };

                while (pos < extension.RawData.Length - 1)
                {
                    if (extension.RawData[pos] == 0x06) // OID tag
                    {
                        int len = extension.RawData[pos + 1];
                        if (pos + 2 + len <= extension.RawData.Length)
                        {
                            byte[] oidBytes = new byte[len];
                            Array.Copy(extension.RawData, pos + 2, oidBytes, 0, len);

                            // Convert OID bytes to string
                            string oidValue = DecodeOid(oidBytes);
                            string friendlyName = ekuOids.TryGetValue(oidValue, out string? name) ? name : oidValue;

                            sb.AppendLine();
                            sb.Append($"  {friendlyName} ({oidValue})");

                            pos += 2 + len;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        pos++;
                    }
                }

                AddProperty("Extended Key Usage", sb.ToString());
            }
            catch
            {
                AddProperty("Extended Key Usage", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddBasicConstraints(X509Extension extension, bool critical)
        {
            try
            {
                // Basic Constraints: SEQUENCE { BOOLEAN [CA], INTEGER [pathlen] (optional) }
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                int pos = 2; // Skip SEQUENCE tag and length

                if (pos < extension.RawData.Length)
                {
                    // Check for CA flag (BOOLEAN)
                    if (extension.RawData[pos] == 0x01)
                    {
                        pos++; // Skip BOOLEAN tag
                        int len = extension.RawData[pos++]; // Get length (should be 1)
                        bool isCA = len > 0 && extension.RawData[pos] != 0x00;
                        sb.AppendLine();
                        sb.Append($"  CA: {(isCA ? "TRUE" : "FALSE")}");
                        pos += len;
                    }

                    // Check for pathLenConstraint (INTEGER)
                    if (pos < extension.RawData.Length && extension.RawData[pos] == 0x02)
                    {
                        pos++; // Skip INTEGER tag
                        int len = extension.RawData[pos++]; // Get length
                        if (pos + len <= extension.RawData.Length && len <= 4)
                        {
                            int pathLen = 0;
                            for (int i = 0; i < len; i++)
                            {
                                pathLen = (pathLen << 8) | extension.RawData[pos++];
                            }
                            sb.AppendLine();
                            sb.Append($"  Path Length: {pathLen}");
                        }
                    }
                }

                AddProperty("Basic Constraints", sb.ToString());
            }
            catch
            {
                AddProperty("Basic Constraints", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddSubjectAlternativeName(X509Extension extension, bool critical)
        {
            try
            {
                // Subject Alternative Name contains GeneralNames
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Parse ASN.1 structure
                // SEQUENCE OF GeneralName
                int pos = 2; // Skip SEQUENCE tag and length

                var dnsNames = new List<string>();
                var ipAddresses = new List<string>();
                var emailAddresses = new List<string>();
                var otherNames = new List<string>();

                while (pos < extension.RawData.Length - 1)
                {
                    byte tag = extension.RawData[pos];

                    // GeneralName tags:
                    // 0x82 = DNS name
                    // 0x87 = IP address
                    // 0x81 = RFC 822 name (email)
                    // 0x84 = Directory name
                    // 0x80 = Other name

                    if (tag == 0x82) // DNS name
                    {
                        pos++; // Skip tag
                        int len = extension.RawData[pos++]; // Get length
                        if (pos + len <= extension.RawData.Length)
                        {
                            string dns = Encoding.ASCII.GetString(extension.RawData, pos, len);
                            dnsNames.Add(dns);
                            pos += len;
                        }
                    }
                    else if (tag == 0x87) // IP address
                    {
                        pos++; // Skip tag
                        int len = extension.RawData[pos++]; // Get length
                        if (pos + len <= extension.RawData.Length)
                        {
                            if (len == 4) // IPv4
                            {
                                string ip = $"{extension.RawData[pos]}.{extension.RawData[pos + 1]}.{extension.RawData[pos + 2]}.{extension.RawData[pos + 3]}";
                                ipAddresses.Add(ip);
                            }
                            else if (len == 16) // IPv6
                            {
                                var ipv6Bytes = new byte[16];
                                Array.Copy(extension.RawData, pos, ipv6Bytes, 0, 16);
                                string ip = FormatIPv6Address(ipv6Bytes);
                                ipAddresses.Add(ip);
                            }
                            pos += len;
                        }
                    }
                    else if (tag == 0x81) // Email address (RFC 822)
                    {
                        pos++; // Skip tag
                        int len = extension.RawData[pos++]; // Get length
                        if (pos + len <= extension.RawData.Length)
                        {
                            string email = Encoding.ASCII.GetString(extension.RawData, pos, len);
                            emailAddresses.Add(email);
                            pos += len;
                        }
                    }
                    else
                    {
                        // Skip other tag types
                        pos++; // Skip tag
                        if (pos < extension.RawData.Length)
                        {
                            int len = extension.RawData[pos++]; // Get length
                            pos += len;
                        }
                    }
                }

                if (dnsNames.Count > 0)
                {
                    sb.AppendLine();
                    sb.Append("  DNS Names:");
                    foreach (string dns in dnsNames)
                        sb.AppendLine().Append($"    {dns}");
                }

                if (ipAddresses.Count > 0)
                {
                    sb.AppendLine();
                    sb.Append("  IP Addresses:");
                    foreach (string ip in ipAddresses)
                        sb.AppendLine().Append($"    {ip}");
                }

                if (emailAddresses.Count > 0)
                {
                    sb.AppendLine();
                    sb.Append("  Email Addresses:");
                    foreach (string email in emailAddresses)
                        sb.AppendLine().Append($"    {email}");
                }

                AddProperty("Subject Alternative Name", sb.ToString());
            }
            catch
            {
                AddProperty("Subject Alternative Name", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddIssuerAlternativeName(X509Extension extension, bool critical)
        {
            try
            {
                // Similar parsing to SAN
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");
                sb.AppendLine();
                sb.Append("  (See Subject Alternative Name parsing)");

                AddProperty("Issuer Alternative Name", sb.ToString());
            }
            catch
            {
                AddProperty("Issuer Alternative Name", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddCRLDistributionPoints(X509Extension extension, bool critical)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Try to extract HTTP/HTTPS URLs from the raw data
                string rawData = Encoding.ASCII.GetString(extension.RawData);
                var urls = new List<string>();

                // Look for http:// and https:// URLs
                int searchPos = 0;
                while (true)
                {
                    int httpIndex = rawData.IndexOf("http://", searchPos);
                    int httpsIndex = rawData.IndexOf("https://", searchPos);

                    if (httpIndex == -1 && httpsIndex == -1)
                        break;

                    int urlIndex = (httpIndex != -1 && (httpsIndex == -1 || httpIndex < httpsIndex))
                        ? httpIndex : httpsIndex;

                    // Find end of URL (look for delimiter or end of URL-like content)
                    int urlEnd = rawData.IndexOfAny(new[] { '\0', (char)0x82, (char)0x86 }, urlIndex);
                    if (urlEnd == -1)
                        urlEnd = rawData.Length;

                    string url = rawData.Substring(urlIndex, urlEnd - urlIndex).Trim();
                    if (!string.IsNullOrWhiteSpace(url) && !urls.Contains(url))
                    {
                        urls.Add(url);
                    }

                    searchPos = urlEnd + 1;
                }

                if (urls.Count > 0)
                {
                    sb.AppendLine();
                    sb.Append("  CRL Distribution Points:");
                    foreach (string url in urls)
                        sb.AppendLine().Append($"    {url}");
                }
                else
                {
                    sb.AppendLine();
                    sb.Append("  (Unable to parse URLs)");
                }

                AddProperty("CRL Distribution Points", sb.ToString());
            }
            catch
            {
                AddProperty("CRL Distribution Points", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddAuthorityInfoAccess(X509Extension extension, bool critical)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Parse AIA which contains access locations
                // OCSP (1.3.6.1.5.5.7.48.1) and CA Issuers (1.3.6.1.5.5.7.48.2)

                string rawData = Encoding.ASCII.GetString(extension.RawData);
                var ocspUrls = new List<string>();
                var issuerUrls = new List<string>();

                // Simple URL extraction
                int searchPos = 0;
                while (true)
                {
                    int httpIndex = rawData.IndexOf("http://", searchPos);
                    int httpsIndex = rawData.IndexOf("https://", searchPos);

                    if (httpIndex == -1 && httpsIndex == -1)
                        break;

                    int urlIndex = (httpIndex != -1 && (httpsIndex == -1 || httpIndex < httpsIndex))
                        ? httpIndex : httpsIndex;

                    int urlEnd = rawData.IndexOfAny(new[] { '\0', (char)0x82, (char)0x86 }, urlIndex);
                    if (urlEnd == -1)
                        urlEnd = rawData.Length;

                    string url = rawData.Substring(urlIndex, urlEnd - urlIndex).Trim();

                    // Try to determine type based on position or just add to both
                    searchPos = urlEnd + 1;

                    if (!string.IsNullOrWhiteSpace(url))
                    {
                        // For simplicity, just add to OCSP if we can't determine
                        if (rawData.Substring(0, urlIndex).Contains("1.3.6.1.5.5.7.48.1") ||
                            rawData.Substring(0, urlIndex).Contains("06 09 60 86 48 01 86 F8 42 01 01"))
                        {
                            if (!ocspUrls.Contains(url))
                                ocspUrls.Add(url);
                        }
                        else if (rawData.Substring(0, urlIndex).Contains("1.3.6.1.5.5.7.48.2") ||
                                 rawData.Substring(0, urlIndex).Contains("06 09 60 86 48 01 86 F8 42 01 02"))
                        {
                            if (!issuerUrls.Contains(url))
                                issuerUrls.Add(url);
                        }
                        else
                        {
                            if (!ocspUrls.Contains(url))
                                ocspUrls.Add(url);
                        }
                    }
                }

                if (ocspUrls.Count > 0)
                {
                    sb.AppendLine();
                    sb.Append("  OCSP URLs:");
                    foreach (string url in ocspUrls)
                        sb.AppendLine().Append($"    {url}");
                }

                if (issuerUrls.Count > 0)
                {
                    sb.AppendLine();
                    sb.Append("  CA Issuer URLs:");
                    foreach (string url in issuerUrls)
                        sb.AppendLine().Append($"    {url}");
                }

                if (ocspUrls.Count == 0 && issuerUrls.Count == 0)
                {
                    sb.AppendLine();
                    sb.Append("  (Unable to parse URLs)");
                }

                AddProperty("Authority Information Access", sb.ToString());
            }
            catch
            {
                AddProperty("Authority Information Access", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddCertificatePolicies(X509Extension extension, bool critical)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Parse policy OIDs
                int pos = 2; // Skip SEQUENCE tag and length

                var knownPolicies = new Dictionary<string, string>
                {
                    { "2.5.29.32.0", "Any Policy" },
                    { "1.3.6.1.4.1.311.21.10", "Microsoft Commercial Code Signing" },
                    { "1.3.6.1.4.1.311.21.11", "Microsoft Kernel Code Signing" },
                };

                int policyCount = 0;
                while (pos < extension.RawData.Length - 1)
                {
                    if (extension.RawData[pos] == 0x30) // SEQUENCE (policy)
                    {
                        pos++; // Skip SEQUENCE tag
                        int seqLen = extension.RawData[pos++]; // Get length
                        int endPos = pos + seqLen;

                        if (pos < endPos && extension.RawData[pos] == 0x06) // OID tag
                        {
                            pos++; // Skip OID tag
                            int oidLen = extension.RawData[pos++]; // Get length
                            if (pos + oidLen <= endPos)
                            {
                                byte[] oidBytes = new byte[oidLen];
                                Array.Copy(extension.RawData, pos, oidBytes, 0, oidLen);
                                string oidValue = DecodeOid(oidBytes);
                                string friendlyName = knownPolicies.TryGetValue(oidValue, out string? name) ? name : oidValue;

                                if (policyCount > 0)
                                    sb.AppendLine();
                                sb.Append($"  {friendlyName} ({oidValue})");

                                policyCount++;
                                pos += oidLen;
                            }
                        }

                        pos = endPos;
                    }
                    else
                    {
                        pos++;
                    }
                }

                if (policyCount == 0)
                {
                    sb.AppendLine();
                    sb.Append("  (Unable to parse policies)");
                }

                AddProperty("Certificate Policies", sb.ToString());
            }
            catch
            {
                AddProperty("Certificate Policies", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddApplicationPolicies(X509Extension extension, bool critical)
        {
            try
            {
                // Microsoft Application Policies - similar to Extended Key Usage
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Similar parsing to EKU
                int pos = 2; // Skip SEQUENCE tag and length

                var appPolicyOids = new Dictionary<string, string>
                {
                    { "1.3.6.1.4.1.311.21.10", "Microsoft Commercial Code Signing" },
                    { "1.3.6.1.4.1.311.21.11", "Microsoft Kernel Code Signing" },
                };

                while (pos < extension.RawData.Length - 1)
                {
                    if (extension.RawData[pos] == 0x06) // OID tag
                    {
                        int len = extension.RawData[pos + 1];
                        if (pos + 2 + len <= extension.RawData.Length)
                        {
                            byte[] oidBytes = new byte[len];
                            Array.Copy(extension.RawData, pos + 2, oidBytes, 0, len);
                            string oidValue = DecodeOid(oidBytes);
                            string friendlyName = appPolicyOids.TryGetValue(oidValue, out string? name) ? name : oidValue;

                            sb.AppendLine();
                            sb.Append($"  {friendlyName} ({oidValue})");

                            pos += 2 + len;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        pos++;
                    }
                }

                AddProperty("Application Policies", sb.ToString());
            }
            catch
            {
                AddProperty("Application Policies", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddNameConstraints(X509Extension extension, bool critical)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");
                sb.AppendLine();
                sb.Append("  (Complex structure - raw data shown)");
                sb.AppendLine();
                sb.Append($"  {FormatRawExtensionData(extension.RawData)}");

                AddProperty("Name Constraints", sb.ToString());
            }
            catch
            {
                AddProperty("Name Constraints", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddPolicyConstraints(X509Extension extension, bool critical)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Parse: SEQUENCE { INTEGER [requireExplicitPolicy] (optional), INTEGER [inhibitPolicyMapping] (optional) }
                int pos = 2; // Skip SEQUENCE tag and length

                while (pos < extension.RawData.Length - 1)
                {
                    if (extension.RawData[pos] == 0x02) // INTEGER tag
                    {
                        pos++; // Skip INTEGER tag
                        int len = extension.RawData[pos++]; // Get length
                        if (pos + len <= extension.RawData.Length && len <= 4)
                        {
                            int value = 0;
                            for (int i = 0; i < len; i++)
                            {
                                value = (value << 8) | extension.RawData[pos++];
                            }

                            // Heuristic: first integer is usually requireExplicitPolicy, second is inhibitPolicyMapping
                            if (sb.ToString().Contains("Require Explicit"))
                            {
                                sb.AppendLine();
                                sb.Append($"  Inhibit Policy Mapping: {value}");
                            }
                            else
                            {
                                sb.AppendLine();
                                sb.Append($"  Require Explicit Policy: {value}");
                            }
                        }
                    }
                    else
                    {
                        pos++;
                    }
                }

                AddProperty("Policy Constraints", sb.ToString());
            }
            catch
            {
                AddProperty("Policy Constraints", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private void AddInhibitAnyPolicy(X509Extension extension, bool critical)
        {
            try
            {
                // Inhibit anyPolicy contains a single INTEGER
                StringBuilder sb = new StringBuilder();
                sb.Append(critical ? "Critical" : "Non-critical");

                // Find the INTEGER value
                for (int i = 2; i < extension.RawData.Length - 1; i++)
                {
                    if (extension.RawData[i] == 0x02) // INTEGER tag
                    {
                        int len = extension.RawData[i + 1];
                        if (i + 2 + len <= extension.RawData.Length && len <= 4)
                        {
                            int value = 0;
                            for (int j = 0; j < len; j++)
                            {
                                value = (value << 8) | extension.RawData[i + 2 + j];
                            }
                            sb.AppendLine();
                            sb.Append($"  Skip Certificates: {value}");
                            break;
                        }
                    }
                }

                AddProperty("Inhibit Any Policy", sb.ToString());
            }
            catch
            {
                AddProperty("Inhibit Any Policy", $"{(critical ? "Critical" : "Non-critical")} - Parse error");
            }
        }

        private string DecodeOid(byte[] oidBytes)
        {
            try
            {
                // Decode BER-encoded OID
                if (oidBytes.Length == 0)
                    return "";

                StringBuilder sb = new StringBuilder();

                // First byte is special: (first arc * 40) + second arc
                int firstByte = oidBytes[0];
                int firstArc = firstByte / 40;
                int secondArc = firstByte % 40;
                sb.Append($"{firstArc}.{secondArc}");

                // Remaining bytes
                int value = 0;
                for (int i = 1; i < oidBytes.Length; i++)
                {
                    byte b = oidBytes[i];
                    if ((b & 0x80) == 0)
                    {
                        // Last byte of this value
                        value = (value << 7) | b;
                        sb.Append($".{value}");
                        value = 0;
                    }
                    else
                    {
                        // More bytes to come
                        value = (value << 7) | (b & 0x7F);
                    }
                }

                return sb.ToString();
            }
            catch
            {
                return BitConverter.ToString(oidBytes).Replace("-", " ");
            }
        }

        private string FormatRawExtensionData(byte[] data)
        {
            try
            {
                // Show hex representation of raw extension data
                string hex = BitConverter.ToString(data).Replace("-", " ");
                return hex.Length > 100 ? hex.Substring(0, 100) + "..." : hex;
            }
            catch
            {
                return "(Unable to format)";
            }
        }

        private string FormatIPv6Address(byte[] bytes)
        {
            try
            {
                // Format IPv6 address
                var groups = new ushort[8];
                for (int i = 0; i < 8; i++)
                {
                    groups[i] = (ushort)((bytes[i * 2] << 8) | bytes[i * 2 + 1]);
                }

                // Simple IPv6 formatting (could be improved with :: compression)
                return string.Join(":", groups.Select(g => g.ToString("x")));
            }
            catch
            {
                return "(Invalid IPv6)";
            }
        }

        private string TruncateString(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
                return value;
            return value.Substring(0, maxLength);
        }

        private void AddHeader(string header)
        {
            AddProperty("", "");
            AddProperty(header, "");
        }

        private void AddProperty(string name, string value)
        {
            Properties.Add(new CertificateProperty { Name = name, Value = value });
        }

        private void ClearCertificateData()
        {
            CertificateContent = string.Empty;
            Properties.Clear();
        }

        private string FormatSerialNumber(string serialNumber)
        {
            if (string.IsNullOrEmpty(serialNumber))
                return "N/A";

            var sb = new StringBuilder();
            for (int i = 0; i < serialNumber.Length; i += 2)
            {
                if (sb.Length > 0)
                    sb.Append(":");
                sb.Append(serialNumber.Substring(i, 2));
            }
            return sb.ToString();
        }

        private string FormatThumbprint(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
                return "N/A";

            var sb = new StringBuilder();
            for (int i = 0; i < thumbprint.Length; i += 2)
            {
                if (sb.Length > 0)
                    sb.Append(":");
                sb.Append(thumbprint.Substring(i, 2));
            }
            return sb.ToString();
        }

        private string GetSha1Thumbprint(X509Certificate2 certificate)
        {
            try
            {
                using var sha1 = System.Security.Cryptography.SHA1.Create();
                byte[] hash = sha1.ComputeHash(certificate.RawData);
                return BitConverter.ToString(hash).Replace("-", ":");
            }
            catch
            {
                return "N/A";
            }
        }

        private void CopyCertificateContent()
        {
            if (!string.IsNullOrEmpty(CertificateContent))
            {
                Clipboard.SetText(CertificateContent);
                StatusMessage = "Certificate content copied to clipboard.";
            }
        }

        private void ExportToFile()
        {
            try
            {
                var saveFileDialog = new SaveFileDialog
                {
                    Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                    Title = "Export Certificate Details",
                    DefaultExt = "txt",
                    FileName = $"certificate_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    var content = FormatPropertiesForExport();
                    File.WriteAllText(saveFileDialog.FileName, content, Encoding.UTF8);
                    StatusMessage = $"Certificate details exported to: {Path.GetFileName(saveFileDialog.FileName)}";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error exporting to file: {ex.Message}";
            }
        }

        private string FormatPropertiesForExport()
        {
            var sb = new StringBuilder();
            var now = DateTime.Now;
            const string line = "--------------------------------------------------------------------------------";
            const string doubleLine = "================================================================================";

            // Header
            sb.AppendLine(doubleLine);
            sb.AppendLine("CERTIFICATE DETAILS REPORT");
            sb.AppendLine(doubleLine);
            sb.AppendLine($"Generated: {now:yyyy-MM-dd HH:mm:ss} ({now:zzz})");
            sb.AppendLine();

            // Certificate Content (PEM)
            sb.AppendLine(line);
            sb.AppendLine("CERTIFICATE CONTENT");
            sb.AppendLine(line);
            sb.AppendLine(CertificateContent);
            sb.AppendLine();

            // Properties
            sb.AppendLine(line);
            sb.AppendLine("CERTIFICATE PROPERTIES");
            sb.AppendLine(line);
            sb.AppendLine();

            foreach (var prop in Properties)
            {
                // Section headers
                if (string.IsNullOrEmpty(prop.Name) && string.IsNullOrEmpty(prop.Value))
                {
                    sb.AppendLine();
                    continue;
                }

                // Section title (all caps in Name, empty Value)
                if (!string.IsNullOrEmpty(prop.Name) && prop.Value == string.Empty)
                {
                    sb.AppendLine();
                    sb.AppendLine($"[ {prop.Name} ]");
                    sb.AppendLine(line);
                    continue;
                }

                // Property name and value
                if (!string.IsNullOrEmpty(prop.Name))
                {
                    // Format indented multi-line values
                    if (prop.Value.Contains('\n'))
                    {
                        sb.AppendLine($"{prop.Name}:");
                        var lines = prop.Value.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var lineItem in lines)
                        {
                            if (!string.IsNullOrWhiteSpace(lineItem))
                                sb.AppendLine($"    {lineItem}");
                        }
                    }
                    else
                    {
                        sb.AppendLine($"{prop.Name}: {prop.Value}");
                    }
                }
                else if (!string.IsNullOrEmpty(prop.Value))
                {
                    // Value only (continuation)
                    sb.AppendLine($"    {prop.Value}");
                }
            }

            // Footer
            sb.AppendLine();
            sb.AppendLine(doubleLine);
            sb.AppendLine("END OF REPORT");
            sb.AppendLine(doubleLine);

            return sb.ToString();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
