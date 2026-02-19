# 🔐 CertDecipher

A modern, dark-themed X.509 certificate viewer for Windows that provides detailed information about certificates, private keys, and certificate signing requests (CSRs).
<img width="886" height="643" alt="image" src="https://github.com/user-attachments/assets/01d24e4f-d40f-49dd-8588-b564569c0d62" />
 </br>
_sample_

![Version](https://img.shields.io/badge/version-1.0.1-blue)
![.NET](https://img.shields.io/badge/.NET-8.0-purple)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

## ✨ Features

### 📁 Supported File Formats

| Format | Extensions | Description |
|--------|-----------|-------------|
| **Certificates** | `.pem`, `.cer`, `.crt`, `.der` | X.509 certificates in PEM or DER encoding |
| **PKCS#12/PFX** | `.pfx`, `.p12` | Personal Information Exchange files with private keys |
| **PKCS#7** | `.p7b`, `.p7c` | Cryptographic Message Syntax certificate chains |
| **PKCS#8** | `.p8` | Private key files (encrypted or unencrypted) |
| **CSR** | `.p10`, `.csr` | Certificate Signing Requests |
| **PEM Keys** | `.pem` | Private keys in PEM format (RSA, EC, DSA) |

### 📋 Certificate Information Displayed

#### Basic Information
- Certificate version
- Serial number (hex and decimal)
- Signature algorithm
- **SHA-256 and SHA-1 thumbprints** 🔑
- **Self-signed detection** ✅
- **Days until expiry** ⏰

#### Validity Period ⏱️
- Valid from / Valid to dates (local and GMT)
- **Days until expiry** with smart formatting:
  - `365 days` - normal countdown
  - `1 day` - expires tomorrow
  - `Expires today!` - expires today ⚠️
  - `EXPIRED (X days ago)` - already expired ❌
- Status indicator (Valid / Not Yet Valid / Expired)

#### Subject & Issuer Details 👤
- Full Distinguished Name (DN)
- Common Name (CN)
- Organization (O)
- Organizational Unit (OU)
- Country/Region (C)
- State/Province (ST)
- Locality (L)
- Email (E)
- Domain Component (DC)

#### Public Key Information 🔐
- Algorithm (RSA, ECC/ECDSA, DSA)
- Key size
- RSA: Modulus (first 40 bytes), Exponent
- ECC: Curve information

#### Extensions (parsed) 📝
- Subject Key Identifier
- Authority Key Identifier
- Key Usage
- Extended Key Usage
- Subject Alternative Name (SAN) - DNS, IP, Email
- Basic Constraints (CA flag, path length)
- CRL Distribution Points
- Authority Information Access (OCSP, CA Issuers)
- Certificate Policies
- And more...

### 🚀 Special Features

#### 🔗 Chain Support
- **PKCS#7 chains** - View all certificates in .p7b/.p7c files
- **PFX chains** - View all certificates in PKCS#12 files
- **PEM chains** - View all certificates in multi-certificate PEM files
- Chain display shows role (End Entity / Chain Certificate) and thumbprint for each

#### 🔑 Private Key Inspection
- View PKCS#8 and PEM private key files
- Detect key type (RSA, ECC/ECDSA, DSA)
- Display key size and parameters
- **Password-protected keys** - prompts for password when needed 🔒
- Shows encryption status

#### 📝 CSR Inspection
- View Certificate Signing Requests before issuance
- Shows requested Subject DN
- Displays requested public key algorithm
- Lists requested extensions (SAN, Key Usage, etc.)
- Shows signature algorithm

#### 🔐 Password Protection
- Prompts for password on encrypted files
- Supports password-protected PFX/PKCS#12 files
- Supports encrypted PKCS#8 private keys
- Supports encrypted PEM private keys
- **Clears data on password failure** - no confusion when wrong password is entered ✨

## 🚀 Getting Started

### 📦 Prerequisites

- Windows 10 or later
- [.NET 8.0 Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) (or SDK for development)

### 🔨 Building from Source

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/CertDecipher.git
   cd CertDecipher
   ```

2. **Build the project**
   ```bash
   dotnet build
   ```

3. **Run the application**
   ```bash
   dotnet run
   ```

### 💾 Using the Pre-built Executable

1. Download the latest release from the [Releases](https://github.com/yourusername/CertDecipher/releases) page
2. Extract the ZIP file
3. Run `CertDecipher.exe`

## 📖 Usage

### 👁️ Viewing a Certificate

1. Click **Select Certificate File**
2. Browse to your certificate file
3. View the certificate content and properties

### 📋 Copying Certificate Content

1. Load a certificate
2. Click the **Copy** button to copy the PEM content to clipboard

### 💾 Exporting Certificate Details

1. Load a certificate
2. Click the **Export to File** button
3. Choose a location to save the detailed report

### 🔑 Opening Password-Protected Files

1. Select a password-protected PFX or PKCS#8 file
2. Enter the password when prompted
3. View the certificate/key details

## 📂 Project Structure

```
CertDecipher/
├── Models/
│   └── CertificateProperty.cs      # Model for certificate properties
├── ViewModels/
│   ├── MainViewModel.cs            # Main view model with all logic
│   └── RelayCommand.cs             # Command implementation for MVVM
├── App.xaml                         # Application definition
├── App.xaml.cs                      # Application code-behind
├── MainWindow.xaml                  # Main window UI definition
├── MainWindow.xaml.cs               # Main window code-behind
├── CertDecipher.csproj              # Project file
├── certs.ico                        # Application icon
└── README.md                        # This file
```

### 🏗️ Architecture

CertDecipher follows the **Model-View-ViewModel (MVVM)** pattern:

- **Model**: `CertificateProperty` represents a single name-value property pair
- **View**: `MainWindow.xaml` defines the UI layout and styling
- **ViewModel**: `MainViewModel.cs` contains all business logic:
  - File loading and parsing
  - Certificate/Key/CSR inspection
  - Property extraction and formatting
  - Extension parsing
  - ASN.1 decoding for CSRs

## 📚 Dependencies

- **.NET 8.0 Windows** - Target framework
- **WPF** - UI framework
- **System.Security.Cryptography** - Certificate and cryptographic operations
- **Microsoft.Win32** - File dialogs

No external NuGet packages required! ✨

## 👨‍💻 Development

### ➕ Adding New Features

The codebase is organized to make it easy to extend:

1. **Add new file format support** - Add a new `LoadXxxFile()` method in `MainViewModel.cs`
2. **Parse new extensions** - Add a new `AddXxxExtension()` method in `PopulateProperties()`
3. **Add new properties** - Simply call `AddProperty()` in the appropriate section

### 🎨 Code Style

- C# conventions
- XML comments for public methods
- Clear method names describing their purpose
- Comprehensive error handling with user-friendly messages

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- Built with WPF and .NET 8.0
- Dark theme inspired by Visual Studio Code
- ASN.1 parsing based on PKCS#10 / RFC 2986
- Certificate handling via .NET's `X509Certificate2` class

## 📜 Changelog

### Version 1.0.1 (Current)
- ✅ Added PKCS#7 (.p7b/.p7c) certificate chain support
- ✅ Added PKCS#8 (.p8) private key support
- ✅ Added Certificate Signing Request (.p10/.csr) support
- ✅ Added PEM private key detection and loading
- ✅ Added SHA-1 thumbprint alongside SHA-256
- ✅ Added days until expiry countdown
- ✅ Added self-signed certificate detection
- ✅ Improved error handling - clears data on load failure
- ✅ Multi-certificate PEM chain support

### Version 1.0.0
- 🎉 Initial release
- Basic certificate viewing (PEM, DER, PFX)
- Certificate chain display for PFX files
- Extension parsing
- Copy and export functionality
- Dark theme UI

---

**Made with ❤️ using WPF & C#**
