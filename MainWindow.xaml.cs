using System.Windows;
using CertDecipher.ViewModels;

namespace CertDecipher
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel();
        }
    }
}
