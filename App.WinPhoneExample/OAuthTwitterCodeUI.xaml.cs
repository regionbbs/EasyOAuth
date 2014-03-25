using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;

namespace App.WinPhoneExample
{
    public partial class OAuthTwitterCodeUI : PhoneApplicationPage
    {
        public OAuthTwitterCodeUI()
        {
            InitializeComponent();
        }

        private void cmdCancel_Click(object sender, RoutedEventArgs e)
        {

        }

        private void cmdOK_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(this.txtCode.Text))
            {
                MessageBox.Show("Please provide authentication code shown on screen.");
                return;
            }
        }
    }
}