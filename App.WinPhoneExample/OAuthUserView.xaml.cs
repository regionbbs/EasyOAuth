using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using EasyOAuth.Core.Portable;

namespace App.WinPhoneExample
{
    public partial class OAuthUserView : PhoneApplicationPage
    {
        public OAuthUserView()
        {
            InitializeComponent();
            this.OAuthUserViewUI.Navigated += (s, e) =>
                {
                    if (e.Uri.Query[0] == '?')
                        App.FacebookOAuthProvider.AccessToken(e.Uri.Query.Substring(1));
                    else
                        App.FacebookOAuthProvider.AccessToken(e.Uri.Query);

                    NavigationService.GoBack();
                };
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            string url = null, redirectUri = null, scope = null;

            NavigationContext.QueryString.TryGetValue("url", out url);
            NavigationContext.QueryString.TryGetValue("redirect_uri", out redirectUri);
            NavigationContext.QueryString.TryGetValue("scope", out scope);

            this.OAuthUserViewUI.Navigate(
                new Uri(url + "&redirect_uri=" + redirectUri + "&scope=" + scope));
        }
        
        private void cmdCancel_Click(object sender, RoutedEventArgs e)
        {
            this.NavigationService.GoBack();
        }
    }
}