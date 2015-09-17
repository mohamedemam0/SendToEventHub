using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Devices.Geolocation;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.Web.Http;


namespace SendToEventHub
{
    public sealed partial class MainPage : Page
    {
        const string sbNamespace = "https://iacaddemo.servicebus.windows.net/";
        const string keyName = "Send";
        const string keyValue = "+k5+YyNNhlYWxW3mwuY7ANMO4inkwo07ECB3JB03si8=";
        const string entity = "iacaddemo";

        private Geolocator _geolocator = null;
        double longitude;
        double lattitude;

        public MainPage()
        {
            this.InitializeComponent();
            _geolocator = new Geolocator();
            GetLocation();
        }

        private string GetSASToken(string baseAddress, string SASKeyName, string SASKeyValue)
        {
            TimeSpan fromEpochStart = DateTime.UtcNow - new DateTime(1970, 1, 1);
            string expiry = Convert.ToString((int)fromEpochStart.TotalSeconds + 3600);
            string stringToSign = WebUtility.UrlEncode(baseAddress) + "\n" + expiry;
            string hmac = GetSHA256Key(SASKeyValue, stringToSign);
            string hash = HmacSha256(SASKeyValue, stringToSign);
            string sasToken = String.Format(CultureInfo.InvariantCulture, "sr={0}&sig={1}&se={2}&skn={3}",
                WebUtility.UrlEncode(baseAddress), WebUtility.UrlEncode(hash), expiry, SASKeyName);
            return sasToken;
        }
        public string GetSHA256Key(string hashKey, string stringToSign)
        {
            MacAlgorithmProvider macAlgorithmProvider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA256");
            BinaryStringEncoding encoding = BinaryStringEncoding.Utf8;
            var messageBuffer = CryptographicBuffer.ConvertStringToBinary(stringToSign, encoding);
            IBuffer keyBuffer = CryptographicBuffer.ConvertStringToBinary(hashKey, encoding);
            CryptographicKey hmacKey = macAlgorithmProvider.CreateKey(keyBuffer);
            IBuffer signedMessage = CryptographicEngine.Sign(hmacKey, messageBuffer);
            return CryptographicBuffer.EncodeToBase64String(signedMessage);
        }
        public string HmacSha256(string secretKey, string value)
        {
            // Move strings to buffers.
            var key = CryptographicBuffer.ConvertStringToBinary(secretKey, BinaryStringEncoding.Utf8);
            var msg = CryptographicBuffer.ConvertStringToBinary(value, BinaryStringEncoding.Utf8);

            // Create HMAC.
            var objMacProv = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
            var hash = objMacProv.CreateHash(key);
            hash.Append(msg);
            return CryptographicBuffer.EncodeToBase64String(hash.GetValueAndReset());
        }

        private async void GetLocation()
        {
            _geolocator.DesiredAccuracy = PositionAccuracy.High;
            Geoposition pos = await _geolocator.GetGeopositionAsync();

            longitude = pos.Coordinate.Point.Position.Longitude;
            lattitude = pos.Coordinate.Point.Position.Latitude;
            Send(2.2, longitude, lattitude);
        }

        async void Send(double dist, double longitude, double lattitude)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new Windows.Web.Http.Headers.HttpCredentialsHeaderValue("SharedAccessSignature", GetSASToken(sbNamespace, keyName, keyValue));
                var buffer = Windows.Security.Cryptography.CryptographicBuffer.ConvertStringToBinary(dist.ToString() + ", " + longitude.ToString() + ", " + lattitude.ToString(), Windows.Security.Cryptography.BinaryStringEncoding.Utf8);
                HttpBufferContent BufferContent = new HttpBufferContent(buffer);
                BufferContent.Headers.Add("Content-Type", "application/atom+xml;type=entry;charset=utf-8");
                var res = await client.PostAsync(new Uri("https://iacaddemo.servicebus.windows.net/iacaddemo/partitions/1/messages"), BufferContent);
            }

        }
    }
}
