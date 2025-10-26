//using System.Net;
//using System.Security;
//using System.Security.Cryptography;
//using System.Text;
//using System.Xml.Linq;

//namespace ConsoleApp1
//{
//    internal class Program
//    {
////        static async Task<string> PostSoapAsync(HttpClient client, string url, string soapAction, string soapBody)
////        {
////            var req = new HttpRequestMessage(HttpMethod.Post, url);
////            req.Content = new StringContent(soapBody, Encoding.UTF8, "text/xml");
////            req.Headers.Add("SOAPAction", soapAction);
////            var resp = await client.SendAsync(req);
////            var text = await resp.Content.ReadAsStringAsync();
////            if (!resp.IsSuccessStatusCode)
////                throw new Exception($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}\n{text}");
////            return text;
////        }

////        public static async Task Main()
////        {
////            var urlClient = "http://10.10.10.29:8530/ClientWebService/Client.asmx";
////            var urlSimpleAuth = "http://10.10.10.29:8530/SimpleAuthWebService/SimpleAuth.asmx";

////            // If your WSUS requires Windows auth, use default credentials:
////            var handler = new HttpClientHandler { UseDefaultCredentials = true, PreAuthenticate = true, AllowAutoRedirect = false };
////            using var http = new HttpClient(handler);

////            // 1) GetConfig -> grab <LastChange>
////            string getConfigEnvelope = $@"<?xml version=""1.0"" encoding=""utf-8""?>
////<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""
////               xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
////               xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
////  <soap:Body>
////    <GetConfig xmlns=""http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"">
////      <protocolVersion>1.8</protocolVersion>
////    </GetConfig>
////  </soap:Body>
////</soap:Envelope>";

////            string cfgXml = await PostSoapAsync(
////                http, urlClient,
////                "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig",
////                getConfigEnvelope);

////            var cfgDoc = XDocument.Parse(cfgXml);
////            XNamespace nsClient = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService";
////            var lastChange = cfgDoc
////                 .Descendants()
////                 .FirstOrDefault(x => x.Name.LocalName == "LastChange")
////                 ?.Value;
////            if (string.IsNullOrEmpty(lastChange))
////                throw new Exception("Could not read <LastChange> from GetConfig response.");

////            // 2) GetAuthorizationCookie -> get <PlugInId> and base64 <CookieData>
////            var clientId = Guid.NewGuid().ToString();        // you can persist your own client ID
////            var dnsName = Environment.MachineName;          // or full DNS name if you have it

////            string getAuthEnvelope = $@"<?xml version=""1.0"" encoding=""utf-8""?>
////<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""
////               xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
////               xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
////  <soap:Body>
////    <GetAuthorizationCookie xmlns=""http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService"">
////      <clientId>{SecurityElement.Escape(clientId)}</clientId>
////      <targetGroupName />
////      <dnsName>{SecurityElement.Escape(dnsName)}</dnsName>
////    </GetAuthorizationCookie>
////  </soap:Body>
////</soap:Envelope>";

////            string authXml = await PostSoapAsync(
////                http, urlSimpleAuth,
////                "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie",
////                getAuthEnvelope);

////            var authDoc = XDocument.Parse(authXml);
////            XNamespace nsAuth = "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService";
////            var authResult = authDoc
////                .Descendants(nsAuth + "GetAuthorizationCookieResult")
////                .FirstOrDefault();
////            if (authResult == null)
////                throw new Exception("No <GetAuthorizationCookieResult> element found in response.");

////            // use namespace-qualified element names
////            string plugInId = authResult.Element(nsAuth + "PlugInId")?.Value ?? "SimpleTargeting";
////            string cookieB64 = authResult.Element(nsAuth + "CookieData")?.Value?.Trim()
////                               ?? throw new Exception("No <CookieData> found in GetAuthorizationCookieResult.");

////            // 3) GetCookie -> pass the AuthorizationCookie array + timestamps
////            string nowIso = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
////            string getCookieEnvelope = $@"<?xml version=""1.0"" encoding=""utf-8""?>
////<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""
////               xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
////               xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
////               xmlns:soapenc=""http://schemas.xmlsoap.org/soap/encoding/"">
////  <soap:Body>
////    <GetCookie xmlns=""http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"">
////      <authCookies xmlns:q1=""http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"" soapenc:arrayType=""q1:AuthorizationCookie[1]"">
////        <AuthorizationCookie>
////          <PlugInId>{SecurityElement.Escape(plugInId)}</PlugInId>
////          <CookieData>{cookieB64}</CookieData>
////        </AuthorizationCookie>
////      </authCookies>
////      <oldCookie xsi:nil=""true"" />
////      <lastChange>{lastChange}</lastChange>
////      <currentTime>{nowIso}</currentTime>
////      <protocolVersion>1.8</protocolVersion>
////    </GetCookie>
////  </soap:Body>
////</soap:Envelope>";

////            string cookieXml = await PostSoapAsync(
////                http, urlClient,
////                "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie",
////                getCookieEnvelope);

////            Console.WriteLine(cookieXml);
////        }
//        static async Task Main()
//        {
//            string hexKey = "877C14E433638145AD21BD0C17393071";
//            byte[] key = new byte[16];
//            for (int i = 0; i < 16; i++)
//                key[i] = Convert.ToByte(hexKey.Substring(i * 2, 2), 16);

//            string ysooo = "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAAAcvYyBjYWxjBgcAAAADY21kBAUAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0aG9kMAdtZXRob2QxAwMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkIAAAACQkAAAAJCgAAAAQIAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BgsAAACwAlN5c3RlbS5GdW5jYDNbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GDAAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkKBg0AAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQYOAAAAGlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzBg8AAAAFU3RhcnQJEAAAAAQJAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQkPAAAACQ0AAAAJDgAAAAYUAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhUAAAA+U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEKAAAACQAAAAYWAAAAB0NvbXBhcmUJDAAAAAYYAAAADVN5c3RlbS5TdHJpbmcGGQAAACtJbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhoAAAAyU3lzdGVtLkludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEQAAAACAAAAAYbAAAAcVN5c3RlbS5Db21wYXJpc29uYDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCQwAAAAKCQwAAAAJGAAAAAkWAAAACgs=";
            
//            byte[] ser = Convert.FromBase64String(ysooo);
//            //byte[] enc = BuildCookieForUnencrypted(ser, key, new byte[16]);
//            var enc2 = EncryptPayload(ser, key);
//            string base64Payload = Convert.ToBase64String(enc2);

//            using var client = new HttpClient();

//            var url = "http://10.10.10.29:8530/ClientWebService/Client.asmx";
//            var xmlBody =
//$$"""
//<?xml version="1.0" encoding="utf-8"?>
//<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
//  <soap:Body>
//    <GetCookie xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
//      <authCookies>
//        <AuthorizationCookie>
//          <PlugInId>SimpleTargeting</PlugInId>
//          <CookieData>{{base64Payload}}</CookieData>
//        </AuthorizationCookie>
//      </authCookies>
//      <oldCookie xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
//      <protocolVersion>1.20</protocolVersion>
//    </GetCookie>
//  </soap:Body>
//</soap:Envelope>
//""";


//            // build request manually to set custom headers
//            var request = new HttpRequestMessage(HttpMethod.Post, url);
//            request.Content = new StringContent(xmlBody, Encoding.UTF8, "text/xml");

//            // add SOAPAction header
//            request.Headers.Add("SOAPAction", "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie");
//            request.Headers.Host = "10.10.10.29:8530";
//            // send request
//            var response = await client.SendAsync(request);

//            string responseBody = await response.Content.ReadAsStringAsync();
//            Console.WriteLine("Status: " + response.StatusCode);
//            Console.WriteLine(responseBody);
//        }

//        static byte[] EncryptPayload(byte[] data, byte[] key)
//        {
//            using (var aes = new AesCryptoServiceProvider())
//            {
//                aes.Key = key;
//                aes.Mode = CipherMode.CBC;
//                aes.Padding = PaddingMode.None;
//                aes.IV = new byte[16]; // null

//                byte[] salt = new byte[16];
//                new RNGCryptoServiceProvider().GetNonZeroBytes(salt);

//                using (var encryptor = aes.CreateEncryptor())
//                {
//                    int num = data.Length % encryptor.InputBlockSize;
//                    int num2 = data.Length - num;
//                    byte[] result = new byte[encryptor.InputBlockSize + num2 + encryptor.OutputBlockSize];
//                    encryptor.TransformBlock(salt, 0, salt.Length, result, 0);
//                    encryptor.TransformBlock(data, 0, num2, result, salt.Length);
//                    byte[] paddedBlock = new byte[encryptor.InputBlockSize];
//                    for (int i = 0; i < num; i++)
//                    {
//                        paddedBlock[i] = data[num2 + i];
//                    }
//                    encryptor.TransformBlock(paddedBlock, 0, paddedBlock.Length, result, salt.Length + num2);

//                    return result;
//                }
//            }
//        }
//        public static byte[] BuildCookieForUnencrypted(
//        byte[] payloadUnencryptedCookieData, // bytes that UnencryptedCookieData.Deserialize expects
//        byte[] key,
//        byte[] iv)
//        {
//            using (var aes = new AesCryptoServiceProvider())
//            {
//                aes.Mode = CipherMode.CBC;
//                aes.Padding = PaddingMode.None;   // critical: decryptor uses TransformBlock only
//                aes.Key = key ?? throw new ArgumentNullException(nameof(key));
//                aes.IV = iv ?? throw new ArgumentNullException(nameof(iv));

//                int blockSize = aes.BlockSize / 8;

//                // 1) Sentinel: one full block that will be decrypted then ignored by DecryptData()
//                var sentinel = new byte[blockSize];
//                // You can fill with any deterministic or random content; it won't be read later.
//                // Example: random to avoid patterns:
//                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(sentinel);

//                // 2) Payload: must be block-aligned because Padding=None and only TransformBlock is used.
//                var payloadPadded = PadZero(payloadUnencryptedCookieData, blockSize);

//                // 3) Concatenate plaintext = [sentinel][payload]
//                var plaintext = new byte[sentinel.Length + payloadPadded.Length];
//                Buffer.BlockCopy(sentinel, 0, plaintext, 0, sentinel.Length);
//                Buffer.BlockCopy(payloadPadded, 0, plaintext, sentinel.Length, payloadPadded.Length);

//                // 4) Encrypt using TransformBlock (to mirror the decryptor’s pattern)
//                using (var enc = aes.CreateEncryptor())
//                {
//                    if (plaintext.Length % blockSize != 0 || plaintext.Length <= blockSize)
//                        throw new InvalidOperationException("Plaintext must be >= 2 blocks and block-aligned.");

//                    var ciphertext = new byte[plaintext.Length];

//                    // First block (sentinel)
//                    enc.TransformBlock(plaintext, 0, blockSize, ciphertext, 0);

//                    // Remaining blocks
//                    enc.TransformBlock(plaintext, blockSize, plaintext.Length - blockSize, ciphertext, blockSize);

//                    // No TransformFinalBlock call since we're using Padding=None and perfectly aligned data.
//                    return ciphertext;
//                }
//            }
//        }

//        private static byte[] PadZero(byte[] data, int blockSize)
//        {
//            if (data == null) throw new ArgumentNullException(nameof(data));
//            int rem = data.Length % blockSize;
//            if (rem == 0) return data;
//            var padded = new byte[data.Length + (blockSize - rem)];
//            Buffer.BlockCopy(data, 0, padded, 0, data.Length);
//            // zeros already in the tail
//            return padded;
//        }
//    }
//}
