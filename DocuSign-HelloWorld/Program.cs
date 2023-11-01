using DocuSign.eSign.Client;
using DocuSign.eSign.Api;
using DocuSign.eSign.Model;
using DocuSign.eSign.Client.Auth;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using static DocuSign.eSign.Client.Auth.OAuth.UserInfo;
using System.Net;
using Microsoft.IdentityModel.Protocols;
using static DocuSign.eSign.Client.Auth.OAuth;
using DocuSign.CodeExamples.Authentication;
using static System.Runtime.InteropServices.JavaScript.JSType;


class Program
{
    [Obsolete]
    static void Main()
    {
        // Your DocuSign integration key, username, password, and account ID
        //string integrationKey = "52fbf297-280f-4550-aa13-45a88edb6762";
        //string email = "mark.walker@zealitconsultants.com";
        //string password = "";
        string accountId = "7896adf0-3fe5-46b7-b78e-ed6b99d26ca5";
        //string userId = "bbe6601a-356a-4906-b850-0f9698dac705";
        //string aud = "account-d.docusign.com";
        //string apiUrl = "https://account-d.docusign.com";
        string clientId = "52fbf297-280f-4550-aa13-45a88edb6762";            
        string impersonatedUserId = "bbe6601a-356a-4906-b850-0f9698dac705"; 

       

        // Path to your private key file (replace with your private key file path)
        string privateKeyFilePath = @"C:\Users\Mark Walker\source\repos\Archer\DocuSign-HelloWorld\private_key.pem";

        // Read the private key from the file
        string privateKey = File.ReadAllText(privateKeyFilePath);
        string tempPrivateKey = "";

                                             
        //tempPrivateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----\r\n", string.Empty);
        //tempPrivateKey = tempPrivateKey.Replace("\r\n-----END PRIVATE KEY-----\r\n", string.Empty);
        //tempPrivateKey = tempPrivateKey.Replace("\r\n\r\n", string.Empty);



        // Convert the private key string to a Stream
        //byte[] privateKeyBytes = Encoding.ASCII.GetBytes(tempPrivateKey);
               

        var privateKeyBytes = System.Text.Encoding.UTF8.GetBytes(File.ReadAllText("private_key.pem"));
        //byte[] privateKeyBytes = Convert.FromBase64String(tempPrivateKey);
        //MemoryStream privateKeyStream = new MemoryStream(privateKeyBytes);

        //Get Access Token
        OAuthToken accessToken = null;
        try
        {
            //accessToken = JwtAuth.AuthenticateWithJwt("ESignature", ConfigurationManager.AppSettings["ClientId"], ConfigurationManager.AppSettings["ImpersonatedUserId"],
            //                                            ConfigurationManager.AppSettings["AuthServer"], DsHelper.ReadFileContent(ConfigurationManager.AppSettings["PrivateKeyFile"]));

            accessToken = JwtAuth.AuthenticateWithJwt("ESignature", clientId, impersonatedUserId, "account-d.docusign.com", privateKeyBytes);
        }
        catch (ApiException apiExp)
        {
            Console.WriteLine(apiExp.Message);
        }

        // Initialize the API client 
        ApiClient apiClient = new ApiClient("https://demo.docusign.net/restapi"); 
        //apiClient.Configuration.AddDefaultHeader("Authorization", "Bearer " + GetAccessToken(privateKey, integrationKey, userId, aud, apiUrl));
        apiClient.Configuration.AddDefaultHeader("Authorization", "Bearer " + accessToken);

        // Create an envelope definition
        EnvelopeDefinition envelopeDefinition = new EnvelopeDefinition
        {
            EmailSubject = "Hello World",
            Status = "sent",
            Documents = new List<Document>
            {
                new Document
                {
                    DocumentBase64 = Convert.ToBase64String(System.IO.File.ReadAllBytes(@"C:\Users\Mark Walker\source\repos\Archer\DocuSign-HelloWorld\HelloWorld.pdf")),
                    DocumentId = "1",
                    FileExtension = "pdf",
                    Name = "HelloWorld.pdf"
                }
            },
            Recipients = new Recipients
            {
                Signers = new List<Signer>
                {
                    new Signer
                    {
                        Email = "mark.walker@zealitconsultants.com",
                        Name = "Mark Walker",
                        RecipientId = "1",
                        RoutingOrder = "1"
                    }
                }
            }
        };

        var docuSignClient = new DocuSignClient();
        docuSignClient.SetOAuthBasePath("account-d.docusign.com");
        var userInfo = docuSignClient.GetUserInfo(accessToken.access_token);
        Account acct = userInfo.Accounts.FirstOrDefault();

        Console.WriteLine("Welcome to the JWT Code example! ");
        Console.Write("Enter the signer's email address: ");
        string signerEmail = Console.ReadLine();
        Console.Write("Enter the signer's name: ");
        string signerName = Console.ReadLine();
        Console.Write("Enter the carbon copy's email address: ");
        string ccEmail = Console.ReadLine();
        Console.Write("Enter the carbon copy's name: ");
        string ccName = Console.ReadLine();
        Console.WriteLine("");
        string envelopeId = SigningViaEmail.SendEnvelopeViaEmail(signerEmail, signerName, ccEmail, ccName, accessToken.access_token, acct.BaseUri + "/restapi", acct.AccountId, @"C:\Users\Mark Walker\source\repos\Archer\DocuSign-HelloWorld\HelloWorld.pdf", "sent");
        Console.WriteLine("");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"Successfully sent envelope with envelopeId {envelopeId}");
        Console.WriteLine("");
        Console.WriteLine("");
        Console.ForegroundColor = ConsoleColor.White;
        Environment.Exit(0);

        // Create the envelope
        EnvelopesApi envelopesApi = new EnvelopesApi(apiClient);
        EnvelopeSummary envelopeSummary = envelopesApi.CreateEnvelope(accountId, envelopeDefinition);

        Console.WriteLine($"Envelope sent! Envelope ID: {envelopeSummary.EnvelopeId}");
    }

    //FROM WEB
    //[Obsolete]
    //static string GetAccessToken(string integratorKey, string userId, Stream privateKeyStream)
    //{
    //    ApiClient apiClient = new ApiClient("https://demo.docusign.net/restapi");

    //    OAuth.OAuthToken tokenInfo = apiClient.RequestJWTUserToken(integratorKey, userId, "signature", privateKeyStream, 1);

    //    return tokenInfo.access_token;
    //}


    //FROM QUICKSTART EXAMPLE
    //public OAuth.OAuthToken GenerateAccessToken(string clientId, string clientSecret, string code)
    //{
    //    if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(code))
    //    {
    //        throw new ArgumentNullException();
    //    }

    //    string s = clientId + ":" + clientSecret;
    //    string text = Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
    //    DocuSignRequest docuSignRequest = new DocuSignRequest(HttpMethod.Post, oAuthBasePathWithScheme + "oauth/token", "");
    //    docuSignRequest.AddHeaderParameter("Authorization", "Basic " + text);
    //    docuSignRequest.AddHeaderParameter("Content-Type", "application/x-www-form-urlencoded");
    //    docuSignRequest.AddHeaderParameter("Cache-Control", "no-store");
    //    docuSignRequest.AddHeaderParameter("Pragma", "no-cache");
    //    foreach (KeyValuePair<string, string> item in new Dictionary<string, string>
    //        {
    //            { "grant_type", "authorization_code" },
    //            { "code", code }
    //        })
    //    {
    //        docuSignRequest.AddPostParameter(item.Key, item.Value);
    //    }

    //    DocuSignResponse docuSignResponse = RestClient.SendRequest(docuSignRequest);
    //    if (docuSignResponse.StatusCode >= HttpStatusCode.OK && docuSignResponse.StatusCode < HttpStatusCode.BadRequest)
    //    {
    //        OAuth.OAuthToken oAuthToken = JsonConvert.DeserializeObject<OAuth.OAuthToken>(docuSignResponse.Content);
    //        string value = "Bearer " + oAuthToken.access_token;
    //        if (!Configuration.DefaultHeader.ContainsKey("Authorization"))
    //        {
    //            Configuration.DefaultHeader.Add("Authorization", value);
    //        }
    //        else
    //        {
    //            Configuration.DefaultHeader["Authorization"] = value;
    //        }

    //        return oAuthToken;
    //    }

    //    throw new ApiException((int)docuSignResponse.StatusCode, "Error while requesting server, received a non successful HTTP code with response Body: " + docuSignResponse.Content, docuSignResponse.Content, docuSignResponse);
    //}

    //FROM MAVERICK (aka Dan)
    //public string GetAccessToken(string privateKeyPem, string integrationKey, string userId, string aud, string apiUrl)
    //{
    //    var client = new HttpClient();
    //    try
    //    {
    //        // reading the content of a private key PEM file, PKCS8 encoded 
    //        //string privateKeyPem = prodKey ? PROD_PRIVATE_KEY : PRIVATE_KEY;

    //        // keeping only the payload of the key 
    //        privateKeyPem = privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", "");
    //        privateKeyPem = privateKeyPem.Replace("-----END RSA PRIVATE KEY-----", "");

    //        byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);

    //        // creating the RSA key 
    //        RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
    //        provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
    //        RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(provider);

    //        // Generating the token 
    //        var now = DateTime.UtcNow;

    //        TimeSpan iat = DateTime.UtcNow - new DateTime(1970, 1, 1);
    //        TimeSpan oneHr = TimeSpan.FromHours(1);
    //        int iatVal = (int)iat.TotalSeconds;
    //        var expVal = iat.Add(oneHr).TotalSeconds;

    //        var claims = new[] {
    //                new Claim(JwtRegisteredClaimNames.Iss, integrationKey),
    //                new Claim(JwtRegisteredClaimNames.Sub, userId),
    //                new Claim(JwtRegisteredClaimNames.Aud, aud),
    //                new Claim(JwtRegisteredClaimNames.Iat, iatVal.ToString()),
    //                new Claim(JwtRegisteredClaimNames.Exp, (iatVal+4000).ToString()),
    //            };

    //        var handler = new JwtSecurityTokenHandler();

    //        var token = new JwtSecurityToken
    //        (
    //            null,
    //            null,
    //            claims,
    //            null,
    //            null,
    //            new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256)
    //        );

    //        token.Payload["scope"] = "signature impersonation";

    //        var jwt = handler.WriteToken(token);

    //        var values = new Dictionary<string, string>
    //                {
    //                    {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
    //                    {"assertion", jwt}
    //                };

    //        var content = new FormUrlEncodedContent(values);
    //        var response = client.PostAsync(apiUrl + "/oauth/token", content);
    //        var responseString = response.Content.ReadAsStringAsync();
    //        var data = (JObject)JsonConvert.DeserializeObject(responseString);
    //        var accessToken = data.SelectToken("access_token").Value<string>();

    //        HttpResponseMessage authorizationReponse;
    //        string baseUri;

    //        using (var requestMessage = new HttpRequestMessage(HttpMethod.Get, apiUrl + "/oauth/userinfo"))
    //        {
    //            requestMessage.Headers.Authorization =
    //                new AuthenticationHeaderValue("Bearer", accessToken);

    //            authorizationReponse = client.SendAsync(requestMessage);
    //            var authorizationReponseString =  authorizationReponse.Content.ReadAsStringAsync();
    //            var authorizationData = (JObject)JsonConvert.DeserializeObject(authorizationReponseString);
    //            baseUri = authorizationData.SelectToken("accounts[0].base_uri").Value<string>();
    //        }

    //        DocusignSession session = new DocusignSession
    //        (
    //            jwt,
    //            accessToken,
    //            baseUri
    //        );

    //        return session;
    //    }
    //    catch (Exception e)
    //    {
    //        Console.WriteLine(e.ToString());
    //        Console.WriteLine(
    //             new System.Diagnostics.StackTrace().ToString()
    //        );
    //        throw;
    //    }
    //    finally
    //    {
    //        client.Dispose();
    //    }
    //}
}

