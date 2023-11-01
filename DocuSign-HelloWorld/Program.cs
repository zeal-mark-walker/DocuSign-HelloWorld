using DocuSign.eSign.Client;
using DocuSign.eSign.Api;
using DocuSign.eSign.Model;
using static DocuSign.eSign.Client.Auth.OAuth.UserInfo;
using static DocuSign.eSign.Client.Auth.OAuth;
using DocuSign.CodeExamples.Authentication;

class Program
{
    static void Main()
    {      
        string accountId = "7896adf0-3fe5-46b7-b78e-ed6b99d26ca5";
        string authServer = "account-d.docusign.com";
        string api = "ESignature";
        string clientId = "52fbf297-280f-4550-aa13-45a88edb6762";            
        string impersonatedUserId = "bbe6601a-356a-4906-b850-0f9698dac705";       

        // Path to your private key file (replace with your private key file path)
        string privateKeyFilePath = @"C:\Users\Mark Walker\source\repos\Archer\DocuSign-HelloWorld\private_key.pem";
        string docPdf = @"C:\Users\Mark Walker\source\repos\Archer\DocuSign-HelloWorld\HelloWorld.pdf";

        // Read the private key from the file
        string privateKey = File.ReadAllText(privateKeyFilePath);

        var privateKeyBytes = System.Text.Encoding.UTF8.GetBytes(File.ReadAllText("private_key.pem"));

        //Get Access Token
        OAuthToken accessToken = null;
        try
        {
            accessToken = JwtAuth.AuthenticateWithJwt(api, clientId, impersonatedUserId, authServer, privateKeyBytes);
        }
        catch (ApiException apiExp)
        {
            Console.WriteLine(apiExp.Message);
        }

        // Initialize the API client 
        ApiClient apiClient = new ApiClient("https://demo.docusign.net/restapi"); 
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
        string envelopeId = SigningViaEmail.SendEnvelopeViaEmail(signerEmail, signerName, ccEmail, ccName, accessToken.access_token, acct.BaseUri + "/restapi", acct.AccountId, docPdf, "sent");
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
}

