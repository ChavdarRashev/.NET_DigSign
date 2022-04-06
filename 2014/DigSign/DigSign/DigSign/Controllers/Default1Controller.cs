using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;


namespace DigSign.Controllers
{
    public class Default1Controller : Controller
    {
        //
        // GET: /Default1/

        public static byte[] StrToByteArray(string str)
        {
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            return encoding.GetBytes(str);
        }

        public static byte[] ExtractEnvelopedData(byte[] signature)
        {
            if (signature == null)
                throw new ArgumentNullException("signature");

            // decode the signature
            SignedCms cms = new SignedCms();
            cms.Decode(signature);

            if (cms.Detached)
                throw new InvalidOperationException("Cannot extract enveloped content from a detached signature.");

            return cms.ContentInfo.Content;
        }

        public ActionResult Index()
        {
                
            return View();
        }


        [HttpPost]
        public ActionResult Index(string pkcs7, string plainText)
        {
             // Java аплета връща pkcs#7 формат на подпис. В него се съдържа подписа, сертификата с публичния ключ, digest алгоритъма, digestEncryptionAlgorithm 

            // string pkcs7 = "MIIEawYJKoZIhvcNAQcCoIIEXDCCBFgCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCApQwggKQMIIB+aADAgECAgMAinEwDQYJKoZIhvcNAQEFBQAwgZExCzAJBgNVBAYTAkJHMQ4wDAYDVQQIEwVTb2ZpYTEOMAwGA1UEBxMFU29maWExHjAcBgNVBAoTFUZpcnN0IEludmVzdG1lbnQgQmFuazELMAkGA1UECxMCSVQxFDASBgNVBAMTC2UtZmliYW5rLmJnMR8wHQYJKoZIhvcNAQkBFhBlLWJhbmtAZmliYW5rLmJnMB4XDTA2MDgxMTE0MTYyNVoXDTE2MDIwOTE1MjUxMlowQTEeMBwGA1UEAxMVQ0hhdmRhciBaYXJrb3YgUmFzaGV2MR8wHQYJKoZIhvcNAQkBFhByYXNoZXZAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvKTeVaBYPkzmHUUmcYM+kbubgK66IwdWZFHqQZpEZXL7i+J+BcA2jx5or9iUjtk/RTKtYi3YeWpMVot5tztD51NM0z8y6d9kkBSVTyKPj6Ctf8hRIydcXdWDpbwXHN6Bu5hFE/KAsaBC+qHrbRGlHaH2tW/PokojkHwig17xedwIDAQABo0UwQzARBglghkgBhvhCAQEEBAMCB4AwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCA7gwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQEFBQADgYEAgoXwHMhOtzbuFxNip2RKQd78ikco4Kx0jIkdSl3SDn81vbwkwYzhe1LlIB1pYGX82NXZbA+IKZ8Dq1GFPpts0ZIxGbrYo9fYmsBJKLCaKVSSMgXUGQ2GASbLk677yPCvSdmTZtMXj3IJFh4uuRh4SVJqGQj+xSnZ9qzN4tGbDCMxggGfMIIBmwIBATCBmTCBkTELMAkGA1UEBhMCQkcxDjAMBgNVBAgTBVNvZmlhMQ4wDAYDVQQHEwVTb2ZpYTEeMBwGA1UEChMVRmlyc3QgSW52ZXN0bWVudCBCYW5rMQswCQYDVQQLEwJJVDEUMBIGA1UEAxMLZS1maWJhbmsuYmcxHzAdBgkqhkiG9w0BCQEWEGUtYmFua0BmaWJhbmsuYmcCAwCKcTAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTQwMTAyMjIwNDI3WjAjBgkqhkiG9w0BCQQxFgQUhuKx7kKz6NV/oqzBm9uW0V3+QQkwDQYJKoZIhvcNAQEBBQAEgYBJQoyIJUDs0vz2M7vy01/0spFclDGWfeViWip8nPEBnIY1jg4xKXUZE3CtxV8yndQTXVzgLNjDjlM0TVad0T3BmmY+sjHs9HwMTVj8X2BxkYu2Y18Ni51Ojzmh7rNmeTPZPO8TvBqMsI5qaQm4ekiESkPS1vy+6RHlHG4H0d3yHA==";
            // string pkcs8 = "MIIEawYJKoZIhvcNAQcCoIIEXDCCBFgCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCApQwggKQMIIB+aADAgECAgMAinEwDQYJKoZIhvcNAQEFBQAwgZExCzAJBgNVBAYTAkJHMQ4wDAYDVQQIEwVTb2ZpYTEOMAwGA1UEBxMFU29maWExHjAcBgNVBAoTFUZpcnN0IEludmVzdG1lbnQgQmFuazELMAkGA1UECxMCSVQxFDASBgNVBAMTC2UtZmliYW5rLmJnMR8wHQYJKoZIhvcNAQkBFhBlLWJhbmtAZmliYW5rLmJnMB4XDTA2MDgxMTE0MTYyNVoXDTE2MDIwOTE1MjUxMlowQTEeMBwGA1UEAxMVQ0hhdmRhciBaYXJrb3YgUmFzaGV2MR8wHQYJKoZIhvcNAQkBFhByYXNoZXZAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvKTeVaBYPkzmHUUmcYM+kbubgK66IwdWZFHqQZpEZXL7i+J+BcA2jx5or9iUjtk/RTKtYi3YeWpMVot5tztD51NM0z8y6d9kkBSVTyKPj6Ctf8hRIydcXdWDpbwXHN6Bu5hFE/KAsaBC+qHrbRGlHaH2tW/PokojkHwig17xedwIDAQABo0UwQzARBglghkgBhvhCAQEEBAMCB4AwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCA7gwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQEFBQADgYEAgoXwHMhOtzbuFxNip2RKQd78ikco4Kx0jIkdSl3SDn81vbwkwYzhe1LlIB1pYGX82NXZbA+IKZ8Dq1GFPpts0ZIxGbrYo9fYmsBJKLCaKVSSMgXUGQ2GASbLk677yPCvSdmTZtMXj3IJFh4uuRh4SVJqGQj+xSnZ9qzN4tGbDCMxggGfMIIBmwIBATCBmTCBkTELMAkGA1UEBhMCQkcxDjAMBgNVBAgTBVNvZmlhMQ4wDAYDVQQHEwVTb2ZpYTEeMBwGA1UEChMVRmlyc3QgSW52ZXN0bWVudCBCYW5rMQswCQYDVQQLEwJJVDEUMBIGA1UEAxMLZS1maWJhbmsuYmcxHzAdBgkqhkiG9w0BCQEWEGUtYmFua0BmaWJhbmsuYmcCAwCKcTAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTQwMTAyMTQzNDIzWjAjBgkqhkiG9w0BCQQxFgQU0WULZ3JPgAiGEMkQ9Lb03BvDsrMwDQYJKoZIhvcNAQEBBQAEgYA2S2DG6Ty26C6MRFZRfOJ6EgFF25BMbI0OOyINc3l/GF+RXwl9ZmqLogpa56dZtgLGIREyGZ0iFO/LgU3CHzS0Y3cUdPfSABKXlfNUSuOLboonxCOo45xAbTMthx7mZKZ+aUWyPRfnepQXH2Sh4ftQx/Q31vfEbP+ZDDbxQe+sMw==";
            // byte[] bt = StrToByteArray(pkcs8);
            // byte[] tt = ExtractEnvelopedData(bt);
            // byte[] bt = StrToByteArray(pkcs7);
            // byte[] dfg = ExtractEnvelopedData(bt);

            
            byte[] wer = StrToByteArray(plainText);

            ContentInfo contentInfo = new ContentInfo(wer);

            SignedCms cms = new SignedCms(contentInfo, true);
            cms.Decode(Convert.FromBase64String(pkcs7));
            bool wwb = cms.Detached;

            ContentInfo ci = cms.ContentInfo;

            string err = "no error";

            
            try
            {
                cms.CheckSignature(false); // Проверява се signature и подписа, проверява се само валидността на подписа, но не и на веригта
            }

            catch (Exception e)
            {
                err = e.Message;
            }

           
            X509Certificate2Collection certs = cms.Certificates;  // От pkcs#7 се взима серрификата

         
            foreach (X509Certificate2 mCert in certs)  // Извличане на данните от  сертификата
            {
                string df = mCert.SerialNumber;
                string dd = mCert.Subject;
                string dd3 = mCert.Issuer;
                string dd4 = mCert.Thumbprint;
                //string dd6 = mCert.IssuerName;
                bool fff = mCert.Verify();  // Проверка на сертификат, подобна на тази по-горе. Не се проверява веригата, ревокейшун листа и дали е издаден от съответния CA
                                                       // http://stackoverflow.com/questions/10083650/x509certificate2-verify-method-validating-against-revocation-list-and-perform
                err = ValidateCert(mCert);  //Още един начин за проверка на сертификат. Чрез този метод се прави най-пълна проверка на сертификата и неговата верига и дали е издаден от желан CA издател
                
            }

            string retMass;
            if (err == "no error") retMass = "No error. Signature and certificate are valid.";
            else retMass = "Error! " + err;

            ViewBag.err = retMass;
            
            return View();
        }



        string ValidateCert(X509Certificate2 cert) // X509Certificate2 cert - сертификата, който валидираме 
          {

              string retValue = "no error";  // Връщаната стойност no error - верификацията е успешен валиден сертификат

            X509Chain chain = new X509Chain(); 
            // check entire chain for revocation 
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain; 
            // check online and offline revocation lists 
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; // X509RevocationMode.Offline; 
            // timeout for online revocation list 
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30); 
            // no exceptions, check all properties 
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag; 
            // modify time of verification 
            //chain.ChainPolicy.VerificationTime = new DateTime(1999, 1, 1); 


            X509Certificate2Collection certificates = new X509Certificate2Collection();

            string filePath = HttpContext.Server.MapPath("~/Content/certificates/RootCA5_PEM.cer");
            string filePath1 = HttpContext.Server.MapPath("~/Content/certificates/StampIT_Primary_Root_CA_base64.crt");

            certificates.Import(filePath);
            certificates.Import(filePath1);
            
            
            //chain.ChainPolicy.ExtraStore.AddRange(certificates);
            //chain.ChainPolicy.ExtraStore.Add(certificates);    //Очаквам след като по този начин се добавят сертификати - root CA израза chain.Build(cert) по-долу да върне false за сертификат , чийто  root CA не е добавен чрез chain.ChainPolicy.ExtraStore.Add - но това не е така  винаги chain.Build(cert) връща true не зависимо дали root CA за дадения сертификат е добавен или не.

           

            bool isChainValid = chain.Build(cert);
            if (chain.ChainStatus.Length != 0) 
             { 
                var vbn = chain.ChainStatus[0].StatusInformation; 
             }
            
            
            if (!isChainValid)   // Тук се взимат всички съобщенията за грешките относно веригата revocation list и т.н
            {
                string[] errors = chain.ChainStatus
                    .Select(x => String.Format("{0} ({1})", x.StatusInformation.Trim(), x.Status))
                    .ToArray();
                 retValue = "Unknown errors.";

                if (errors != null && errors.Length > 0)
                {
                    retValue = String.Join(", ", errors);
                }

                // throw new Exception("Trust chain did not complete to the known authority anchor. Errors: " + retValue);
            }

            // http://stackoverflow.com/questions/6497040/how-do-i-validate-that-a-certificate-was-created-by-a-particular-certification-a?rq=1
            // This piece makes sure it actually matches your known root
            bool flagCA = false;
            foreach (X509Certificate2 Cert in certificates)
            {
                if (chain.ChainElements
                    .Cast<X509ChainElement>()
                    .Any(x => x.Certificate.Thumbprint == Cert.Thumbprint))
                {
                    flagCA = true;
                }
            }

            if (!flagCA) retValue += "Trust chain did not complete to the known any authority anchor. Thumbprints did not match.";


            return retValue;
        }

    }
}
