using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SignWebForm.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;

namespace SignWebForm.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Report(SignForm res)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Format using white spaces.
            xmlDocument.PreserveWhitespace = true;

            // Load the passed XML file into the document.
            xmlDocument.LoadXml(res.XMLSign);

            // Create a new SignedXml object and pass it
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            var result = signedXml.CheckSignature();


            string plainText = null;
            XmlNodeList elemList = xmlDocument.GetElementsByTagName("X509Certificate");
            foreach (XmlElement xElem in elemList)
            {
                plainText = xElem.InnerText;
            }

           
            byte[] wer = StrToByteArray(plainText);
            X509Certificate2 cert = new X509Certificate2(wer, string.Empty, X509KeyStorageFlags.MachineKeySet);

            string SerialNumber = cert.SerialNumber;
            string Subject = cert.Subject;
            string Issuer = cert.Issuer;
            string Thumbprint = cert.Thumbprint;
            //string IssuerName = cert.IssuerName;
            bool fff = cert.Verify();  // Проверка на сертификат, подобна на тази по-горе. Не се проверява веригата, ревокейшун листа и дали е издаден от съответния CA
                                        // http://stackoverflow.com/questions/10083650/x509certificate2-verify-method-validating-against-revocation-list-and-perform
           // err = ValidateCert(mCert);  //Още един начин за проверка на сертификат. Чрез този метод се прави най-пълна проверка на сертификата и неговата верига и дали е издаден от желан CA издател



            return View(res);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public static byte[] StrToByteArray(string str)
        {
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            return encoding.GetBytes(str);
        }

        /*
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
        */
    }
}
