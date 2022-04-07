using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using SignWebForm.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
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

        public IActionResult File()
        {
            return View();
        }

        public IActionResult Text()
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

           //Проверка на подписаните данни - проверява дали подписаните данни отговарят на тези които са в XML-a, не се проверява дали сертификата е валиден. Тази проверка се прави по-надолу
            var resultSignature = signedXml.CheckSignature();



            string plainText = null;
            XmlNodeList elemList = xmlDocument.GetElementsByTagName("X509Certificate");
            foreach (XmlElement xElem in elemList)
            {
                plainText = xElem.InnerText;
            }
           
            byte[] wer = StrToByteArray(plainText);
            X509Certificate2 cert = new X509Certificate2(wer, string.Empty, X509KeyStorageFlags.MachineKeySet);

            // Check the signature and return the result.
            // Тук се прави освен проверка на подписа и валидността на сертификата едновременно 
            // var result = signedXml.CheckSignature(cert, false);

            //Поради оскъдната документация за проверка на подписа и сертификата се използват поотделно resultSignature = signedXml.CheckSignature() и resultCert = cert.Verify(), а не signedXml.CheckSignature(cert, false);


            string SerialNumber = cert.SerialNumber;
            string Subject = cert.Subject;
            string Issuer = cert.Issuer;
            string Thumbprint = cert.Thumbprint;  // Уникален параметър , който може да служи за идентификация. Примерно при логване с клиент сертификат трябва да се провери дали Thumbprint от сесията при ligin-a съответсва с Thumbprint на подписа
            //string IssuerName = cert.IssuerName;
            
            bool resultCert = cert.Verify();  // Проверка на сертификат. Проверява се дали сертификата е revocked, но не се проверява сертификатите по веригата дали те а са revoked,  и дали е издаден от съответния CA за повече информация  http://stackoverflow.com/questions/10083650/x509certificate2-verify-method-validating-against-revocation-list-and-perform
           
            // err = ValidateCert(mCert);  //Още един начин за проверка на сертификат. Чрез този метод се прави най-пълна проверка на сертификата и неговата верига и дали е издаден от желан CA издател този метод може да се види в по-старата версия от 2014 (директория 2014)

            if (resultSignature & resultCert){
                // Успешна проверка
            }
            else
            {
               // Неуспешна проверка
            }

            return View(res);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ReportFile(InputFileModel fileInput)
        {
            var formFile = fileInput.file;

          
            JObject jsonSign = JObject.Parse(fileInput.XMLsignFile);
            string pkcs7 = (string)jsonSign["signature"];

            var filePath = Path.GetTempFileName();

            using (var stream = System.IO.File.Create(filePath))
            {
                await formFile.CopyToAsync(stream);
            }

           
            string inputContent = System.IO.File.ReadAllText(filePath);

            byte[] wer = StrToByteArray(inputContent);

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




            ViewBag.signFile = fileInput.XMLsignFile;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ReportText(SignFormText formText)
        {
            

            JObject jsonSign = JObject.Parse(formText.TextSign);
            string pkcs7 = (string)jsonSign["signature"];

            string tmp = formText.Text;
            var ddd = Encoding.UTF8.GetBytes(tmp);
            tmp = Convert.ToString(ddd);
            

            byte[] wer = StrToByteArray(formText.Text);

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




            ViewBag.signText = formText.TextSign;
            return View();
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

       



    }
}
