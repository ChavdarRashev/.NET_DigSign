using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using SignWebForm.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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
        //ToDo да се направи проверка на издателя на сертификата - дали този сертификат е издаден от съответния издател. Това се прави само ако WEB сървъра не проверява предварително и не допуска само потребители със сертификати от определен доставчик.

        //да се направи софтуер, който да проверява вече направен подпис срещу съдържанието или файла или xml-a
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

        public IActionResult FileSCS()
        {
            return View();
        }

        //Тук за разлика от FileSCS, подписания файл не се изпраща, като стринг, а като прикачен файл към формата. Във варианта FileSCS, когато се изпраща стринг от textarea има ограничения че input и textarea могат да съдържат до  524288 символа или половин мегабайт. За по-големи подписани файлове не може да се използва FileSCS, а трябва да се използва FileSCSToFormFile 
        public IActionResult FileSCSToFormFile()
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

            //Долните три коментирани реда , не връщат повече информация от колкото cert.Subject и cert.Issuer
            //X500DistinguishedName IssuerName = cert.IssuerName;
            //string nameI = IssuerName.Name;
            //X500DistinguishedName userName = cert.SubjectName;


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
        public async Task<IActionResult> ReportFile(InputFileModel fileInput)  //Кодът е идентичен с по-долните два метода виж там за коменмтари
        {
            var formFile = fileInput.file;  // 


            JObject jsonSign = JObject.Parse(fileInput.FileSignFile); // В textarea от формата  с име FileSignFile съсъдржа json стринг образуван от подписващия Java софтуер. Този json е случаен формат на Java разработчика, a не е някакъв стандартизиран.

            string pkcs7 = (string)jsonSign["signature"]; // от JSON-a взимаме елемента с име signature - това е подписа в PKCS#7 формат

            var filePath = Path.GetTempFileName();
            using (var stream = System.IO.File.Create(filePath))
            {
                await formFile.CopyToAsync(stream);
            }


            string inputContent = System.IO.File.ReadAllText(filePath);

            string inputContent1 = Uri.EscapeDataString(inputContent);

            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(inputContent1);

            //Тук не работи файлове с кирилски символи. Работи в txt файлове с които има латински символи
            // Тества се UTF8 , ToBase64String и т.н но не работи

            //string gr = System.Convert.ToBase64String(plainTextBytes);

            byte[] wer = StrToByteArray(inputContent);

            ContentInfo contentInfo = new ContentInfo(wer);

            SignedCms cms = new SignedCms(contentInfo, true);
            cms.Decode(Convert.FromBase64String(pkcs7));
           
            string err = "no error";


            try
            {
                cms.CheckSignature(false); // Проверява се подписа и сертификата. Проверява се само валидността на подписа, но не и на веригата. If is true, only the digital signatures are verified. If it is false, the digital signatures are verified, the signers' certificates are validated, and the purposes of the certificates are validated.
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
                bool fff = mCert.Verify();  // Проверка на сертификат дали е валиден и проверява да не е в ревокейшън листа.Тази проверка е подобна на на тази по-горе cms.CheckSignature. Не се проверява сертификатите по веригата дали те не са в ревокейшун листа и дали е издаден от съответния CA. За да работи този метод трябва на компютъра(сървъра), който на който се изпълнява този код да е инсталиран root сертификата на издателя.
                // http://stackoverflow.com/questions/10083650/x509certificate2-verify-method-validating-against-revocation-list-and-perform
               // err = ValidateCert(mCert);  //Още един начин за проверка на сертификат. Чрез този метод се прави най-пълна проверка на сертификата и неговата верига и дали е издаден от желан CA издател - този код може да се види във версията от 2014 г в това репозитори

            }

            string retMass;
            if (err == "no error") retMass = "No error. Signature and certificate are valid.";
            else retMass = "Error! " + err;




            // ViewBag.signFile = fileInput.XMLsignFile;
            ViewBag.signFile = retMass;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ReportText(SignFormText formText)
        {
           
            //ToDo 1. На по-бавни компютри прозореца за избор на сертификат много бавно се показва

            JObject jsonSign = JObject.Parse(formText.TextSign);  // В textarea от формата  с име TextSign съсъдржа json стринг образуван от подписващия Java софтуер. Този json е случаен формат на разработчика е не е някакъв стандартизиран.
            string pkcs7 = (string)jsonSign["signature"]; // от JSON-a взимаме елемента с име signature - това е подписа в PKCS#7 формат

            string tmp = formText.Text;  // В textarea от формата  с име е текста, който подписваме.
           

            byte[] wer = StrToByteArray(formText.Text);  // Масив от туп byte (In C#, byte is the data type for 8-bit unsigned integers, so a byte[] should be an array of integers who are between 0 and 255), ако formText.Text съдържа string "abc", то масива ще има три стойности 97, 98, 99

            ContentInfo contentInfo = new ContentInfo(wer);   // The ContentInfo class represents the CMS/PKCS #7 ContentInfo data structure as defined in the CMS/PKCS #7 standards document. This data structure is the basis for all CMS/PKCS #7 messages.

            SignedCms cms = new SignedCms(contentInfo, true);  //The SignedCms class enables signing and verifying of CMS/PKCS #7 messages. true параметъра показва signature is detached това значи, че съобщението (текстът), който се подписва не се съдържа в подписа. In PKCS#7 SignedData, attached and detached formats are supported… In detached format, data that is signed is not embedded inside the SignedData package instead it is placed at some external location…
                                                               
             cms.Decode(Convert.FromBase64String(pkcs7));  //Decodes  SignedCms message. Декодира подписа, като подписа му се подава, като array от byte

            string err = "No error. Signature and certificate, are valid.";


            try
            {
              cms.CheckSignature(false); // Проверява се подписа и сертификата. Проверява се само валидността на подписа, но не и на веригата. If is true, only the digital signatures are verified. If it is false, the digital signatures are verified, the signers' certificates are validated, and the purposes of the certificates are validated.
            }

            catch (Exception e)
            {
                err = e.Message;
            }


            ViewBag.signText = formText.TextSign;
            ViewBag.err = err;
            return View();
        }

        public async Task<IActionResult> ReportFileSCS(InputFileModel fileInput)
        {
            var formFile = fileInput.file;  


            JObject jsonSign = JObject.Parse(fileInput.FileSignFile); // В textarea от формата  с име FileSignFile сe съдржа json стринг образуван от подписващия Java софтуер. Този json е случаен формат на Java разработчика, a не е някакъв стандартизиран.

            string pkcs7 = (string)jsonSign["signature"]; // от JSON-a взимаме елемента с име signature - това е подписа в PKCS#7 формат

            string fileContent = (string)jsonSign["filecontent"]; // Съдържанието на файла компресирано чрез gzip. Java софтуерът за подписване stampitls.jnlp на потребителския компютър компресира файла в gzip формат, прави го в base64  стринг и го слага в JSON полето  filecontent, като преди това прави подписа чрез хаш стойност на оргиналния файл
            string fileName = (string)jsonSign["filename"]; // Името на некомпресирания файл 


            byte[] decoded = Convert.FromBase64String(fileContent);  // от base64 в byte масив. Всеки един елемент от този масив съдържа неотрицателно 8 битово число. Пример: текстови файл с три символа "abc" се предсавя в паметта, като 01100001 01100010 01100011  или  97, 98, 99 в десетична система или 61, 62, 63 с шейсетнатична система. "abc" в base64 ще бъде """". Следователно горния код прави текстови файл "abc" , който base64 "YWJj" в масив byte[] с три стойности 97, 98, 99
            
            byte[] decompressed = Decompress(decoded); // Декомпресира gzip в byte[] масив. Виж по-долу метода

           // System.IO.File.WriteAllBytes(@"c:\tempZatTriene\kaval.txt", decompressed);  //Записваме файла във файловата система на компютъра



            ContentInfo contentInfo = new ContentInfo(decompressed);  // The ContentInfo class represents the CMS/PKCS #7 ContentInfo data structure as defined in the CMS/PKCS #7 standards document. This data structure is the basis for all CMS/PKCS #7 messages.

            SignedCms cms = new SignedCms(contentInfo, true); //The SignedCms class enables signing and verifying of CMS/PKCS #7 messages. true параметъра показва signature is detached това значи, че съобщението (текстът), който се подписва не се съдържа в подписа. In PKCS#7 SignedData, attached and detached formats are supported… In detached format, data that is signed is not embedded inside the SignedData package instead it is placed at some external location…

            cms.Decode(Convert.FromBase64String(pkcs7));

            string err = "no error";


            try
            {
                cms.CheckSignature(false); // Проверява се подписа и сертификата. Проверява се само валидността на подписа, но не и на веригата. If is true, only the digital signatures are verified. If it is false, the digital signatures are verified, the signers' certificates are validated, and the purposes of the certificates are validated.
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
                bool fff = mCert.Verify();  // Проверка на сертификат дали е валиден и проверява да не е в ревокейшън листа.Тази проверка е подобна на на тази по-горе cms.CheckSignature. Не се проверява сертификатите по веригата дали те не са в ревокейшун листа и дали е издаден от съответния CA. За да работи този метод трябва на компютъра(сървъра), който на който се изпълнява този код да е инсталиран root сертификата на издателя.
                  // http://stackoverflow.com/questions/10083650/x509certificate2-verify-method-validating-against-revocation-list-and-perform
                  // err = ValidateCert(mCert);  //Още един начин за проверка на сертификат. Чрез този метод се прави най-пълна проверка на сертификата и неговата верига и дали е издаден от желан CA издател - този код може да се види във версията от 2014 г в това репозитори

            }

            string retMass;
            if (err == "no error") retMass = "No error. Signature and certificate are valid.";
            else retMass = "Error! " + err;

            ViewBag.signFile = retMass;
            return View();
        }

        
        public async Task<IActionResult> ReportFileSCSToFormFile(IFormFile postFile)
        {
            long fileSize = postFile.Length; //Големината на целия подписан json файл в байти

            var result = new StringBuilder();
            //Изчитаме подписания файл, като стринг
            using (var reader = new StreamReader(postFile.OpenReadStream()))
            {
                while (reader.Peek() >= 0)
                    result.AppendLine(await reader.ReadLineAsync());
            }

            string fileString = result.ToString();

            JObject jsonSign = JObject.Parse(fileString); // В fileString сe съдржа json стринг образуван от подписващия Java софтуер. Този json е случаен формат по идея Java разработчика, a не е някакъв стандартизиран.

            string pkcs7 = (string)jsonSign["signature"]; // от JSON-a взимаме елемента с име signature - това е подписа в PKCS#7 формат

            string fileContent = (string)jsonSign["filecontent"]; // Съдържанието на файла компресирано чрез gzip. Java софтуерът за подписване stampitls.jnlp на потребителския компютър компресира файла в gzip формат, прави го в base64  стринг и го слага в JSON полето  filecontent, като преди това прави подписа чрез хаш стойност на оргиналния файл
            
            long fileGzipSize=System.Text.ASCIIEncoding.ASCII.GetByteCount(fileContent);  //Големината на компресирания gzip файл в BASE64 формат
            
            string fileName = (string)jsonSign["filename"]; // Името на некомпресирания файл 


            byte[] decoded = Convert.FromBase64String(fileContent);  // от base64 в byte масив. Всеки един елемент от този масив съдържа неотрицателно 8 битово число. Пример: текстови файл с три символа "abc" се предсавя в паметта, като 01100001 01100010 01100011  или  97, 98, 99 в десетична система или 61, 62, 63 с шейсетнатична система. "abc" в base64 ще бъде """". Следователно горния код прави текстови файл "abc" , който base64 "YWJj" в масив byte[] с три стойности 97, 98, 99

            long fileGzip= decoded.Length;  //Големината на компресирания gzip файл в чист бинарен формат

            byte[] decompressed = Decompress(decoded); // Декомпресира gzip в byte[] масив. Виж по-долу метода
            // System.IO.File.WriteAllBytes(@"c:\tempZatTriene\kaval.txt", decompressed);  //Записваме файла във файловата система на компютъра
            
            long fileOriginalSize = decompressed.Length;

            /*
             *  Големина на файловете в модула общи положения пример в байти bytes:
             *  оргинален PDF файл в операционнaта sistema  - 2 569 529
             *  същия този файл w json формат  подписан в браузъра и base64 енккоднат - 3 296 799
             *  fileSize - 3 296 799 bytes  - пристига на сървъра виж по-горе
             *  fileGzipSize - 3 293 052  - само PDF файла компресиран в gzip изваден от общия JSON и енкоднат в base64 
             *  fileGzip - 2 469 788 - Големината на компресирания gzip файл в чист бинарен формат
             *  fileOriginalSize - 2 569 529 - след декомпресиране
             *  
             *  Извод за примера с pdf-a компресирания файл е 96.5 % от оргиналния - това може да бъде предпоставка за взимане на решение , как да се съхрани файла в базата данни и нна ОС в чист вид или компресиран. За моента при 96.5% за компресиран файл няма смисъл да се държи компресиран - направо оргинален
             *  
            */



            ContentInfo contentInfo = new ContentInfo(decompressed);  // The ContentInfo class represents the CMS/PKCS #7 ContentInfo data structure as defined in the CMS/PKCS #7 standards document. This data structure is the basis for all CMS/PKCS #7 messages.

            SignedCms cms = new SignedCms(contentInfo, true); //The SignedCms class enables signing and verifying of CMS/PKCS #7 messages. true параметъра показва signature is detached това значи, че съобщението (текстът), който се подписва не се съдържа в подписа. In PKCS#7 SignedData, attached and detached formats are supported… In detached format, data that is signed is not embedded inside the SignedData package instead it is placed at some external location…

            cms.Decode(Convert.FromBase64String(pkcs7));

            string err = "no error";


            try
            {
                cms.CheckSignature(false); // Проверява се подписа и сертификата. Проверява се само валидността на подписа, но не и на веригата. If is true, only the digital signatures are verified. If it is false, the digital signatures are verified, the signers' certificates are validated, and the purposes of the certificates are validated.
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
                bool fff = mCert.Verify();  // Проверка на сертификат дали е валиден и проверява да не е в ревокейшън листа.Тази проверка е подобна на на тази по-горе cms.CheckSignature. Не се проверява сертификатите по веригата дали те не са в ревокейшун листа и дали е издаден от съответния CA. За да работи този метод трябва на компютъра(сървъра), който на който се изпълнява този код да е инсталиран root сертификата на издателя.
                                            // http://stackoverflow.com/questions/10083650/x509certificate2-verify-method-validating-against-revocation-list-and-perform
                                            // err = ValidateCert(mCert);  //Още един начин за проверка на сертификат. Чрез този метод се прави най-пълна проверка на сертификата и неговата верига и дали е издаден от желан CA издател - този код може да се види във версията от 2014 г в това репозитори

            }

            string retMass;
            if (err == "no error") retMass = "No error. Signature and certificate are valid.";
            else retMass = "Error! " + err;

            ViewBag.signFile = retMass;
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

        

        public static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                var buffer = new byte[4096];
                int read;

                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    resultStream.Write(buffer, 0, read);
                }

                return resultStream.ToArray();
            }
        }





    }
}
