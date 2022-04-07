using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace SignWebForm.Models
{
    public class InputFileModel
    {
        [Required(ErrorMessage = "Не сте прикачели файл.")]
        [Display(Name = "Файл")]
        public IFormFile file { get; set; }
        public string XMLsignFile {get; set;}
    }
}
