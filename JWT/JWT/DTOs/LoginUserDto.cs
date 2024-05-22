using System.ComponentModel.DataAnnotations;

namespace JWT.DTOs
{
    public class LoginUserDto
    {
        [Required]
        public string name { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
