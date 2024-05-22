using System.ComponentModel.DataAnnotations;

namespace JWT.DTOs
{
    public class RefreshTokenRequestDTO
    {

       
            [Required]
            public string Token { get; set; }
            [Required]
            public string RefreshToken { get; set; }
      
  

}
}
