using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWT.Models
{
    public class JwtContext:IdentityDbContext<ApplicationUser>
    {
        public JwtContext()
        {
            
        }
        public JwtContext(DbContextOptions options):base(options) 
        {
            
        }
        public DbSet<Employee> employees { get; set; }
    }
}
