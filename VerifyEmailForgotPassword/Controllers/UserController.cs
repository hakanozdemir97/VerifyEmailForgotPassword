using MailKit;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Security;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using VerifyEmailForgotPassword.Models;
using VerifyEmailForgotPassword.Services.EmailService;

namespace VerifyEmailForgotPassword.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IEmailService _emailService;

        //public UserController(DataContext context)
        //{
        //    _context = context;
        //}
        public UserController(DataContext context, IEmailService emailService)
        {
            _context = context;
            _emailService = emailService;
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegisterDto request)
        {
            if (_context.Users.Any(u => u.Email == request.Email))
            {
                return BadRequest("User already exists.");
            }

            CreatePasswordHash(request.Password,
                out byte[] passwordHash,
                out byte[] passwordSalt);

            var user = new User
            {
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomToken()
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            //Sending mail to user for registration info
            EmailDto emailDto = new EmailDto()
            {
                To = user.Email,
                Subject = "Registration",
                Body = "Please click on the verification link sent to your e-mail to activate your account." + "     " + user.VerificationToken
            };
            _emailService.SendEmail(emailDto);

            return Ok("User successfully created!");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLoginDto request)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);
            if (user == null)
            {
                return BadRequest("User not found.");
            }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Password is incorrect.");
            }
            if (user.VerifiedAt == null)
            {
                return BadRequest("User not verified! Please check your e-mail.");
            }

            return Ok($"Welcome back, {user.Email}! :)");
        }

        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string token)
        {
            var user = _context.Users.FirstOrDefault(u => u.VerificationToken == token);
            if (user == null)
            {
                return BadRequest("Invalid token.");
            }
            user.VerifiedAt = DateTime.Now;
            await _context.SaveChangesAsync();

            //Sending mail to user for verify info
            EmailDto emailDto = new EmailDto()
            {
                To = user.Email,
                Subject = "Account Verify",
                Body = "User verified! :)"
            };
            _emailService.SendEmail(emailDto);

            return Ok("User verified! :)");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == email);
            if (user == null)
            {
                return BadRequest("User not found.");
            }

            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires = DateTime.Now.AddDays(1);
            await _context.SaveChangesAsync();

            //Sending mail to user for the password change.
            EmailDto emailDto = new EmailDto()
            {
                To = user.Email,
                Subject = "Forgot Password",
                Body = "You can use the token in the mail to change your password. The validity period of the token is 1 day." + "     " + user.PasswordResetToken
            };
            _emailService.SendEmail(emailDto);

            return Ok("You may now reset your password.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto request)
        {
            var user = _context.Users.FirstOrDefault(u => u.PasswordResetToken == request.Token);
            if (user == null || user.ResetTokenExpires < DateTime.Now)
            {
                return BadRequest("Invalid Token.");
            }

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;
            await _context.SaveChangesAsync();

            return Ok("Password successfully reset.");
        }

        [HttpPost("send-mail")]
        public async Task<IActionResult> SendMail(EmailDto request)
        {
            _emailService.SendEmail(request);
            return Ok();
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateRandomToken()
        {
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
            return token;
        }

    }
}
