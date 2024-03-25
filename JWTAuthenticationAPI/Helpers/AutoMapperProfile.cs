using AutoMapper;
using JWTAuthenticationAPI.DTOS;
using JWTAuthenticationAPI.Models;

namespace JWTAuthenticationAPI.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<RegisterDTO, ApplicationUser>().ReverseMap()
                .ForMember(dest => dest.Password, opt => opt.Ignore());
            CreateMap<ApplicationUser, ChangePasswordDTO>().ReverseMap();
            CreateMap<ApplicationUser, LoginDTO>().ReverseMap();
        }
    }
}
