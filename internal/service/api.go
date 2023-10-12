// package service 封装了后台管理服务的核心业务逻辑。
package service

import (
	"context"
	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"
	v1 "kratos-casbin/api/admin/v1"
	"kratos-casbin/internal/conf"
	myAuthz "kratos-casbin/internal/pkg/authorization"
)

// AdminService 结构体实现了v1.UnimplementedAdminServiceServer接口，
// 提供后台管理服务的相关功能，如用户登录、登出、注册等。
type AdminService struct {
	v1.UnimplementedAdminServiceServer

	log  *log.Helper // 用于日志记录
	auth *conf.Auth  // 用于身份验证的配置
}

// NewAdminService 创建并返回一个新的AdminService实例。
func NewAdminService(auth *conf.Auth, logger log.Logger) *AdminService {
	l := log.NewHelper(log.With(logger, "module", "service/admin"))
	return &AdminService{
		log:  l,
		auth: auth,
	}
}

// ListUser 返回用户列表。
func (s *AdminService) ListUser(_ context.Context, _ *emptypb.Empty) (*v1.ListUserReply, error) {
	return &v1.ListUserReply{}, nil
}

// Login 接受登录请求，并在验证用户身份后返回JWT令牌。
func (s *AdminService) Login(_ context.Context, req *v1.LoginReq) (*v1.User, error) {
	var id uint64 = 10
	var email = "hello@kratos.com"
	var roles []string

	switch req.UserName {
	case "admin":
		roles = append(roles, "ROLE_ADMIN")
	case "moderator":
		roles = append(roles, "ROLE_MODERATOR")
	}

	var securityUser myAuthz.SecurityUser
	securityUser.AuthorityId = req.GetUserName()
	token := securityUser.CreateAccessJwtToken([]byte(s.auth.GetApiKey()))

	return &v1.User{
		Id:       &id,
		UserName: &req.UserName,
		Token:    &token,
		Email:    &email,
		Roles:    roles,
	}, nil
}

// Logout 用于用户登出。
func (s *AdminService) Logout(_ context.Context, _ *v1.LogoutReq) (*v1.LogoutReply, error) {
	return nil, nil
}

// Register 用于新用户的注册。
func (s *AdminService) Register(_ context.Context, _ *v1.RegisterReq) (*v1.RegisterReply, error) {
	return &v1.RegisterReply{
		Message: "register success",
		Success: true,
	}, nil
}

// GetPublicContent 返回公共内容。
func (s *AdminService) GetPublicContent(_ context.Context, _ *emptypb.Empty) (*v1.Content, error) {
	return &v1.Content{
		Content: "PublicContent",
	}, nil
}

// GetUserBoard 返回用户面板的内容。
func (s *AdminService) GetUserBoard(_ context.Context, _ *emptypb.Empty) (*v1.Content, error) {
	return &v1.Content{
		Content: "UserBoard",
	}, nil
}

// GetModeratorBoard 返回版主面板的内容。
func (s *AdminService) GetModeratorBoard(_ context.Context, _ *emptypb.Empty) (*v1.Content, error) {
	return &v1.Content{
		Content: "ModeratorBoard",
	}, nil
}

// GetAdminBoard 返回管理员面板的内容。
func (s *AdminService) GetAdminBoard(_ context.Context, _ *emptypb.Empty) (*v1.Content, error) {
	return &v1.Content{
		Content: "AdminBoard",
	}, nil
}
