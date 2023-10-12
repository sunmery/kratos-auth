// package authorization 封装了与身份验证和鉴权相关的工具类和方法。
package authorization

import (
	"context"
	"errors"
	"github.com/go-kratos/kratos/v2/middleware/auth/jwt"
	"github.com/go-kratos/kratos/v2/transport"
	jwtV4 "github.com/golang-jwt/jwt/v4"
	authzM "github.com/tx7do/kratos-casbin/authz"
)

// ClaimAuthorityId 是用于JWT Claims的常量，表示权限ID。
const ClaimAuthorityId = "authorityId"

// SecurityUser 结构体定义了用户的安全属性，如路径、方法、权限ID和域。
type SecurityUser struct {
	Path        string
	Method      string
	AuthorityId string
	Domain      string
}

// GetDomain 返回SecurityUser的域。
func (su *SecurityUser) GetDomain() string {
	return su.Domain
}

// NewSecurityUser 创建并返回一个新的SecurityUser实例。
func NewSecurityUser() authzM.SecurityUser {
	return &SecurityUser{}
}

// ParseFromContext 从上下文中解析出JWT Claims和操作信息，并填充到SecurityUser中。
func (su *SecurityUser) ParseFromContext(ctx context.Context) error {
	// 从上下文中获取JWT Claims
	if claims, ok := jwt.FromContext(ctx); ok {
		su.AuthorityId = claims.(jwtV4.MapClaims)[ClaimAuthorityId].(string)
	} else {
		return errors.New("jwt claim missing")
	}

	// 从上下文中获取操作信息
	if header, ok := transport.FromServerContext(ctx); ok {
		su.Path = header.Operation()
		su.Method = "*"
	} else {
		return errors.New("jwt claim missing")
	}

	return nil
}

// 以下方法获取SecurityUser的属性值
func (su *SecurityUser) GetSubject() string {
	return su.AuthorityId
}

func (su *SecurityUser) GetObject() string {
	return su.Path
}

func (su *SecurityUser) GetAction() string {
	return su.Method
}

// CreateAccessJwtToken 使用给定的密钥为SecurityUser创建一个JWT访问令牌。
func (su *SecurityUser) CreateAccessJwtToken(secretKey []byte) string {
	claims := jwtV4.NewWithClaims(jwtV4.SigningMethodHS256,
		jwtV4.MapClaims{
			ClaimAuthorityId: su.AuthorityId,
		})

	signedToken, err := claims.SignedString(secretKey)
	if err != nil {
		return ""
	}

	return signedToken
}

// ParseAccessJwtTokenFromContext 从上下文中解析JWT令牌，并填充到SecurityUser中。
func (su *SecurityUser) ParseAccessJwtTokenFromContext(ctx context.Context) error {
	claims, ok := jwt.FromContext(ctx)
	if !ok {
		return errors.New("no jwt token in context")
	}
	return su.ParseAccessJwtToken(claims)
}

// ParseAccessJwtTokenFromString 解析给定的JWT令牌字符串，并填充到SecurityUser中。
func (su *SecurityUser) ParseAccessJwtTokenFromString(token string, secretKey []byte) error {
	parseAuth, err := jwtV4.Parse(token, func(*jwtV4.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return err
	}

	claims, ok := parseAuth.Claims.(jwtV4.MapClaims)
	if !ok {
		return errors.New("no jwt token in context")
	}

	return su.ParseAccessJwtToken(claims)
}

// ParseAccessJwtToken 从JWT Claims解析并填充到SecurityUser中。
func (su *SecurityUser) ParseAccessJwtToken(claims jwtV4.Claims) error {
	if claims == nil {
		return errors.New("claims is nil")
	}

	mc, ok := claims.(jwtV4.MapClaims)
	if !ok {
		return errors.New("claims is not map claims")
	}

	strAuthorityId, ok := mc[ClaimAuthorityId]
	if ok {
		su.AuthorityId = strAuthorityId.(string)
	}

	return nil
}
