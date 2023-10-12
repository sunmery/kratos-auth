## Kratos Auth

## 前置条件
使用之前有以下常识会帮助你更好的理解本例子:

1. 熟悉Kratos, 本例使用`Kratos-layout`模板
2. 有使用JWT的经验, 了解JWT的原理, 了解JWT的使用场景, 了解JWT的优缺点, 本例使用`github.com/golang-jwt/jwt/v4`库作为身份验证
3. 了解Casbin的模型定义, 规则定义, 策略定义, 本例使用`github.com/casbin/casbin/v2`库作为身份鉴权

## 与Kratos集成
1. 使用`Kratos-layout`模板创建项目
    ```shell
    kratos new kratos-casbin
    ```

2. 定义`configs/config.yaml`配置, 顶层添加`JWT`配置
    ```yaml
    auth:
      service_key: some_jwt_sign_key
      api_key: some_api_key
    ```
3. 添加Casbin的`model.conf`模型文件与`policy.csv`策略文件
    `configs/authz/model.conf`
    ```conf
    [request_definition]
    r = sub, obj, act
    
    [policy_definition]
    p = sub, obj, act
    
    [role_definition]
    g = _, _
    
    [policy_effect]
    e = some(where (p.eft == allow))
    
    [matchers]
    m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
    ```

    `configs/authz/model.csv`
    ```csv
    p, moderator, /admin.v1.AdminService/GetModeratorBoard, *
    p, api_admin, /admin.v1.AdminService/*, *
    g, admin, api_admin
    ```

4. 更新Proto配置:`conf/conf.proto`
    ```proto
    // ... [略去部分代码]
    message Bootstrap {
      Server server = 1;
      Data data = 2;
      Auth auth = 3;
    }
    
    message Auth {
      string service_key = 1;
      string api_key = 2;
    }
    ```
5. 注入`Auth`配置到wire
    ```go
    // wireApp init kratos application.
    func wireApp(*conf.Server, *conf.Data, *conf.Auth, log.Logger) (*kratos.App, func(), error) {
        panic(wire.Build(server.ProviderSet, data.ProviderSet, biz.ProviderSet, service.ProviderSet, newApp))
    }
    ```

6. 更新`main.go`, 添加`Auth`配置
    ```go
    func main() {
        flag.Parse()
        logger := log.With(log.NewStdLogger(os.Stdout),
            "ts", log.DefaultTimestamp,
            "caller", log.DefaultCaller,
            "service.id", id,
            "service.name", Name,
            "service.version", Version,
            "trace.id", tracing.TraceID(),
            "span.id", tracing.SpanID(),
        )
        c := config.New(
            config.WithSource(
                file.NewSource(flagconf),
            ),
        )
        defer c.Close()
    
        if err := c.Load(); err != nil {
            panic(err)
        }
    
        var bc conf.Bootstrap
        if err := c.Scan(&bc); err != nil {
            panic(err)
        }
    
        app, cleanup, err := wireApp(bc.Server, bc.Data, bc.Auth, logger) // 注入Auth配置
        if err != nil {
            panic(err)
        }
        defer cleanup()
    
        // start and wait for stop signal
        if err := app.Run(); err != nil {
            panic(err)
        }
    }
    ```

7. API接口定义
   `api/admin/v1/admin.proto`
    ```protobuf
    syntax = "proto3";
    
    package admin.v1;
    
    import "google/api/annotations.proto";
    import "google/protobuf/empty.proto";
    
    option go_package = "api/admin/v1;v1";
    
    
    service AdminService {
      // 登陆
      rpc Login (LoginReq) returns (User) {
        option (google.api.http) = {
          post: "/api/v1/login"
          body: "*"
        };
      }
      // 登出
      rpc Logout (LogoutReq) returns (LogoutReply) {
        option (google.api.http) = {
          post: "/api/v1/logout"
          body: "*"
        };
      }
      // 注册
      rpc Register (RegisterReq) returns (RegisterReply) {
        option (google.api.http) = {
          post: "/api/v1/register"
          body: "*"
        };
      }
    
      // 用户列表
      rpc ListUser (google.protobuf.Empty) returns (ListUserReply) {
        option (google.api.http) = {
          get: "/api/v1/users"
        };
      }
    
      rpc GetPublicContent (google.protobuf.Empty) returns (Content) {
        option (google.api.http) = {
          get: "/api/v1/all"
        };
      }
      rpc GetUserBoard (google.protobuf.Empty) returns (Content) {
        option (google.api.http) = {
          get: "/api/v1/user"
        };
      }
      rpc GetModeratorBoard (google.protobuf.Empty) returns (Content) {
        option (google.api.http) = {
          get: "/api/v1/mod"
        };
      }
      rpc GetAdminBoard (google.protobuf.Empty) returns (Content) {
        option (google.api.http) = {
          get: "/api/v1/admin"
        };
      }
    }
    
    message Content {
      string content = 1;
    }
    
    message User {
      optional uint64 id = 1;
      optional string user_name = 2 [json_name = "user_name"];
      optional string password = 3 [json_name = "password"];
      optional string nick_name = 4 [json_name = "nick_name"];
      optional string email = 5 [json_name = "email"];
      repeated string roles = 6;
      optional string token = 7;
    }
    
    message ListUserReply {
      repeated User items = 1;
      int32 total = 2;
    }
    
    // 请求 - 登录
    message LoginReq {
      string user_name = 1 [json_name = "user_name"];
      string password = 2;
    }
    // 回应 - 登录
    message LoginReply {
      User user = 1;
    }
    
    // 请求 - 登出
    message LogoutReq {
      uint64 id = 1;
    }
    // 回应 - 登出
    message LogoutReply {
      uint64 id = 1;
    }
    
    message RegisterReq {
      string username = 1;
      string password = 2;
      string email = 3;
    }
    message RegisterReply {
      string message = 1;
      bool success = 2;
    }
    ```
   
8. 服务器中间件添加: 修改`Server`层的`http`文件, 添加用于身份验证JWT和身份鉴权Casbin的代码:
    ```go
    package server
    import (
        "context"
        "github.com/casbin/casbin/v2/model"
        fileAdapter "github.com/casbin/casbin/v2/persist/file-adapter"
        "github.com/go-kratos/kratos/v2/middleware/auth/jwt"
        "github.com/go-kratos/kratos/v2/middleware/logging"
        "github.com/go-kratos/kratos/v2/middleware/selector"
        "github.com/go-kratos/kratos/v2/middleware/tracing"
        "github.com/go-kratos/swagger-api/openapiv2"
        jwtV4 "github.com/golang-jwt/jwt/v4"
        "github.com/gorilla/handlers"
        sv1 "kratos-casbin/api/admin/v1"
        v1 "kratos-casbin/api/helloworld/v1"
        "kratos-casbin/internal/conf"
        myAuthz "kratos-casbin/internal/pkg/authorization"
        "kratos-casbin/internal/service"
    
        "github.com/go-kratos/kratos/v2/log"
        "github.com/go-kratos/kratos/v2/middleware/recovery"
        "github.com/go-kratos/kratos/v2/transport/http"
        casbinM "github.com/tx7do/kratos-casbin/authz/casbin"
    )
    
    // NewWhiteListMatcher 创建jwt白名单
    func NewWhiteListMatcher() selector.MatchFunc {
        whiteList := make(map[string]struct{})
        whiteList["/admin.v1.AdminService/Login"] = struct{}{}
        whiteList["/admin.v1.AdminService/Logout"] = struct{}{}
        whiteList["/admin.v1.AdminService/Register"] = struct{}{}
        whiteList["/admin.v1.AdminService/GetPublicContent"] = struct{}{}
        return func(ctx context.Context, operation string) bool {
            if _, ok := whiteList[operation]; ok {
                return false
            }
            return true
        }
    }
    
    // NewMiddleware 创建中间件
    func NewMiddleware(ac *conf.Auth, logger log.Logger) http.ServerOption {
        m, _ := model.NewModelFromFile("../../configs/authz/authz_model.conf")
        a := fileAdapter.NewAdapter("../../configs/authz/authz_policy.csv")
    
        return http.Middleware(
            recovery.Recovery(),
            tracing.Server(),
            logging.Server(logger),
            selector.Server(
                // JWT, 用于身份验证
                // 这里配置了key与签名方法, 用于验证token
                jwt.Server(
                    func(token *jwtV4.Token) (interface{}, error) {
                        return []byte(ac.ApiKey), nil
                    },
                    jwt.WithSigningMethod(jwtV4.SigningMethodHS256),
                ),
                // casbin配置, 用于鉴权
                // 这里配置了casbin的model和policy, 以及SecurityUserCreator
                casbinM.Server(
                    casbinM.WithCasbinModel(m),
                    casbinM.WithCasbinPolicy(a),
                    casbinM.WithSecurityUserCreator(myAuthz.NewSecurityUser),
                ),
            ).
                Match(NewWhiteListMatcher()).Build(), // 跳过身份验证的白名单
        )
    }
    
    // NewHTTPServer new an HTTP server.
    func NewHTTPServer(
        c *conf.Server,
        ac *conf.Auth,
        logger log.Logger,
        s *service.AdminService, // admin服务
    ) *http.Server {
        var opts = []http.ServerOption{
            NewMiddleware(ac, logger),
            http.Filter(handlers.CORS(
                handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}),
                handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}),
                handlers.AllowedOrigins([]string{"*"}),
            )),
        }
        if c.Http.Network != "" {
            opts = append(opts, http.Network(c.Http.Network))
        }
        if c.Http.Addr != "" {
            opts = append(opts, http.Address(c.Http.Addr))
        }
        if c.Http.Timeout != nil {
            opts = append(opts, http.Timeout(c.Http.Timeout.AsDuration()))
        }
        srv := http.NewServer(opts...)
    
        h := openapiv2.NewHandler()
        srv.HandlePrefix("/q/", h)
        
        sv1.RegisterAdminServiceHTTPServer(srv, s) // 注册admin服务
        return srv
    }
    
    ```

9. 编写身份验证与鉴权的工具类
    `internal/pkg/authorization/authz.go`
    ```go
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
    
    // ClaimAuthorityId 用于JWT Claims的常量，表示权限ID。
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
    
    ```

10. 编写业务逻辑
    `service/api.go`
    ```go
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
    
    ```

11. 注入依赖
    ```go
    // ProviderSet is service providers.
    var ProviderSet = wire.NewSet(NewGreeterService, NewAdminService)
    ```

12. 运行项目
    ```shell
    kratso run
    ```

13. 访问 `http://localhost:8000/q/swagger-ui/` 查看接口请求列表和请求方式
    1. 先进行注册,`http://localhost:8000/api/v1/register`, POST请求携带`user_name`, `password`Body参数, 注册成功后会返回`success`和`message`
    2. 再进行登录, POST请求携带`user_name`, `password`参数登录后会返回`token`,
    3. 登陆后访问GET `http://localhost:8000/api/v1/users`,在Header添加`Authorization`头与`Bearer `+`Token`值, 如果是`admin`用户会返回用户列表, 如果是`moderator`用户会返回`401`错误, 未登陆访问会返回`401`错误

## 参考
1. https://mp.weixin.qq.com/s/hXYUwZVIKAPZayyPbJCMaw
2. https://github.com/go-kratos/examples/tree/main/casbin
3. https://github.com/lisa-sum/kratos-auth
4. https://github.com/tx7do/kratos-casbin/blob/main/authz/authz.go
