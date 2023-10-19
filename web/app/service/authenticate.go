package service

import (
	"Aug/web/app/Models"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"time"
)

type LoginInfo Models.UsersApiLoginReq
type JWTClaims struct { // token里面添加用户信息，验证token后可能会用到用户信息
	jwt.StandardClaims
	UserID      int      `json:"user_id"`
	Password    string   `json:"password"`
	Username    string   `json:"username"`
	FullName    string   `json:"full_name"`
	Permissions []string `json:"permissions"`
}

var (
	Secret     = "LiuBei"  // 加盐
	ExpireTime = 3600 * 24 // token有效期
)

// 登录
func Getcookie(c *gin.Context) string {

	var loginRequest LoginInfo //  定义json 变量 数据结构类型 为 Models.Admins

	claims := &JWTClaims{
		UserID:      1,
		Username:    loginRequest.Username,
		Password:    loginRequest.Password,
		FullName:    loginRequest.Username,
		Permissions: []string{},
	}
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Second * time.Duration(ExpireTime)).Unix()
	signedToken, err := GetToken(claims)

	if err != nil {
		c.JSON(400, err.Error())
		return ""
	}
	//fmt.Printf(signedToken)
	return signedToken
}

//身份验证

func Verify(c *gin.Context) (result bool, userName string, err error) {
	strToken, err := c.Cookie("Crow")
	if strToken == "" {
		result = false
		return result, "", nil
	}
	claim, err := verifyAction(strToken)
	if err != nil {
		result = false
		return result, "", nil
	}
	result = true
	userName = claim.Username
	return result, userName, nil
}

// 刷新token
func Refresh(c *gin.Context) {
	strToken, err := c.Cookie("Crow")
	claims, err := verifyAction(strToken)
	if err != nil {
		c.JSON(400, gin.H{"err": err.Error()})
		return
	}
	claims.ExpiresAt = time.Now().Unix() + (claims.ExpiresAt - claims.IssuedAt)
	signedToken, err := GetToken(claims)
	if err != nil {
		c.JSON(400, gin.H{"err": err.Error()})
		return
	}
	c.JSON(200, gin.H{"data": signedToken})
}

// 验证token是否存在，存在则获取信息
func verifyAction(strToken string) (claims *JWTClaims, err error) {
	token, err := jwt.ParseWithClaims(strToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(Secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, err
	}
	if err := token.Claims.Valid(); err != nil {
		return nil, err
	}
	return claims, nil
}

// 生成token
func GetToken(claims *JWTClaims) (signedToken string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err = token.SignedString([]byte(Secret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

// 接口身份验证
func GetDeployment(c *gin.Context) bool {

	//身份认证
	checkUser, _, err := Verify(c) //第二个值是用户名，这里没有使用
	if err != nil {
		c.JSON(400, gin.H{"err": err.Error()})
		return false
	}
	if checkUser == false {
		//c.String(http.StatusOK, "身份验证失败，请重新登录")
		return false
	}
	return true
}
