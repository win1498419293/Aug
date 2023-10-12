package Controllers

import (
	"Aug/web/app/Models"
	"Aug/web/app/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

var (
	Secret     = "LiuBei"  // 加盐
	ExpireTime = 3600 * 24 // token有效期
)

func Userinsert(c *gin.Context) {
	var json Models.Users    //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.BindJSON(&json) //  获取前台传过来的 json数据
	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	username, err := json.UserInsert()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}

	c.JSON(200, gin.H{ // 反馈给前台的信息，同时返回最新创建的一条数据的Id
		"status":   true,
		"username": username,
		"message":  "注册成功",
	})
}

func Userinfo(c *gin.Context) {
	var json Models.Users         //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBindUri(&json) //  获取前台传过来的 json数据
	Username := c.Query("username")
	cookie := service.Getcookie(c)
	c.SetCookie("Cookie", cookie, 3600, "/", "localhost", false, true)

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	if Username == "" {
		username, err := json.UserFindAll()
		//将密码替换为*号
		for i := 0; i < len(username); i++ {
			username[i].Password = "******"
		}
		if err != nil {
			fmt.Printf("database error %v", err)
			return
		}
		c.JSON(200, gin.H{ // 反馈给前台的信息，同时返回最新创建的一条数据的Id
			"status":   true,
			"username": username,
			"123":      Username,
			"message":  "查询成功",
		})
	} else {
		username, err := json.UserFind(Username)
		username.Password = "*******"
		if err != nil {
			fmt.Printf("database error %v", err)
			return
		}
		c.JSON(200, gin.H{ // 反馈给前台的信息，同时返回最新创建的一条数据的Id
			"status":   true,
			"username": username,
			"123":      Username,
			"message":  "查询成功",
		})
	}
}

func UserLogin(c *gin.Context) {
	var json Models.UsersApiLoginReq
	err := c.ShouldBindUri(&json)
	if err != nil {
		fmt.Printf("userlogin error %v", err)
	}
	username := json.Username
	password := json.Password
	json.UserLogin(username)
	if username != json.Username || err != nil {
		c.JSON(200, gin.H{ // 反馈给前台的信息，同时返回最新创建的一条数据的Id
			"status":  false,
			"message": "用户名或密码错误",
		})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(json.Password), []byte(password))
	if err != nil {
		loginmsg := Models.Loginmsg{
			Status:  false,
			Message: "登录失败",
		}
		c.JSON(http.StatusOK, loginmsg)
		return
	}

	var loginRequest service.LoginInfo //  定义json 变量 数据结构类型 为 Models.Admins

	claims := &service.JWTClaims{
		UserID:      1,
		Username:    loginRequest.Username,
		Password:    loginRequest.Password,
		FullName:    loginRequest.Username,
		Permissions: []string{},
	}
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Second * time.Duration(ExpireTime)).Unix()
	signedToken, err := service.GetToken(claims)

	if err != nil {
		c.JSON(400, err.Error())
		return
	}
	loginmsg := Models.Userlogmsg{
		Status:   true,
		Code:     200,
		Username: json.Username,
		Message:  "登录成功",
		Token:    signedToken,
	}
	c.JSON(http.StatusOK, loginmsg)
}

func Usermenu(c *gin.Context) {
	data := Models.ModuleInit()
	c.JSON(http.StatusOK, data)
}

func Userlogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "这是首页",
	})

}

func Userindex(c *gin.Context) {
	service.GetDeployment(c)
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "这是首页",
	})

}

func Userpostindex(c *gin.Context) {
	c.JSON(200, gin.H{ // 反馈给前台的信息，同时返回最新创建的一条数据的Id
		"status":  true,
		"message": "userindex",
	})

}
