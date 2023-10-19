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

// 注册管理用户
func Admininsert(c *gin.Context) {
	var json Models.Admins   //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.BindJSON(&json) //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	id, err := json.AdminInsert()

	if err != nil {
		fmt.Printf("database error %v", err)
		fmt.Printf("database error %v", id)
		return
	}

	c.JSON(200, gin.H{ // 反馈给前台的信息，同时返回最新创建的一条数据的Id
		"status":  true,
		"id":      id,
		"message": "创建成功",
	})
	c.HTML(http.StatusOK, "html/users/home.html", gin.H{
		"title": "这是首页",
	})

}

func Adminupdate(c *gin.Context) {
	var json Models.Admins   //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.BindJSON(&json) //  获取前台传过来的 json数据
	ids := &json.Id
	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	fmt.Println(*ids)
	id, err := json.Update(*ids)

	if err != nil {
		fmt.Printf("database error %v", err)
		fmt.Printf("database error %v", id)
		return
	}

	c.JSON(200, gin.H{ // 反馈给前台的信息，同时返回最新创建的一条数据的Id
		"status":  true,
		"id":      id,
		"message": "修改成功",
	})
}

func Adminlogin(c *gin.Context) {
	var json Models.Admins     //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据
	username := json.Username
	password := json.Password
	_, err = json.Login(username)
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
	cookie := service.Getcookie(c)
	c.SetCookie("Crow", cookie, 3600, "/", "127.0.0.1", false, true)
	c.JSON(http.StatusOK, loginmsg)

}

func Adminindex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "这是首页",
	})

}

func Admingetlogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "这是首页",
	})

}

func Adminhome(c *gin.Context) {
	c.HTML(http.StatusOK, "home.html", gin.H{
		"title": "这是首页",
	})

}
