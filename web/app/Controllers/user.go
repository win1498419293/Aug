package Controllers

import (
	"Aug/web/app/Models"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
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

func Usermenu(c *gin.Context) {
	data := Models.ModuleInit()
	c.JSON(http.StatusOK, data)
}

func Userindex(c *gin.Context) {
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
