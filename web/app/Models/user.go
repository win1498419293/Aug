package Models

import (
	"Aug/web/database"
	"golang.org/x/crypto/bcrypt"
)

// 登录请求参数
type UsersApiLoginReq struct {
	Username string `v:"required|length:4,20#账号不能为空|账号长度应当在:min到:max之间"`
	Password string `v:"required|length:6,20|password3#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号"`
}

// 添加用户请求参数
type Users struct {
	Username string `v:"required|length:4,20#账号不能为空|账号长度应当在:min到:max之间"`
	Password string `v:"required|length:6,20|password3#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号"`
	NickName string `v:"required#昵称不能为空"`
	Phone    string `v:"required|phone#手机号不能为空|手机号格式不正确"`
	Email    string `v:"required|email#邮箱不能为空|邮箱格式不正确"`
	Remark   string `v:"required#个性签名不能为空"`
}

// 删除用户所需信息
type UserApiDelReq struct {
	Username string `v:"required|length:4,20#账号不能为空|账号长度应当在:min到:max之间"`
}

// 修改密码所需信息
type UserApiChangePasswordReq struct {
	Password  string `v:"required|length:6,20|password3|different:Password1#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号|新密码不能和旧密码一致"`
	Password1 string `v:"required|length:6,20|password3#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号"`
	Password2 string `v:"required|length:6,20|password3|same:Password2#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号|两次密码输入不相等"`
}

// 用户修改资料所需信息
type UserApiSetInfoReq struct {
	Username string `v:"required|length:4,20#账号不能为空|账号长度应当在:min到:max之间"`
	NickName string `v:"required#昵称不能为空"`
	Phone    string `v:"required|phone#手机号不能为空|手机号格式不正确"`
	Email    string `v:"required|email#邮箱不能为空|邮箱格式不正确"`
	Remark   string `v:"required#个性签名不能为空"`
}

// 用户管理 模糊分页查询返回数据所需信息
type UserRspManager struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Count int64  `json:"count"`
}

type Userlogmsg struct {
	Status   bool   `json:"status"  binding:"required"`
	Code     int    `json:"code"  binding:"required"`
	Username string `json:"username"  binding:"required"`
	Message  string `json:"msg"  binding:"required"`
	Token    string `json:"token" binding:"required"`
}

// Insert 新增user用户
func (user *Users) UserInsert() (username string, err error) {
	database.DB.AutoMigrate(&user) //  这里的DB变量是 database 包里定义的，Create 函数是 gorm包的创建数据API
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hash)
	result := database.DB.Create(&user)
	if result.Error != nil {
		err = result.Error
	}
	return user.Username, err // 返回新建数据的id 和 错误信息，在控制器里接收
}

// Destroy 删除user用户
func (user *UserApiDelReq) UserDestroy() (err error) {
	result := database.DB.Delete(&user)
	if result.Error != nil {
		err = result.Error
	}
	return
}

// Update 修改user用户
func (user *UserApiSetInfoReq) UserUpdate(Username string) (users UserApiSetInfoReq, err error) {
	result := database.DB.Model(&user).Where("Username = ?", Username).Updates(&user)
	if result.Error != nil {
		err = result.Error
	}
	return
}

// FindOne 查询user用户
func (user *Users) UserFind(username string) (users Users, err error) {
	result := database.DB.Where("username = ?", username).First(&users) // 这里的 &admins 跟返回参数要一致
	if result.Error != nil {
		err = result.Error
		return users, err
	}
	return users, nil
}

// Findall 查询user用户
func (user *Users) UserFindAll() (users []Users, err error) {
	result := database.DB.Find(&users) // 这里的 &admins 跟返回参数要一致
	if result.Error != nil {
		err = result.Error
		return users, err
	}
	return users, nil
}

// user登录
func (user *UsersApiLoginReq) UserLogin(username string) (users UsersApiLoginReq, err error) {
	result := database.DB.Where("username = ?", username).First(&user) // 这里的 &admins 跟返回参数要一致
	if result.Error != nil {
		err = result.Error
		return
	}
	return
}
