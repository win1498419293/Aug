package Models

import (
	"Aug/web/database"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"strconv"
)

type Admins struct {
	gorm.Model        // 这里的配置可以让ORM 自动维护 时间戳字段，很爽有木有
	Id         int    `json:"id"  binding:"required"`
	Username   string `json:"username"  binding:"required"`
	Password   string `json:"password"  binding:"required"`
	Mobile     string `json:"mobile" binding:"required"`
}

type Admininfo struct {
	gorm.Model        // 这里的配置可以让ORM 自动维护 时间戳字段，很爽有木有
	Unamename  string `json:"unamename"  binding:"required"`
	Password   string `json:"password"  binding:"required"`
}

type Loginmsg struct {
	Status   bool   `json:"status"  binding:"required"`
	Code     int    `json:"code"  binding:"required"`
	Id       int    `json:"id"  binding:"required"`
	Username string `json:"username"  binding:"required"`
	Message  string `json:"msg"  binding:"required"`
}

// Insert 新增admin用户
func (admin *Admins) AdminInsert() (userID string, err error) {
	database.DB.AutoMigrate(&admin) //  这里的DB变量是 database 包里定义的，Create 函数是 gorm包的创建数据API
	hash, err := bcrypt.GenerateFromPassword([]byte(admin.Password), bcrypt.DefaultCost)
	admin.Password = string(hash)
	result := database.DB.Create(&admin)
	userID = strconv.Itoa(admin.Id)
	if result.Error != nil {
		err = result.Error
	}
	return userID, err // 返回新建数据的id 和 错误信息，在控制器里接收
}

// Destroy 删除admin用户
func (admin *Admins) Destroy() (err error) {
	result := database.DB.Delete(&admin)
	if result.Error != nil {
		err = result.Error
	}
	return
}

// Update 修改admin用户
func (admin *Admins) Update(id int) (user Admins, err error) {
	result := database.DB.Model(&admin).Where("id = ?", id).Updates(&admin)
	if result.Error != nil {
		err = result.Error
	}
	return
}

// Findall 查询admin用户
func (admin *Admins) FindAll() (admins []Admins, err error) {
	result := database.DB.Find(&admin) // 这里的 &admins 跟返回参数要一致
	if result.Error != nil {
		err = result.Error
		return
	}
	return
}

// FindOne 查询admin用户
func (admin *Admins) Login(username string) (admins Admins, err error) {
	result := database.DB.Where("username = ?", username).First(&admin) // 这里的 &admins 跟返回参数要一致
	if result.Error != nil {
		err = result.Error
		return
	}
	return
}
