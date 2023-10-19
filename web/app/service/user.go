package service

import (
	"Aug/web/database"
)

// 用户修改资料所需信息
type UserInfo struct {
	Id         int    `json:"id"`
	Username   string `json:"username"`
	NickName   string `json:"nickname"`
	Phone      string `json:"phone"`
	Email      string `json:"email"`
	Remark     string `json:"remark"`
	Created_at string `json:"created_at"`
}

type UserInfores struct {
	Code int        `json:"code"`
	Msg  string     `json:"msg"`
	Data []UserInfo `json:"Data"`
}

func (sub *UserInfo) GetUserInfo() (admins []UserInfo, err error) {
	result := database.DB.Table("users").Find(&admins)
	if result.Error != nil {
		err = result.Error
		return admins, err
	}
	return admins, err
}

func (sub *UserInfo) UserDelete(id int) bool {
	result := database.DB.Table("users").Where("id=?", id).Delete(&sub)
	if result.Error != nil {
		return false
	}
	rowsAffected := result.RowsAffected
	if rowsAffected > 0 {
		return true
	}
	return false
}
