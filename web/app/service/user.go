package service

import (
	"Aug/web/app/Models"
	"Aug/web/database"
)

type userinfo Models.UsersApiLoginReq

// 查询漏洞表信息
func (sub *userinfo) GetUserLogin() (admins userinfo, err error) {
	result := database.DB.Table("Vuln").Find(&admins)
	if result.Error != nil {
		err = result.Error
		return admins, err
	}
	return admins, err
}
