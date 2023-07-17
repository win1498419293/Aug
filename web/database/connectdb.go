package database

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func init() {
	db, err := gorm.Open(sqlite.Open("result/Subdomain.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	if db.Error != nil {
		fmt.Printf("database error %v", db.Error)
	}
	DB = db

}
