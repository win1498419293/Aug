package Weak_Pass_Burst

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"sync"
)

func MssqlScan(ScanType string, ip string) {
	user := Readfile("dic/dic_username_mssql.txt")
	pass := Readfile("dic/dic_password_mssql.txt")

	resultChan := make(chan string)

	var wg sync.WaitGroup
	for _, u := range user {
		for _, p := range pass {
			wg.Add(1)
			go func(u, p string) {
				defer wg.Done()
				fmt.Println("Check... " + ip + " " + u + " " + p)
				res, err := MssqlAuth(ip, "1433", u, p)
				if res && err == nil {
					resultChan <- fmt.Sprintf("%s %s 3306 %s %s", ScanType, ip, u, p)
				} else if err != nil {
					resultChan <- fmt.Sprintf("Error occurred: %v", err)
				}
			}(u, p)
		}
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

}

func MssqlAuth(ip string, port string, user string, pass string) (result bool, err error) {
	result = false
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("panic occurred: %v", r)
		}
	}()
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%s;encrypt=disable", ip, user, pass, port)
	db, err := sql.Open("mssql", connString)
	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result = true
		}
	}
	return result, err
}
