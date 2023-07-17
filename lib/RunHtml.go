package lib

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"html/template"
	"math"
	"net/http"
	"strconv"
)

type vulnstruct struct {
	Id         []string
	Url        []string
	Vname      []string
	CreateTime []string
}
type taskstruct struct {
	Id         []string
	Url        []string
	Vname      []string
	CreateTime []string
}
type subdstruct struct {
	Id         []string
	Url        []string
	Vname      []string
	CreateTime []string
}

type Data struct {
	Value int    `json:"value"`
	Name  string `json:"name"`
}

func getUsersHandler(c *gin.Context) {

	// 获取查询参数
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("pageSize", "10")

	// 将查询参数转换为整数
	pageInt, _ := strconv.Atoi(page)
	pageSizeInt, _ := strconv.Atoi(pageSize)

	// 根据分页参数查询数据
	// 这里可以根据具体的业务逻辑进行数据库查询等操作
	// 示例中只是简单返回一些模拟数据
	users := SelectVuln()
	subd := SelectAllSubdmaindb("", "")
	task := SelectAllTaskdb("", "")
	res := Paginator(0, 10, 78)
	ids := []string{}
	urls := []string{}
	vnames := []string{}
	times := []string{}
	for i := 0; i < len(users); i++ {
		ids = append(ids, users[i]["id"])
		urls = append(urls, users[i]["Url"])
		vnames = append(vnames, users[i]["Vname"])
		times = append(times, users[i]["CreateTime"])

	}
	//统计每个字符串出现的次数
	var valueMap = make(map[string]int)
	for _, r := range vnames {
		valueMap[r]++
	}
	ma := []string{}
	for Nname, Value := range valueMap {
		resule := "{\"value\":" + strconv.Itoa(Value) + "," + " \"name\":" + Nname + "},"
		ma = append(ma, resule)
	}

	chartData := []Data{}
	for key, value := range valueMap {
		chartData = append(chartData, Data{
			Value: value,
			Name:  key,
		})
	}
	asd := chartData

	// 计算分页结果
	startIndex := (pageInt - 1) * pageSizeInt
	endIndex := pageInt * pageSizeInt
	if endIndex > len(users) {
		endIndex = len(users)
	}

	data := vulnstruct{
		Url:        urls[startIndex:endIndex],
		Vname:      vnames[startIndex:endIndex],
		CreateTime: times[startIndex:endIndex],
		Id:         ids[startIndex:endIndex],
	}

	// 返回分页结果
	c.HTML(http.StatusOK, "home.html", gin.H{
		"page":       pageInt,
		"pageSize":   pageSizeInt,
		"data":       valueMap,
		"chartData":  asd,
		"vuls_total": len(users),
		"vulns":      data,
		"paginator":  res,
		"subds":      subd,
		"tasks":      task,
	})
}

func runhtml() {

	r := gin.Default()
	// 注册自定义函数
	r.SetFuncMap(template.FuncMap{
		"jsonify": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
	})
	r.LoadHTMLGlob("templates/*.html")
	// 创建路由并指定处理函数
	r.GET("/", getUsersHandler)
	r.Run(":9999") // 运行在9999端口
}

// 分页方法，根据传递过来的页数，每页数，总数，返回分页的内容 7个页数 前 1，2，3，4，5 后 的格式返回,小于5页返回具体页数
func Paginator(page, prepage int, nums int64) map[string]interface{} {
	var firstpage int //前一页地址
	var lastpage int  //后一页地址
	//根据nums总数，和prepage每页数量 生成分页总数
	totalpages := int(math.Ceil(float64(nums) / float64(prepage))) //page总数
	if page > totalpages {
		page = totalpages
	}
	if page <= 0 {
		page = 1
	}
	var pages []int
	switch {
	case page >= totalpages-5 && totalpages > 5: //最后5页
		start := totalpages - 5 + 1
		firstpage = page - 1
		lastpage = int(math.Min(float64(totalpages), float64(page+1)))
		pages = make([]int, 5)
		for i, _ := range pages {
			pages[i] = start + i
		}
	case page >= 3 && totalpages > 5:
		start := page - 3 + 1
		pages = make([]int, 5)
		firstpage = page - 3
		for i, _ := range pages {
			pages[i] = start + i
		}
		firstpage = page - 1
		lastpage = page + 1
	default:
		pages = make([]int, int(math.Min(20, float64(totalpages))))
		for i, _ := range pages {
			pages[i] = i + 1
		}
		firstpage = int(math.Max(float64(1), float64(page-1)))
		lastpage = page + 1
		//fmt.Println(pages)
	}
	paginatorMap := make(map[string]interface{})
	paginatorMap["pages"] = pages
	paginatorMap["totalpages"] = totalpages
	paginatorMap["firstpage"] = firstpage
	paginatorMap["lastpage"] = lastpage
	paginatorMap["currpage"] = page
	return paginatorMap
}
